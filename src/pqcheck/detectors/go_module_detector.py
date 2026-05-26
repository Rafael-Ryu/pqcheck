"""Module-granularity Go detection: a bridge to the bundled crypto-analyzer.

`go/packages` resolves at package/module granularity (it needs neighbouring
files plus deps to type-check), so Go detection runs once per module rather than
once per file. `detect_go_module` invokes the bundled `crypto-analyzer` binary
under a hardened subprocess and maps its JSON to `CryptoFinding`; when `go` is
absent or the module does not resolve, it falls back to the per-file tree-sitter
detector so the detection floor never drops below today's literal-based one.

De-duplication contract (consumed by the future scanner orchestrator, which does
not exist yet — `pqcheck scan` is still a stub): the walker groups discovered
`.go` files by their nearest `go.mod` via `group_go_files_by_module`, the
orchestrator calls `detect_go_module` once per module root, and marks the files
returned by `claimed_go_files` so the per-file loop (used by Python/Java) skips
them. Without that marking the same `.go` would be counted twice. Files under no
`go.mod` are grouped under `None` and stay with the per-file path.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import platform
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Iterable
from importlib.resources import files
from pathlib import Path

from pydantic import ValidationError

from pqcheck.detectors.go_detector import detect_go_file
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation

if sys.platform != "win32":  # resource is POSIX-only
    import resource

_DETECTOR_ID = "go-types"

# The pin is generated at wheel-build time (hatch_build.py) into _constants.py,
# shipping alongside the binary. A bundled binary with no pin is unverifiable
# and refused (fail closed); only the explicit env override runs without one.
try:
    from pqcheck.detectors._constants import CRYPTO_ANALYZER_SHA256 as _generated_pin
except ImportError:
    _generated_pin = None
_CRYPTO_ANALYZER_SHA256: str | None = _generated_pin

# Dev/test override pointing at a locally built binary; Inc4 ships the binary
# under pqcheck/bin/<goos>-<goarch>/ and this stays as an escape hatch.
_ENV_OVERRIDE = "PQCHECK_CRYPTO_ANALYZER"

_TIMEOUT_SECONDS = 60
# Short reap window after a SIGKILL: the child is already dying, so waiting the
# full _TIMEOUT_SECONDS again would only double the worst-case failure latency.
_REAP_TIMEOUT_SECONDS = 5
_MAX_STDOUT_BYTES = 8 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
# Soft Go heap target. The GC works harder as the live heap approaches this
# instead of letting RSS run away, so a heavy-but-benign module finishes rather
# than OOM-killing. This is the primary memory knob; the rlimit below is only a
# crash backstop for true runaways.
_GOMEMLIMIT = "1500MiB"
# Hard backstop on the analyzer child's data segment. We cap RLIMIT_DATA, not
# RLIMIT_AS: the Go runtime reserves a huge virtual address space (vsz) that far
# exceeds resident memory, so an RLIMIT_AS cap OOM-kills modules whose actual
# RSS is modest. RLIMIT_DATA tracks the heap-backing allocations the runtime
# really grows, so a generous ceiling here stops a runaway without falsely
# killing a module that just touches a lot of address space.
_MEMORY_LIMIT_BYTES = 3 * 1024**3


def detect_go_module(module_root: Path) -> list[CryptoFinding]:
    """Detect crypto in the Go module rooted at `module_root`. Never raises.

    Prefers the semantic crypto-analyzer; falls back to the per-file tree-sitter
    detector when the binary is absent, fails SHA-256 verification, or cannot run
    (e.g. `go` missing / module unresolved). A clean analyzer run is trusted even
    when it finds nothing, so an empty semantic result does not trigger fallback.
    """
    located = _locate_binary()
    if located is not None:
        binary, trusted = located
        if _verify_sha256(binary, trusted=trusted):
            stdout = _run_analyzer(module_root, binary)
            if stdout is not None:
                return _map_findings(stdout)
    return _fallback(module_root)


def _fallback(module_root: Path) -> list[CryptoFinding]:
    """Tree-sitter fallback for one module root. Never raises.

    Walks every `.go` file under `module_root`, skipping files that belong to a
    nested module (those have a `go.mod` ancestor below the root that is not the
    root itself, so they will be dispatched on their own root). Returns [] on an
    empty or unreadable module rather than propagating any error — callers rely on
    the never-raise contract.
    """
    module_root = module_root.resolve()
    findings: list[CryptoFinding] = []
    for go_file in sorted(module_root.rglob("*.go")):
        if _nearest_go_mod_dir(go_file, module_root) != module_root:
            continue  # nested module: dispatched on its own root, not here
        findings.extend(detect_go_file(go_file))
    return findings


def group_go_files_by_module(
    go_files: Iterable[Path], *, scan_root: Path
) -> dict[Path | None, list[Path]]:
    """Group `.go` files by the directory of their nearest ancestor `go.mod`.

    Search stops at `scan_root`; a file with no `go.mod` at or below `scan_root`
    is grouped under `None`. Each group's file list is sorted for determinism.
    """
    grouping: dict[Path | None, list[Path]] = {}
    for go_file in go_files:
        root = _nearest_go_mod_dir(go_file, scan_root)
        grouping.setdefault(root, []).append(go_file)
    for paths in grouping.values():
        paths.sort()
    return grouping


def claimed_go_files(grouping: dict[Path | None, list[Path]]) -> set[Path]:
    """Files owned by module dispatch — those under a resolved `go.mod`.

    The per-file fallback loop must skip these to avoid double-counting. Files
    grouped under `None` (no module) are not claimed; they stay per-file.
    """
    return {f for root, paths in grouping.items() if root is not None for f in paths}


def _nearest_go_mod_dir(go_file: Path, scan_root: Path) -> Path | None:
    scan_root = scan_root.resolve()
    current = go_file.resolve().parent
    while current == scan_root or scan_root in current.parents:
        if (current / "go.mod").is_file():
            return current
        if current == scan_root:
            break
        current = current.parent
    return None


def _binary_name() -> str:
    return "crypto-analyzer.exe" if sys.platform == "win32" else "crypto-analyzer"


def _platform_dir() -> str:
    goos = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(
        sys.platform, sys.platform
    )
    goarch = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine().lower(), platform.machine().lower()
    )
    return f"{goos}-{goarch}"


def _locate_binary() -> tuple[Path, bool] | None:
    """Find the crypto-analyzer binary and whether the operator vouches for it.

    The env override is an explicit operator choice (a locally built binary in
    dev or test), returned as trusted so it runs without a pin. The bundled
    location pqcheck/bin/<goos>-<goarch>/ is untrusted and must match the
    build-time pin. Returns None (never raises) when neither resolves to a real
    file — the caller then falls back to tree-sitter.
    """
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        candidate = Path(override)
        return (candidate, True) if candidate.is_file() else None
    try:
        bundled = files("pqcheck.bin").joinpath(_platform_dir(), _binary_name())
    except (ModuleNotFoundError, FileNotFoundError):
        return None  # bin/ not packaged before Inc4
    path = Path(str(bundled))
    return (path, False) if path.is_file() else None


def _verify_sha256(binary: Path, *, trusted: bool) -> bool:
    if trusted:
        return True  # operator vouches for it via PQCHECK_CRYPTO_ANALYZER
    if _CRYPTO_ANALYZER_SHA256 is None:
        return False  # bundled binary with no build-time pin: fail closed
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    return digest == _CRYPTO_ANALYZER_SHA256


def _hardened_env() -> dict[str, str]:
    """Curated env for the analyzer process.

    The binary itself re-pins the `go list` driver env (see analyzer.go); these
    duplicate it so intent survives even if that append order changes, and PATH/
    HOME are kept so the toolchain resolves. The scanned repo is attacker-
    controlled, so every download/exec/workspace lever is pinned off.
    """
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR") if key in os.environ}
    env.update(
        GOTOOLCHAIN="local",
        CGO_ENABLED="0",
        GOFLAGS="-mod=readonly",
        GOWORK="off",
        GOPROXY="off",
        GOSUMDB="off",
        GOENV="off",
        GOMEMLIMIT=_GOMEMLIMIT,
    )
    return env


def _set_memory_limit() -> None:  # pragma: no cover - runs in the forked child
    # Lower the soft limit only, clamped to the inherited hard limit. A non-root
    # child cannot raise a hard limit, and macOS ships a finite RLIMIT_DATA hard
    # cap, so setting (target, target) outright raises inside the preexec_fn and
    # aborts the spawn. GOMEMLIMIT is the primary knob; this rlimit is a
    # best-effort crash backstop, so any platform that rejects it is tolerated.
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_DATA)
        target = _MEMORY_LIMIT_BYTES
        if hard != resource.RLIM_INFINITY:
            target = min(target, hard)
        resource.setrlimit(resource.RLIMIT_DATA, (target, hard))
    except (OSError, ValueError):
        pass


def _run_analyzer(module_root: Path, binary: Path) -> str | None:
    """Invoke the analyzer under the hardened envelope. Never raises.

    Returns decoded stdout on a clean exit, or None on timeout, non-zero exit,
    oversized output, or any OS error — every failure routes to the fallback.

    The child runs in its own session/process group so a timeout can SIGKILL the
    whole group: `go list` and the compiler it spawns are grandchildren that
    `subprocess.run`'s timeout would leave orphaned. stdout is drained chunk by
    chunk against the byte cap so a flood of output is rejected and the child
    torn down the moment the cap is crossed, never buffered past it.
    """
    posix = sys.platform != "win32"
    preexec = _set_memory_limit if posix else None
    try:
        # binary is our SHA-256-verified analyzer and argv is fully controlled;
        # the scanned repo is read by the child under the hardened env, not here.
        proc = subprocess.Popen(  # noqa: S603
            [str(binary), str(module_root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_hardened_env(),
            preexec_fn=preexec,  # noqa: PLW1509 - single-threaded scanner, POSIX-only
            start_new_session=posix,
        )
    except OSError:
        return None
    if posix:
        return _collect_output(proc)
    return _collect_output_windows(proc)


def _collect_output(proc: subprocess.Popen[bytes]) -> str | None:
    """Drain stdout under a wall-clock deadline and the byte cap (POSIX).

    A selector lets the read respect the timeout even if the child writes
    nothing, while the running total enforces the cap before the buffer can
    outgrow it. Any timeout / cap breach / OS error tears down the whole group.
    """
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    chunks: list[bytes] = []
    total = 0
    pipe = proc.stdout
    assert isinstance(pipe, io.BufferedReader)  # stdout=PIPE
    selector = selectors.DefaultSelector()
    selector.register(pipe, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(timeout=remaining):
                _kill_group(proc, posix=True)
                return None
            chunk = pipe.read1(_READ_CHUNK_BYTES)  # one ready read, no refill
            if not chunk:
                break  # EOF
            total += len(chunk)
            if total > _MAX_STDOUT_BYTES:
                _kill_group(proc, posix=True)
                return None
            chunks.append(chunk)
    except OSError:
        _kill_group(proc, posix=True)
        return None
    finally:
        selector.close()
    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except (subprocess.TimeoutExpired, OSError):
        _kill_group(proc, posix=True)
        return None
    if proc.returncode != 0:
        return None
    return b"".join(chunks).decode("utf-8", "replace")


def _collect_output_windows(proc: subprocess.Popen[bytes]) -> str | None:  # pragma: no cover
    """Windows fallback: no selector on pipes, so lean on communicate()."""
    try:
        stdout, _ = proc.communicate(timeout=_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        _kill_group(proc, posix=False)
        return None
    if proc.returncode != 0 or len(stdout) > _MAX_STDOUT_BYTES:
        return None
    return stdout.decode("utf-8", "replace")


def _kill_group(proc: subprocess.Popen[bytes], *, posix: bool) -> None:
    """Tear down the analyzer and any grandchildren it spawned, then reap.

    On POSIX the child leads its own process group, so signalling the group
    reaches the `go list`/compiler grandchildren that would otherwise orphan.
    On Windows there is no killpg, so fall back to killing the direct child.
    """
    with contextlib.suppress(OSError, ProcessLookupError):
        if posix:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover - Windows path
            proc.kill()
    with contextlib.suppress(subprocess.TimeoutExpired, OSError):
        proc.communicate(timeout=_REAP_TIMEOUT_SECONDS)


def _map_findings(stdout: str) -> list[CryptoFinding]:
    """Map the analyzer's JSON array to CryptoFindings. Never raises.

    Malformed JSON or a non-array payload yields []. A single item that fails
    schema validation is skipped so the remaining valid findings survive — the
    pydantic models are the schema, no separate JSON schema is needed.
    """
    try:
        raw = json.loads(stdout)
    except ValueError:
        return []
    if not isinstance(raw, list):
        return []
    findings: list[CryptoFinding] = []
    for item in raw:
        finding = _build_finding(item)
        if finding is not None:
            findings.append(finding)
    return findings


def _build_finding(item: object) -> CryptoFinding | None:
    if not isinstance(item, dict):
        return None
    try:
        location = SourceLocation(
            path=Path(item["path"]),
            line=item["line"],
            column=item["column"],
            end_line=item.get("end_line"),
            end_column=item.get("end_column"),
        )
        return CryptoFinding(
            algorithm=item["algorithm"],
            family=AlgorithmFamily(item["family"]),
            key_size=item.get("key_size"),
            curve=item.get("curve") or None,
            mode=item.get("mode") or None,
            padding=item.get("padding") or None,
            location=location,
            evidence=item.get("evidence", ""),
            detector_id=_DETECTOR_ID,
            confidence=item["confidence"],
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        return None
