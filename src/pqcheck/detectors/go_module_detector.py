"""Module-granularity Go detection: a bridge to the bundled crypto-analyzer.

`go/packages` resolves at package/module granularity (it needs neighbouring
files plus deps to type-check), so Go detection runs once per module rather than
once per file. `detect_go_module` invokes the bundled `crypto-analyzer` binary
under a hardened subprocess and maps its JSON to `CryptoFinding`; when `go` is
absent or the module does not resolve, it falls back to the per-file tree-sitter
detector so the detection floor never drops below today's literal-based one.

The child runs against an attacker-controlled module, so its memory is bounded
on three levels: a GOMEMLIMIT soft GC target, an RLIMIT_DATA crash backstop, and
an RSS poller in the collection loop that SIGKILLs the process group once the
resident set crosses `_RSS_LIMIT_BYTES`. The RSS poller is the real hard cap on
Linux, where the runtime grows its heap via mmap that the rlimit cannot see.

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

from pqcheck.detectors.go_detector import _MAX_KEY_SIZE, detect_go_file
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
# than OOM-killing. GOMEMLIMIT is only a soft GC target the runtime may exceed,
# so the RSS poller below is the real hard backstop on Linux.
_GOMEMLIMIT = "1500MiB"
# Hard RSS ceiling enforced by polling /proc/<pid>/statm in the collection loop.
# This is the real backstop against a host-OOM DoS from an attacker-controlled
# module: GOMEMLIMIT is only a soft GC target, and on Linux RLIMIT_DATA does not
# account for the mmap regions the Go runtime grows its heap from, so neither
# reliably fires. 2 GiB leaves headroom above the 1500MiB soft target for a
# heavy-but-benign module to finish while still capping a true runaway well
# below the RLIMIT_DATA crash backstop.
_RSS_LIMIT_BYTES = 2 * 1024**3
# Cap on how long the selector blocks per iteration so RSS is re-sampled even
# while the child grows its heap without writing stdout. Without it, a silent
# memory runaway would only be caught at the wall-clock timeout, far too late.
_RSS_POLL_SECONDS = 0.25
# Last-ditch crash backstop on the child's data segment. We cap RLIMIT_DATA, not
# RLIMIT_AS: the Go runtime reserves a huge virtual address space (vsz) that far
# exceeds resident memory, so an RLIMIT_AS cap OOM-kills modules whose actual
# RSS is modest. On Linux RLIMIT_DATA also misses mmap-backed heap growth, so it
# is defense in depth only — the RSS poller is the primary kill. Kept for the
# platforms (and allocation paths) where it does bite.
_MEMORY_LIMIT_BYTES = 3 * 1024**3


def detect_go_module(module_root: Path) -> list[CryptoFinding]:
    """Detect crypto in the Go module rooted at `module_root`. Never raises.

    Prefers the semantic crypto-analyzer; falls back to the per-file tree-sitter
    detector when the binary is absent, fails SHA-256 verification, or cannot run
    (e.g. `go` missing / module unresolved). A clean analyzer run is trusted even
    when it finds nothing, so an empty semantic result does not trigger fallback.
    """
    if not _argv_encodable(module_root):
        return _fallback(module_root)
    located = _locate_binary()
    if located is not None:
        binary, trusted = located
        if _verify_sha256(binary, trusted=trusted):
            stdout = _run_analyzer(module_root, binary)
            if stdout is not None:
                return _map_findings(stdout, module_root)
    return _fallback(module_root)


def _argv_encodable(module_root: Path) -> bool:
    """True when the module path is strict UTF-8, a precondition for the argv.

    A scanned repo can carry non-UTF-8 directory names, which os.fsdecode surfaces
    as surrogate escapes. subprocess round-trips those raw bytes instead of
    raising, so the analyzer would silently receive a non-UTF-8 argv. Reject here
    and let the pure-Python fallback (no argv) handle the module.
    """
    try:
        str(module_root).encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


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
    try:
        go_files = sorted(module_root.rglob("*.go"))
    except OSError:
        return findings  # unreadable directory while walking — honour never-raise
    for go_file in go_files:
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
    except (ModuleNotFoundError, FileNotFoundError, TypeError):
        return None  # bin/ unpackaged (source install) or a namespace-package resource lookup
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
    """Curated env for the analyzer's own process — clean slate, not inherited.

    Only PATH/HOME/TMPDIR pass through so the toolchain resolves; every
    download/exec/workspace lever is pinned off because the scanned repo is
    attacker-controlled. This governs the analyzer process itself. The binary is
    authoritative for the `go list` grandchild that actually resolves modules
    (see analyzer.go:hardenedEnv): it re-derives the env there, choosing
    -mod=vendor vs -mod=readonly from the repo and pointing GOCACHE/GOMODCACHE/
    GOPATH at a scratch dir. The pins here are a best-effort process-level floor,
    not a full mirror of that layer.
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


def _set_memory_limit() -> None:
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


def _read_rss_bytes(pid: int) -> int | None:
    """Current resident-set size of `pid` in bytes, or None (best-effort).

    Linux exposes RSS as field 2 (resident pages) of /proc/<pid>/statm. On any
    other platform, or if the process is gone or /proc is unreadable, return
    None so the caller treats the sample as "unknown" rather than a breach.
    """
    if sys.platform != "linux":
        return None
    try:
        fields = Path(f"/proc/{pid}/statm").read_text().split()
        return int(fields[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        return None


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
    """Drain stdout under a wall-clock deadline, byte cap, and RSS ceiling (POSIX).

    The draining and its breach checks live in `_drain_stdout`; here we only
    guard the pipe, reap the child, and decode on a clean exit. Any timeout /
    cap breach / RSS breach / OS error has already torn down the whole group and
    surfaces as None.
    """
    deadline = time.monotonic() + _TIMEOUT_SECONDS
    pipe = proc.stdout
    if not isinstance(pipe, io.BufferedReader):  # stdout=PIPE; guard, asserts are -O stripped
        _kill_group(proc, posix=True)
        return None
    payload = _drain_stdout(proc, pipe, deadline)
    if payload is None:
        return None
    # The child has closed stdout (EOF) and is exiting; grant a fixed reap grace
    # rather than the leftover read budget, which can be ~0 when a slow child
    # trickled valid output up to the deadline — waiting ~0 would SIGKILL a child
    # that already produced a usable payload. Worst-case latency stays bounded at
    # _TIMEOUT_SECONDS + _REAP_TIMEOUT_SECONDS.
    try:
        proc.wait(timeout=_REAP_TIMEOUT_SECONDS)
    except (subprocess.TimeoutExpired, OSError):
        _kill_group(proc, posix=True)
        return None
    if proc.returncode != 0:
        return None
    return payload.decode("utf-8", "replace")


def _drain_stdout(
    proc: subprocess.Popen[bytes], pipe: io.BufferedReader, deadline: float
) -> bytes | None:
    """Read stdout to EOF, enforcing the deadline, byte cap, and RSS ceiling.

    A selector lets the read respect the timeout even if the child writes
    nothing, while the running total enforces the cap before the buffer can
    outgrow it. Each iteration also samples the child's RSS, since a runaway can
    eat host memory without ever writing past the byte cap. Returns the joined
    bytes on EOF, or None after tearing down the group on any breach/error.
    """
    chunks: list[bytes] = []
    total = 0
    selector = selectors.DefaultSelector()
    selector.register(pipe, selectors.EVENT_READ)
    try:
        while True:
            rss = _read_rss_bytes(proc.pid)
            if rss is not None and rss > _RSS_LIMIT_BYTES:
                _kill_group(proc, posix=True)
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(timeout=min(remaining, _RSS_POLL_SECONDS)):
                if deadline - time.monotonic() <= 0:
                    _kill_group(proc, posix=True)
                    return None
                continue  # poll tick elapsed with no data: re-sample RSS, keep waiting
            chunk = pipe.read1(_READ_CHUNK_BYTES)  # one ready read, no refill
            if not chunk:
                return b"".join(chunks)  # EOF
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


def _map_findings(stdout: str, module_root: Path) -> list[CryptoFinding]:
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
        finding = _build_finding(item, module_root)
        if finding is not None:
            findings.append(finding)
    return findings


def _build_finding(item: object, module_root: Path) -> CryptoFinding | None:
    if not isinstance(item, dict):
        return None
    try:
        path = Path(item["path"])
        if not _path_within(path, module_root):
            return None  # a finding outside the scanned module is not trusted
        location = SourceLocation(
            path=path,
            line=item["line"],
            column=item["column"],
            end_line=item.get("end_line"),
            end_column=item.get("end_column"),
        )
        return CryptoFinding(
            algorithm=item["algorithm"],
            family=AlgorithmFamily(item["family"]),
            key_size=_clamp_key_size(item.get("key_size")),
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


def _clamp_key_size(value: object) -> int | None:
    """Bound an analyzer-reported key size, mirroring go_detector's clamp.

    The bundled binary already clamps in constInt, but the PQCHECK_CRYPTO_ANALYZER
    override runs unpinned, so its key_size is untrusted. A value outside a
    plausible range is not a real key and is dropped (the finding survives)
    rather than carried into CBOM/SARIF.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 < value <= _MAX_KEY_SIZE else None


def _path_within(path: Path, root: Path) -> bool:
    """True when path resolves inside root. The binary emits absolute source
    paths under the scanned module; one outside it (`..`, an absolute escape)
    is not a location this scan produced."""
    try:
        return path.resolve().is_relative_to(root.resolve())
    except (OSError, ValueError):
        return False
