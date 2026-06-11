import contextlib
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pqcheck.detectors import go_module_detector as gmd
from pqcheck.detectors.go_module_detector import (
    claimed_go_files,
    detect_go_module,
    group_go_files_by_module,
)
from pqcheck.models import AlgorithmFamily, CryptoFinding, QuantumRisk, SourceLocation

_MD5_SRC = 'package main\nimport "crypto/md5"\nfunc main() { md5.New() }\n'


def _write_module(root: Path, *, module: str = "example.com/m") -> None:
    (root / "go.mod").write_text(f"module {module}\n\ngo 1.24\n", encoding="utf-8")


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path


def test_detect_go_module_rejects_non_utf8_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The spec requires strict-UTF-8 argv. A module path carrying non-UTF-8
    # bytes (here a lone surrogate from os.fsdecode of a non-UTF-8 dir name)
    # must never reach the subprocess; the bridge routes it to the tree-sitter
    # fallback instead. Force the analyzer path so the guard is what diverts it.
    bad_root = Path(str(tmp_path) + "/\udcffmod")
    marker: list[CryptoFinding] = []

    def _must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("analyzer spawned with a non-UTF-8 path")

    monkeypatch.setattr(gmd, "_locate_binary", lambda: (Path("/fake/analyzer"), True))
    monkeypatch.setattr(gmd, "_verify_sha256", lambda binary, trusted: True)
    monkeypatch.setattr(gmd, "_run_analyzer", _must_not_run)
    monkeypatch.setattr(gmd, "_fallback", lambda root: marker)

    assert detect_go_module(bad_root) is marker


def test_groups_files_by_nearest_go_mod(tmp_path: Path) -> None:
    _touch(tmp_path / "go.mod")
    a = _touch(tmp_path / "a.go")
    b = _touch(tmp_path / "pkg" / "b.go")  # no go.mod in pkg -> root module
    _touch(tmp_path / "sub" / "go.mod")
    c = _touch(tmp_path / "sub" / "c.go")  # nested module owns c

    grouping = group_go_files_by_module([a, b, c], scan_root=tmp_path)

    assert grouping[tmp_path] == [a, b]
    assert grouping[tmp_path / "sub"] == [c]


def test_files_outside_any_module_grouped_under_none(tmp_path: Path) -> None:
    x = _touch(tmp_path / "x.go")  # no go.mod anywhere

    grouping = group_go_files_by_module([x], scan_root=tmp_path)

    assert grouping[None] == [x]


def test_each_file_claimed_by_exactly_one_module(tmp_path: Path) -> None:
    _touch(tmp_path / "go.mod")
    _touch(tmp_path / "sub" / "go.mod")
    a = _touch(tmp_path / "a.go")
    c = _touch(tmp_path / "sub" / "c.go")

    grouping = group_go_files_by_module([a, c], scan_root=tmp_path)
    claimed = claimed_go_files(grouping)

    assert claimed == {a, c}
    listed = [f for root, files in grouping.items() if root is not None for f in files]
    assert len(listed) == len(set(listed)), "a .go file must be claimed by one module"


def test_claimed_excludes_non_module_files(tmp_path: Path) -> None:
    x = _touch(tmp_path / "x.go")  # no go.mod -> not owned by module dispatch

    grouping = group_go_files_by_module([x], scan_root=tmp_path)

    assert claimed_go_files(grouping) == set()


def test_fallback_returns_empty_when_walk_raises_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(self: Path, pattern: str) -> object:
        raise PermissionError("unreadable directory")

    monkeypatch.setattr(Path, "rglob", boom)

    assert gmd._fallback(tmp_path) == []


def test_locate_binary_env_override_missing_file_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PQCHECK_CRYPTO_ANALYZER", str(tmp_path / "absent"))
    assert gmd._locate_binary() is None


def test_locate_binary_returns_none_when_unbundled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # No env override and no binary on the resource path -> None. Point the
    # resource lookup at an empty dir so the result does not depend on whether a
    # local build left a binary under pqcheck/bin/ in the working tree.
    monkeypatch.delenv("PQCHECK_CRYPTO_ANALYZER", raising=False)
    monkeypatch.setattr(gmd, "files", lambda _pkg: tmp_path)
    assert gmd._locate_binary() is None


def test_sha256_pin_absent_without_generated_constants() -> None:
    # No build-generated _constants.py in the dev tree -> lenient verification.
    assert gmd._CRYPTO_ANALYZER_SHA256 is None


def test_verify_sha256_matches_pin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(b"binary-bytes")
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", hashlib.sha256(b"binary-bytes").hexdigest())
    assert gmd._verify_sha256(binary, trusted=False) is True


def test_verify_sha256_rejects_mismatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(b"tampered")
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", "0" * 64)
    assert gmd._verify_sha256(binary, trusted=False) is False


def test_locate_binary_env_override_is_trusted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    monkeypatch.setenv("PQCHECK_CRYPTO_ANALYZER", str(binary))
    assert gmd._locate_binary() == (binary, True)


def test_verify_sha256_fails_closed_for_bundled_binary_without_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A bundled binary with no build-time pin is unverifiable: refuse it rather
    # than run an unauthenticated binary off the install tree.
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", None)
    binary = tmp_path / "bin"
    binary.write_bytes(b"unverified")
    assert gmd._verify_sha256(binary, trusted=False) is False


def test_verify_sha256_trusts_override_without_pin(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The env override is an explicit operator choice (dev/test build), trusted
    # without a pin so local development keeps working.
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", None)
    binary = tmp_path / "bin"
    binary.write_bytes(b"dev-built")
    assert gmd._verify_sha256(binary, trusted=True) is True


def test_detect_go_module_falls_back_when_bundled_pin_mismatches(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # End-to-end fail-closed: a present, untrusted (bundled) binary whose bytes
    # do not match the build-time pin must never run — detect_go_module routes to
    # the tree-sitter fallback. Drives the real _verify_sha256 (not mocked) so the
    # security-critical mismatch path is proven through the full entry point.
    binary = tmp_path / "bin" / "crypto-analyzer"
    binary.parent.mkdir()
    binary.write_bytes(b"tampered-binary")
    marker: list[CryptoFinding] = []

    def _must_not_run(*args: object, **kwargs: object) -> None:
        raise AssertionError("analyzer ran despite a SHA-256 pin mismatch")

    monkeypatch.setattr(gmd, "_locate_binary", lambda: (binary, False))
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", "0" * 64)
    monkeypatch.setattr(gmd, "_run_analyzer", _must_not_run)
    monkeypatch.setattr(gmd, "_fallback", lambda root: marker)

    assert detect_go_module(tmp_path) is marker


requires_posix = pytest.mark.skipif(
    sys.platform == "win32", reason="bridge subprocess tests assume POSIX scripts"
)


def _script(path: Path, body: str) -> Path:
    # Drive _run_analyzer against a real child so the selector read, the byte
    # cap, the timeout, and the process-group kill all exercise live fds rather
    # than a mock that cannot back a selectors.select.
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


@requires_posix
def test_run_analyzer_returns_stdout_on_success(tmp_path: Path) -> None:
    binary = _script(tmp_path / "ok.sh", "printf '[]'\n")
    assert gmd._run_analyzer(tmp_path, binary) == "[]"


@requires_posix
def test_run_analyzer_nonzero_exit_returns_none(tmp_path: Path) -> None:
    binary = _script(tmp_path / "fail.sh", "printf 'partial'\nexit 1\n")
    assert gmd._run_analyzer(tmp_path, binary) is None


@requires_posix
def test_run_analyzer_oversized_stdout_rejected(tmp_path: Path) -> None:
    # Emit more than the cap; the chunked reader must abort mid-stream, not
    # buffer it all. yes(1) would never finish on its own.
    binary = _script(tmp_path / "flood.sh", "yes xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
    assert gmd._run_analyzer(tmp_path, binary) is None


def test_run_analyzer_spawn_os_error_returns_none(tmp_path: Path) -> None:
    # A path that is not an executable file -> Popen raises OSError on spawn.
    assert gmd._run_analyzer(tmp_path, tmp_path / "does-not-exist") is None


@requires_posix
def test_run_analyzer_timeout_returns_none(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", 1)
    binary = _script(tmp_path / "hang.sh", "sleep 30\n")
    assert gmd._run_analyzer(tmp_path, binary) is None


@requires_posix
def test_run_analyzer_partial_write_then_hang_times_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Writes far less than a read chunk then hangs: the reader must not block
    # waiting to fill a chunk, it must hit the deadline and bail.
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", 1)
    binary = _script(tmp_path / "drip.sh", "printf 'half'\nsleep 30\n")
    assert gmd._run_analyzer(tmp_path, binary) is None


@requires_posix
def test_run_analyzer_steady_trickle_under_cap_still_times_out(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A child that streams a little at a time, staying under the byte cap and
    # RSS ceiling, must still be bounded by the wall-clock deadline. The deadline
    # has to be checked on every loop iteration, not only when the selector
    # reports no data — otherwise a continuous slow trickle keeps reading past
    # the timeout until the child finishes on its own. The child runs ~6s; with
    # a 1s deadline the call must return None in well under 3s.
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", 1)
    binary = _script(
        tmp_path / "trickle.sh",
        "i=0\nwhile [ $i -lt 60 ]; do printf 'x'; sleep 0.1; i=$((i+1)); done\n",
    )
    started = time.monotonic()
    result = gmd._run_analyzer(tmp_path, binary)
    elapsed = time.monotonic() - started
    assert result is None
    assert elapsed < 3, "wall-clock deadline not enforced under steady trickle"


@requires_posix
def test_run_analyzer_grants_exit_grace_after_read_deadline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A child that produced valid output but closed stdout just as the read
    # deadline lapsed must still get a small grace window to exit. Tying the
    # post-drain wait to the leftover read budget would wait(~0) and SIGKILL a
    # child that already emitted a valid payload, dropping it to the fallback.
    # Drain is stubbed to a clean payload with the deadline already in the past;
    # the child needs a moment to exit, which the reap grace must cover.
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", -1)  # read deadline already past
    monkeypatch.setattr(gmd, "_drain_stdout", lambda proc, pipe, deadline: b"[]")
    binary = _script(tmp_path / "slow_exit.sh", "sleep 0.3\n")
    assert gmd._run_analyzer(tmp_path, binary) == "[]"


def _spy_mkdtemp(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every scratch dir the bridge creates so a test can assert it is
    plumbed to the child and cleaned up afterwards."""
    created: list[str] = []
    real = gmd.tempfile.mkdtemp

    def spy(*args: object, **kwargs: object) -> str:
        path = real(*args, **kwargs)
        created.append(path)
        return path

    monkeypatch.setattr(gmd.tempfile, "mkdtemp", spy)
    return created


@requires_posix
def test_run_analyzer_runs_child_under_owned_scratch_and_cleans_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The bridge owns a scratch dir, hands it to the child as TMPDIR (so the
    # binary's GOCACHE/GOMODCACHE and its own os.MkdirTemp land inside it), and
    # removes it after a clean run. The child records the TMPDIR it saw.
    created = _spy_mkdtemp(monkeypatch)
    binary = _script(tmp_path / "probe.sh", 'printf "%s" "$TMPDIR" > "$1/seen"\nprintf "[]"\n')

    assert gmd._run_analyzer(tmp_path, binary) == "[]"

    assert created, "bridge did not create a scratch dir"
    seen_tmpdir = (tmp_path / "seen").read_text()
    assert seen_tmpdir == created[0], "child did not run under the bridge-owned scratch"
    assert not Path(created[0]).exists(), "scratch dir survived a clean run"


@requires_posix
def test_run_analyzer_removes_scratch_after_sigkill(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The child's in-process cleanup runs via a defer that SIGKILL skips, so the
    # bridge must remove the scratch itself after reaping — regardless of how the
    # child died. Here the child writes into TMPDIR then hangs into a timeout kill.
    created = _spy_mkdtemp(monkeypatch)
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", 1)
    binary = _script(tmp_path / "hang.sh", 'touch "$TMPDIR/leftover"\nsleep 30\n')

    assert gmd._run_analyzer(tmp_path, binary) is None

    assert created, "bridge did not create a scratch dir"
    assert not Path(created[0]).exists(), "scratch leaked after a SIGKILL teardown"


def test_kill_group_swallows_lookup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # Group already gone between timeout and kill: tear-down must not raise.
    class _Dead:
        pid = 4321
        returncode = None

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            return b"", b""

    monkeypatch.setattr(gmd.os, "getpgid", lambda pid: pid)

    def gone(pgid: int, sig: int) -> None:
        raise ProcessLookupError

    monkeypatch.setattr(gmd.os, "killpg", gone)
    gmd._kill_group(_Dead(), posix=True)  # type: ignore[arg-type]


@requires_posix
def test_run_analyzer_timeout_reaps_real_grandchild(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A real process tree: the analyzer stand-in forks a sleeping grandchild and
    # itself hangs. The timeout must SIGKILL the whole group so the grandchild
    # does not survive as an orphan.
    script = _script(
        tmp_path / "fake-analyzer.sh",
        "sleep 300 &\n"  # grandchild, in our process group
        'echo "$!" > "$1/grandchild.pid"\n'
        "sleep 300\n",  # the analyzer itself hangs
    )
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", 1)
    assert gmd._run_analyzer(tmp_path, script) is None

    pid_file = tmp_path / "grandchild.pid"
    assert pid_file.is_file(), "stand-in did not record its grandchild"
    grandchild = int(pid_file.read_text().strip())
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break  # reaped, as intended
        time.sleep(0.05)
    else:
        os.kill(grandchild, signal.SIGKILL)
        pytest.fail("grandchild survived the process-group kill")


@pytest.mark.skipif(sys.platform != "linux", reason="/proc/<pid>/statm is Linux-only")
def test_read_rss_bytes_reports_plausible_value_for_self() -> None:
    # The reader must return a positive byte count for a live process. We read
    # our own pid: the interpreter clearly has a non-trivial resident set.
    rss = gmd._read_rss_bytes(os.getpid())
    assert rss is not None
    assert rss > 1024 * 1024  # at least ~1 MiB resident


def test_read_rss_bytes_returns_none_for_dead_pid() -> None:
    # No /proc entry (dead/never-existed pid, or non-Linux) -> best-effort None.
    assert gmd._read_rss_bytes(2**31 - 1) is None


@pytest.mark.skipif(sys.platform != "linux", reason="/proc is Linux-only")
def test_read_group_rss_includes_grandchild() -> None:
    # The dominant allocator is often the `go list` grandchild, invisible to a
    # parent-only RSS read. The group sum must include it: a small shell leader
    # spawns a python child holding ~100 MiB in the same process group.
    child = "python3 -c 'b=bytearray(100*1024*1024); import time; time.sleep(3)'"
    leader = subprocess.Popen(
        ["sh", "-c", f"{child} & sleep 3"],
        start_new_session=True,
    )
    try:
        time.sleep(0.8)
        group_rss = gmd._read_group_rss_bytes(leader.pid)
        parent_rss = gmd._read_rss_bytes(leader.pid)
        assert group_rss is not None and parent_rss is not None
        # The group total carries the child's ~100 MiB the parent-only read misses.
        assert group_rss >= parent_rss + 80 * 1024 * 1024
    finally:
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(os.getpgid(leader.pid), signal.SIGKILL)
        leader.wait()


def test_read_group_rss_returns_none_for_dead_group() -> None:
    # No process in the group could be sampled -> best-effort None.
    assert gmd._read_group_rss_bytes(2**31 - 1) is None


@requires_posix
def test_run_analyzer_rss_over_ceiling_is_killed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The child is benign but stubbed to report RSS past the ceiling: the poller
    # in the collection loop must tear down the group and route to failure (None)
    # rather than waiting on the wall-clock timeout. A child that sleeps far
    # longer than the timeout proves the RSS kill is what ended it: if the poll
    # were a no-op the call would block for the full _TIMEOUT_SECONDS.
    monkeypatch.setattr(gmd, "_read_group_rss_bytes", lambda pgid: gmd._RSS_LIMIT_BYTES + 1)
    monkeypatch.setattr(gmd, "_TIMEOUT_SECONDS", 30)
    binary = _script(tmp_path / "hog.sh", "sleep 300\n")
    started = time.monotonic()
    result = gmd._run_analyzer(tmp_path, binary)
    elapsed = time.monotonic() - started
    assert result is None
    assert elapsed < 5, "RSS ceiling did not fire; fell through to the timeout"


@requires_posix
def test_run_analyzer_rss_under_ceiling_succeeds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # RSS comfortably under the ceiling must not perturb a clean run.
    monkeypatch.setattr(gmd, "_read_group_rss_bytes", lambda pgid: 1024)
    binary = _script(tmp_path / "ok.sh", "printf '[]'\n")
    assert gmd._run_analyzer(tmp_path, binary) == "[]"


@requires_posix
def test_run_analyzer_missing_stdout_pipe_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # If stdout is somehow not a readable pipe, the collector guards rather than
    # asserting (asserts vanish under python -O).
    class _NoPipe:
        pid = 2**31 - 1  # no such process: _kill_group's getpgid swallows it
        returncode = None
        stdout = None

        def wait(self, timeout: float | None = None) -> int:
            return 0

        def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
            return b"", b""

    assert gmd._collect_output(_NoPipe()) is None  # type: ignore[arg-type]


@requires_posix
def test_collect_output_reap_timeout_after_eof_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The child emits a valid payload, closes stdout (EOF), then refuses to exit.
    # Draining returns the payload, but the reap wait times out, so the group is
    # killed and the result is None — never a payload from a child that hung.
    monkeypatch.setattr(gmd, "_REAP_TIMEOUT_SECONDS", 1)
    binary = _script(tmp_path / "eof_then_hang.sh", "printf '[]'\nexec 1>&-\nsleep 30\n")
    assert gmd._run_analyzer(tmp_path, binary) is None


@requires_posix
def test_drain_stdout_oserror_during_read_returns_none(tmp_path: Path) -> None:
    # An OS error mid-read must tear down the group and surface None, not raise.
    binary = _script(tmp_path / "emit.sh", "printf 'x'\nsleep 30\n")
    proc = subprocess.Popen(
        [str(binary), str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=gmd._hardened_env(str(tmp_path)),
        start_new_session=True,
    )

    class _BoomPipe:
        def __init__(self, real: object) -> None:
            self._real = real

        def fileno(self) -> int:
            return self._real.fileno()  # type: ignore[attr-defined]

        def read1(self, _n: int) -> bytes:
            raise OSError("read failed")

    try:
        result = gmd._drain_stdout(proc, _BoomPipe(proc.stdout), time.monotonic() + 5)  # type: ignore[arg-type]
        assert result is None
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()


_GOLDEN = json.dumps(
    [
        {
            "algorithm": "RSA",
            "family": "asymmetric-encryption",
            "key_size": 2048,
            "path": "/m/main.go",
            "line": 11,
            "column": 2,
            "end_line": 11,
            "end_column": 36,
            "evidence": "rsa.GenerateKey(rand.Reader, 2048)",
            "confidence": 1,
        },
        {
            "algorithm": "AES",
            "family": "symmetric-cipher",
            "mode": "GCM",
            "path": "/m/main.go",
            "line": 12,
            "column": 14,
            "end_line": 12,
            "end_column": 45,
            "evidence": "block, _ := aes.NewCipher(make([]byte, 32))",
            "confidence": 1,
        },
    ]
)


def test_map_findings_builds_cryptofindings() -> None:
    findings = gmd._map_findings(_GOLDEN, Path("/m"))

    assert [f.algorithm for f in findings] == ["RSA", "AES"]
    rsa = findings[0]
    assert rsa.key_size == 2048
    assert rsa.detector_id == "go-types"
    assert rsa.quantum_risk is QuantumRisk.VULNERABLE
    assert rsa.location.path == Path("/m/main.go")
    aes = findings[1]
    assert aes.mode == "GCM"
    assert aes.family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_map_findings_malformed_json_returns_empty() -> None:
    assert gmd._map_findings("{not json", Path("/m")) == []
    assert gmd._map_findings("", Path("/m")) == []


def test_map_findings_non_array_returns_empty() -> None:
    assert gmd._map_findings('{"algorithm": "RSA"}', Path("/m")) == []


def test_map_findings_skips_invalid_item_keeps_valid() -> None:
    stdout = json.dumps(
        [
            {"algorithm": "RSA"},  # missing required fields -> skipped, not raised
            {
                "algorithm": "MD5",
                "family": "hash",
                "path": "/m/h.go",
                "line": 1,
                "column": 0,
                "end_line": 1,
                "end_column": 10,
                "evidence": "md5.New()",
                "confidence": 1,
            },
        ]
    )
    findings = gmd._map_findings(stdout, Path("/m"))
    assert [f.algorithm for f in findings] == ["MD5"]


def test_map_findings_skips_non_dict_items() -> None:
    assert gmd._map_findings('[1, "x", null]', Path("/m")) == []  # non-object elements skipped


def _finding_item(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "algorithm": "RSA",
        "family": "asymmetric-encryption",
        "path": "/m/main.go",
        "line": 1,
        "column": 0,
        "end_line": 1,
        "end_column": 5,
        "evidence": "x",
        "confidence": 1,
    }
    item.update(overrides)
    return item


def test_build_finding_clamps_oversized_key_size() -> None:
    finding = gmd._build_finding(_finding_item(key_size=10**12), Path("/m"))
    assert finding is not None  # the finding survives, only the bogus size is dropped
    assert finding.key_size is None


def test_build_finding_keeps_plausible_key_size() -> None:
    finding = gmd._build_finding(_finding_item(key_size=2048), Path("/m"))
    assert finding is not None
    assert finding.key_size == 2048


def test_build_finding_rejects_non_int_key_size() -> None:
    assert gmd._build_finding(_finding_item(key_size=True), Path("/m")).key_size is None
    assert gmd._build_finding(_finding_item(key_size="2048"), Path("/m")).key_size is None


def test_build_finding_drops_path_outside_module_root() -> None:
    assert gmd._build_finding(_finding_item(path="/etc/passwd"), Path("/m")) is None
    assert gmd._build_finding(_finding_item(path="/m/../etc/x.go"), Path("/m")) is None


def test_build_finding_keeps_path_inside_module_root() -> None:
    finding = gmd._build_finding(_finding_item(path="/m/sub/x.go"), Path("/m"))
    assert finding is not None
    assert finding.location.path == Path("/m/sub/x.go")


def test_platform_dir_maps_to_goos_goarch(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gmd.sys, "platform", "darwin")
    monkeypatch.setattr(gmd.platform, "machine", lambda: "arm64")
    assert gmd._platform_dir() == "darwin-arm64"
    monkeypatch.setattr(gmd.sys, "platform", "linux")
    monkeypatch.setattr(gmd.platform, "machine", lambda: "x86_64")
    assert gmd._platform_dir() == "linux-amd64"


def test_binary_name_per_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(gmd.sys, "platform", "win32")
    assert gmd._binary_name() == "crypto-analyzer.exe"
    monkeypatch.setattr(gmd.sys, "platform", "linux")
    assert gmd._binary_name() == "crypto-analyzer"


def test_detect_go_module_falls_back_when_binary_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gmd, "_locate_binary", lambda: None)
    _write_module(tmp_path)
    (tmp_path / "m.go").write_text(_MD5_SRC, encoding="utf-8")

    findings = detect_go_module(tmp_path)

    assert any(f.algorithm == "MD5" for f in findings)
    assert all(f.detector_id == "go-tree-sitter" for f in findings)


def test_detect_go_module_falls_back_when_analyzer_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    monkeypatch.setattr(gmd, "_locate_binary", lambda: (binary, True))
    monkeypatch.setattr(gmd, "_run_analyzer", lambda root, b: None)
    _write_module(tmp_path)
    (tmp_path / "m.go").write_text(_MD5_SRC, encoding="utf-8")

    findings = detect_go_module(tmp_path)

    assert any(f.algorithm == "MD5" for f in findings)


def test_detect_go_module_uses_analyzer_output_when_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    # The real binary emits absolute source paths under the scanned module; the
    # bridge drops anything outside it, so the golden must live under tmp_path.
    golden = _GOLDEN.replace("/m/", str(tmp_path) + "/")
    monkeypatch.setattr(gmd, "_locate_binary", lambda: (binary, True))
    monkeypatch.setattr(gmd, "_run_analyzer", lambda root, b: golden)

    findings = detect_go_module(tmp_path)

    assert [f.algorithm for f in findings] == ["RSA", "AES"]
    assert all(f.detector_id == "go-types" for f in findings)


def test_detect_go_module_unions_tree_sitter_with_clean_analyzer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Union semantics (corpus decision 2026-06-11, ADR 0005): go/types cannot
    # see GOOS-gated or cgo-gated files, so a clean analyzer run no longer
    # suppresses the syntactic pass — the result is the union of both.
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    monkeypatch.setattr(gmd, "_locate_binary", lambda: (binary, True))
    monkeypatch.setattr(gmd, "_run_analyzer", lambda root, b: "[]")
    _write_module(tmp_path)
    (tmp_path / "m.go").write_text(_MD5_SRC, encoding="utf-8")

    findings = detect_go_module(tmp_path)
    assert [f.algorithm for f in findings] == ["MD5"]
    assert findings[0].detector_id != "go-types"  # came from the syntactic pass


def test_detect_go_module_dedupes_same_call_site_preferring_semantic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    golden = _GOLDEN.replace("/m/", str(tmp_path) + "/")
    monkeypatch.setattr(gmd, "_locate_binary", lambda: (binary, True))
    monkeypatch.setattr(gmd, "_run_analyzer", lambda root, b: golden)

    semantic = gmd._map_findings(golden, tmp_path)
    duplicate = semantic[0].model_copy(
        update={"detector_id": "go-treesitter", "key_size": None}
    )
    extra_loc = duplicate.location.model_copy(update={"line": duplicate.location.line + 90})
    extra = duplicate.model_copy(update={"algorithm": "MD5", "location": extra_loc})
    monkeypatch.setattr(gmd, "_fallback", lambda root: [duplicate, extra])

    findings = detect_go_module(tmp_path)
    # The shared call site keeps the semantic finding (richer key size); the
    # tree-sitter-only site survives the merge.
    algos = [(f.algorithm, f.detector_id) for f in findings]
    assert ("MD5", "go-treesitter") in algos
    assert sum(1 for a, _ in algos if a == semantic[0].algorithm) == len(
        [f for f in semantic if f.algorithm == semantic[0].algorithm]
    )
    shared = [f for f in findings if f.algorithm == semantic[0].algorithm]
    assert all(f.detector_id == "go-types" for f in shared)


def test_merge_dedupes_semantic_internal_duplicates() -> None:
    # go/packages with Tests:true type-checks a production file twice (the
    # package and its under-test variant), duplicating findings for the same
    # call site. Corpus 2026-06-11: 25 such duplicates over 197 real sites.
    def f(line: int, column: int) -> CryptoFinding:
        return CryptoFinding(
            algorithm="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
            location=SourceLocation(path=Path("/m/a.go"), line=line, column=column),
            evidence="rsa.GenerateKey", detector_id="go-types",
        )

    merged = gmd._merge_findings([f(5, 2), f(5, 2), f(9, 0)], [])
    assert [(x.location.line) for x in merged] == [5, 9]


def test_locate_binary_type_error_from_resources_files_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # importlib.resources.files() raises TypeError for namespace packages that
    # have no __file__. _locate_binary must catch it and return None rather than
    # letting the TypeError escape through detect_go_module (which promises never
    # to raise).
    monkeypatch.delenv("PQCHECK_CRYPTO_ANALYZER", raising=False)
    # Patch the name as bound in the module under test (from importlib.resources
    # import files), not the original importlib.resources.files.
    monkeypatch.setattr(gmd, "files", _raise_type_error)
    assert gmd._locate_binary() is None


def _raise_type_error(*_: object, **__: object) -> None:
    raise TypeError("namespace package has no __file__")


def test_detect_go_module_fallback_skips_nested_module_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gmd, "_locate_binary", lambda: None)
    _write_module(tmp_path)
    (tmp_path / "root.go").write_text(_MD5_SRC, encoding="utf-8")
    nested = tmp_path / "sub"
    nested.mkdir()
    _write_module(nested, module="example.com/m/sub")
    (nested / "n.go").write_text(
        'package sub\nimport "crypto/sha1"\nfunc F() { sha1.New() }\n', encoding="utf-8"
    )

    algorithms = {f.algorithm for f in detect_go_module(tmp_path)}

    assert "MD5" in algorithms
    assert "SHA-1" not in algorithms  # nested module is dispatched on its own


# _hardened_env and _set_memory_limit are the Python half of the hostile-input
# security envelope (the analyzer runs over attacker-controlled code). The Go
# side has equivalent coverage in analyzer_envelope_test.go; these guard the
# bridge side against a silent regression that re-enables a lever or breaks the
# rlimit clamp.


def test_hardened_env_pins_levers_over_hostile_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GOPROXY", "https://evil.example")
    monkeypatch.setenv("GOFLAGS", "-mod=mod")
    monkeypatch.setenv("GOTOOLCHAIN", "auto")
    monkeypatch.setenv("TMPDIR", "/host/tmp")

    env = gmd._hardened_env("/scratch/owned")

    assert env["GOTOOLCHAIN"] == "local"
    assert env["CGO_ENABLED"] == "0"
    assert env["GOFLAGS"] == "-mod=readonly"
    assert env["GOWORK"] == "off"
    assert env["GOPROXY"] == "off"
    assert env["GOSUMDB"] == "off"
    assert env["GOENV"] == "off"
    assert env["GOMEMLIMIT"] == gmd._GOMEMLIMIT
    # TMPDIR is the bridge's owned scratch, never the host's.
    assert env["TMPDIR"] == "/scratch/owned"


def test_hardened_env_does_not_inherit_unlisted_host_vars(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GODEBUG", "x509sha1=1")
    monkeypatch.setenv("GOPRIVATE", "evil.example/*")
    monkeypatch.setenv("GOINSECURE", "evil.example/*")
    monkeypatch.setenv("SECRET_TOKEN", "leak-me")

    env = gmd._hardened_env("/scratch/owned")

    for leaked in ("GODEBUG", "GOPRIVATE", "GOINSECURE", "SECRET_TOKEN"):
        assert leaked not in env
    allowed = {
        "PATH", "HOME", "TMPDIR", "GOTOOLCHAIN", "CGO_ENABLED", "GOFLAGS",
        "GOWORK", "GOPROXY", "GOSUMDB", "GOENV", "GOMEMLIMIT",
    }
    assert set(env) <= allowed


@pytest.mark.skipif(sys.platform == "win32", reason="resource/preexec is POSIX-only")
def test_set_memory_limit_clamps_soft_to_finite_hard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[int, tuple[int, int]]] = []
    hard = gmd._MEMORY_LIMIT_BYTES // 2  # finite, below the desired target
    monkeypatch.setattr(
        gmd.resource, "getrlimit", lambda _which: (gmd.resource.RLIM_INFINITY, hard)
    )
    monkeypatch.setattr(
        gmd.resource, "setrlimit", lambda which, limits: captured.append((which, limits))
    )

    gmd._set_memory_limit()

    # Soft clamped down to the hard cap; the hard cap itself is left untouched.
    assert captured == [(gmd.resource.RLIMIT_DATA, (hard, hard))]


@pytest.mark.skipif(sys.platform == "win32", reason="resource/preexec is POSIX-only")
def test_set_memory_limit_keeps_target_when_hard_is_infinite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[tuple[int, tuple[int, int]]] = []
    inf = gmd.resource.RLIM_INFINITY
    monkeypatch.setattr(gmd.resource, "getrlimit", lambda _which: (inf, inf))
    monkeypatch.setattr(
        gmd.resource, "setrlimit", lambda which, limits: captured.append((which, limits))
    )

    gmd._set_memory_limit()

    assert captured == [(gmd.resource.RLIMIT_DATA, (gmd._MEMORY_LIMIT_BYTES, inf))]


@pytest.mark.skipif(sys.platform == "win32", reason="resource/preexec is POSIX-only")
def test_set_memory_limit_swallows_rlimit_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*_args: object) -> None:
        raise OSError("rlimit rejected")

    monkeypatch.setattr(gmd.resource, "getrlimit", boom)

    gmd._set_memory_limit()  # tolerated: the spawn must proceed, not abort
