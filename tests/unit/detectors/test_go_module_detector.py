import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from pqcheck.detectors import go_module_detector as gmd
from pqcheck.detectors.go_module_detector import (
    claimed_go_files,
    detect_go_module,
    group_go_files_by_module,
)
from pqcheck.models import AlgorithmFamily, QuantumRisk

_MD5_SRC = 'package main\nimport "crypto/md5"\nfunc main() { md5.New() }\n'


def _write_module(root: Path, *, module: str = "example.com/m") -> None:
    (root / "go.mod").write_text(f"module {module}\n\ngo 1.24\n", encoding="utf-8")


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")
    return path


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


def test_locate_binary_uses_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    monkeypatch.setenv("PQCHECK_CRYPTO_ANALYZER", str(binary))
    assert gmd._locate_binary() == binary


def test_locate_binary_env_override_missing_file_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("PQCHECK_CRYPTO_ANALYZER", str(tmp_path / "absent"))
    assert gmd._locate_binary() is None


def test_locate_binary_returns_none_when_unbundled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PQCHECK_CRYPTO_ANALYZER", raising=False)
    assert gmd._locate_binary() is None  # bin/ not packaged before Inc4


def test_sha256_pin_absent_without_generated_constants() -> None:
    # No build-generated _constants.py in the dev tree -> lenient verification.
    assert gmd._CRYPTO_ANALYZER_SHA256 is None


def test_verify_sha256_lenient_when_pin_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", None)
    binary = tmp_path / "bin"
    binary.write_bytes(b"unverified")
    assert gmd._verify_sha256(binary) is True


def test_verify_sha256_matches_pin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(b"binary-bytes")
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", hashlib.sha256(b"binary-bytes").hexdigest())
    assert gmd._verify_sha256(binary) is True


def test_verify_sha256_rejects_mismatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin"
    binary.write_bytes(b"tampered")
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", "0" * 64)
    assert gmd._verify_sha256(binary) is False


def _fake_completed(returncode: int, stdout: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=b"")


def test_run_analyzer_returns_stdout_on_success(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(0, b"[]"))
    assert gmd._run_analyzer(tmp_path, tmp_path / "bin") == "[]"


def test_run_analyzer_timeout_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def raise_timeout(*a: object, **k: object) -> object:
        raise subprocess.TimeoutExpired(cmd="crypto-analyzer", timeout=60)

    monkeypatch.setattr(subprocess, "run", raise_timeout)
    assert gmd._run_analyzer(tmp_path, tmp_path / "bin") is None


def test_run_analyzer_nonzero_exit_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(1, b""))
    assert gmd._run_analyzer(tmp_path, tmp_path / "bin") is None


def test_run_analyzer_oversized_stdout_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    oversized = b"x" * (gmd._MAX_STDOUT_BYTES + 1)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _fake_completed(0, oversized))
    assert gmd._run_analyzer(tmp_path, tmp_path / "bin") is None


def test_run_analyzer_os_error_returns_none(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def raise_oserror(*a: object, **k: object) -> object:
        raise OSError("exec format error")

    monkeypatch.setattr(subprocess, "run", raise_oserror)
    assert gmd._run_analyzer(tmp_path, tmp_path / "bin") is None


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
    findings = gmd._map_findings(_GOLDEN)

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
    assert gmd._map_findings("{not json") == []
    assert gmd._map_findings("") == []


def test_map_findings_non_array_returns_empty() -> None:
    assert gmd._map_findings('{"algorithm": "RSA"}') == []


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
    findings = gmd._map_findings(stdout)
    assert [f.algorithm for f in findings] == ["MD5"]


def test_map_findings_skips_non_dict_items() -> None:
    assert gmd._map_findings('[1, "x", null]') == []  # non-object elements skipped


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
    monkeypatch.setattr(gmd, "_locate_binary", lambda: binary)
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
    monkeypatch.setattr(gmd, "_locate_binary", lambda: binary)
    monkeypatch.setattr(gmd, "_run_analyzer", lambda root, b: _GOLDEN)

    findings = detect_go_module(tmp_path)

    assert [f.algorithm for f in findings] == ["RSA", "AES"]
    assert all(f.detector_id == "go-types" for f in findings)


def test_detect_go_module_trusts_empty_analyzer_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"x")
    monkeypatch.setattr(gmd, "_locate_binary", lambda: binary)
    monkeypatch.setattr(gmd, "_run_analyzer", lambda root, b: "[]")
    _write_module(tmp_path)
    (tmp_path / "m.go").write_text(_MD5_SRC, encoding="utf-8")

    assert detect_go_module(tmp_path) == []  # exit-0 + empty trumps fallback


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
