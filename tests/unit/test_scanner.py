from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

import pqcheck.scanner as scanner_mod
from pqcheck import __version__
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation
from pqcheck.policy.loader import load_default_policy
from pqcheck.scanner import scan
from tests.fixtures import keymaterial


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return tmp_path


def test_scan_detects_python_crypto_end_to_end(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"app.py": "import hashlib\nhashlib.md5(b'x')\n"})
    result = scan(root)
    assert result.target == root.resolve()
    assert result.scanner_version == __version__
    assert [f.algorithm for f in result.findings] == ["MD5"]
    assert result.policy_decisions == () and result.policy_id is None


def test_scan_parses_manifests_into_dependencies(tmp_path: Path) -> None:
    root = _tree(tmp_path, {
        "pyproject.toml": '[project]\nname = "demo"\nversion = "0"\n'
        'dependencies = ["pycryptodome"]\n',
    })
    result = scan(root)
    assert any(d.name == "pycryptodome" for d in result.dependencies)


def test_scan_with_policy_evaluates_every_finding(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"a.py": "import hashlib\nhashlib.md5(b'x')\nhashlib.sha256(b'x')\n"})
    policy = load_default_policy("cryptoct-default")
    result = scan(root, policy)
    assert len(result.policy_decisions) == len(result.findings) == 2
    assert result.policy_id == f"{policy.metadata.name}-{policy.metadata.version}"


def test_scan_swallows_per_file_detector_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # One hostile file must never abort the scan: the error is surfaced in
    # ScanResult.errors and the remaining files are still processed.
    root = _tree(tmp_path, {"bad.py": "", "good.py": "import hashlib\nhashlib.md5(b'x')\n"})

    def explode_on_bad(path: Path) -> list[CryptoFinding]:
        if path.name == "bad.py":
            raise RuntimeError("boom")
        return [
            CryptoFinding(
                algorithm="MD5", family=AlgorithmFamily.HASH,
                location=SourceLocation(path=path, line=1, column=0),
                evidence="e", detector_id="t",
            )
        ]

    monkeypatch.setattr(scanner_mod, "detect_python_file", explode_on_bad)
    result = scan(root)
    assert [f.algorithm for f in result.findings] == ["MD5"]
    assert any("bad.py" in e and "boom" in e for e in result.errors)


def test_scan_dispatches_go_modules_once_and_loose_files_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _tree(tmp_path, {
        "svc/go.mod": "module example.com/svc\n",
        "svc/main.go": "package main\n",
        "svc/util.go": "package main\n",
        "loose.go": "package loose\n",
    })
    module_calls: list[tuple[Path, Path]] = []
    file_calls: list[Path] = []
    monkeypatch.setattr(
        scanner_mod, "detect_go_module",
        lambda p, *, scan_root: module_calls.append((p, scan_root)) or [],
    )
    monkeypatch.setattr(
        scanner_mod, "detect_go_file",
        lambda p: file_calls.append(p) or [],
    )
    scan(root)
    # scan_root is passed through so the analyzer bridge can reject a go.mod
    # `replace` pointing outside the scanned tree.
    assert module_calls == [((root / "svc").resolve(), root.resolve())]
    assert [p.name for p in file_calls] == ["loose.go"]


def test_scan_findings_are_sorted_for_stable_output(tmp_path: Path) -> None:
    root = _tree(tmp_path, {
        "z.py": "import hashlib\nhashlib.md5(b'x')\n",
        "a.py": "import hashlib\nhashlib.sha1(b'x')\nhashlib.md5(b'x')\n",
    })
    result = scan(root)
    keys = [(str(f.location.path), f.location.line) for f in result.findings]
    assert keys == sorted(keys)


def test_scan_propagates_walker_errors(tmp_path: Path) -> None:
    result = scan(tmp_path / "missing")
    assert result.findings == ()
    assert result.errors


def test_scan_detects_key_material_end_to_end(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    root = _tree(tmp_path, {})
    (root / "server.key").write_bytes(pem)
    result = scan(root)
    assert [f.algorithm for f in result.findings] == ["RSA"]
    assert result.findings[0].material_kind == "private-key"


def test_scan_swallows_per_file_key_material_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _tree(tmp_path, {"a.key": ""})

    def explode(path: Path) -> list[CryptoFinding]:
        raise RuntimeError("boom")

    monkeypatch.setattr(scanner_mod, "detect_key_material_file", explode)
    result = scan(root)
    assert result.findings == ()
    assert any("a.key" in e and "boom" in e for e in result.errors)


def test_scan_reports_malformed_manifests_and_keeps_scanning(tmp_path: Path) -> None:
    # A manifest the scanner saw but could not parse means an incomplete
    # dependency inventory; it must show up in errors rather than vanish into
    # a clean-looking scan. Valid inputs alongside it still get parsed.
    (tmp_path / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"packages": {', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("cryptography==43.0.0\n", encoding="utf-8")
    (tmp_path / "use.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")

    result = scan(tmp_path)

    assert any("pyproject.toml" in e and "ManifestError" in e for e in result.errors)
    assert any("package-lock.json" in e and "ManifestError" in e for e in result.errors)
    assert [d.name for d in result.dependencies] == ["cryptography"]
    assert [f.algorithm for f in result.findings] == ["MD5"]
