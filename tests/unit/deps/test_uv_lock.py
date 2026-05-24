from pathlib import Path

from pqcheck.deps.uv_lock import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "uv.lock"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_basic_uv_lock(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1

[[package]]
name = "cryptography"
version = "43.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pyopenssl"
version = "24.2.1"
source = { registry = "https://pypi.org/simple" }
""")
    deps = parse(f)
    by_name = {d.name: d for d in deps}
    assert by_name["cryptography"].version == "43.0.0"
    assert by_name["cryptography"].purl == "pkg:pypi/cryptography@43.0.0"
    assert by_name["pyopenssl"].version == "24.2.1"
    assert all(d.ecosystem == "pypi" for d in deps)
    assert all(d.declared_in == f for d in deps)


def test_parse_populates_introduces_algorithms(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "pycryptodome"
version = "3.20.0"
""")
    deps = parse(f)
    assert "RSA" in deps[0].introduces_algorithms
    assert "DES" in deps[0].introduces_algorithms


def test_parse_skips_package_without_name(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
version = "1.0.0"
[[package]]
name = "cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["cryptography"]


def test_parse_accepts_package_without_version(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "my-workspace-member"
source = { workspace = true }
""")
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].name == "my-workspace-member"
    assert deps[0].version is None
    assert deps[0].purl == "pkg:pypi/my-workspace-member"


def test_parse_deduplicates_name_version_pairs(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "cryptography"
version = "43.0.0"
[[package]]
name = "cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert len(deps) == 1


def test_parse_keeps_distinct_versions_of_same_package(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "cryptography"
version = "43.0.0"
[[package]]
name = "cryptography"
version = "44.0.0"
""")
    deps = sorted(parse(f), key=lambda d: d.version or "")
    assert [d.version for d in deps] == ["43.0.0", "44.0.0"]


def test_parse_invalid_toml_returns_empty_list(tmp_path: Path) -> None:
    f = _write(tmp_path, "this is not [valid TOML\n")
    assert parse(f) == []


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "missing.lock") == []


def test_parse_without_package_array(tmp_path: Path) -> None:
    f = _write(tmp_path, "version = 1\n")
    assert parse(f) == []


def test_parse_lowercases_purl_name(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "Cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert deps[0].purl == "pkg:pypi/cryptography@43.0.0"
    # We preserve the originally-declared name on the model but normalize
    # the PURL — matches PyPI's PEP 503 normalization.
    assert deps[0].name == "Cryptography"
