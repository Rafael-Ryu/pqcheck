from pathlib import Path

import pytest

from pqcheck.deps.base import ManifestError
from pqcheck.deps.uv_lock import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "uv.lock"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_utf8_bom_still_parses(tmp_path: Path) -> None:
    # A BOM'd lock (routine Windows tooling output) made tomllib raise, which
    # parse() swallowed into zero deps. utf-8-sig strips the BOM.
    f = tmp_path / "uv.lock"
    f.write_bytes(
        b"\xef\xbb\xbf"
        + b'version = 1\n\n[[package]]\nname = "cryptography"\nversion = "43.0.0"\n'
    )
    deps = parse(f)
    assert {d.name for d in deps} == {"cryptography"}


def test_parse_skips_blank_name_keeps_valid(tmp_path: Path) -> None:
    # A whitespace-only package name survives the empty-name guard but breaks
    # PackageURL. The parser must skip it and still emit the valid sibling —
    # never crash parse() (never-raise contract).
    f = _write(tmp_path, """
version = 1

[[package]]
name = " "
version = "1.0.0"

[[package]]
name = "cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert {d.name for d in deps} == {"cryptography"}


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


def test_parse_invalid_toml_raises_manifest_error(tmp_path: Path) -> None:
    f = _write(tmp_path, "this is not [valid TOML\n")
    with pytest.raises(ManifestError):
        parse(f)


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


def test_parse_skips_virtual_and_editable_workspace_root(tmp_path: Path) -> None:
    # The project's own workspace root shows up as a [[package]] entry with
    # source.virtual or source.editable — not a real dependency.
    f = _write(tmp_path, """
version = 1
[[package]]
name = "pqcheck"
version = "0.0.1"
source = { editable = "." }

[[package]]
name = "some-virtual-root"
source = { virtual = "." }

[[package]]
name = "cryptography"
version = "43.0.0"
source = { registry = "https://pypi.org/simple" }
""")
    deps = parse(f)
    assert {d.name for d in deps} == {"cryptography"}


def test_parse_deeply_nested_toml_raises_manifest_error(tmp_path: Path) -> None:
    # Nested arrays parse recursively; a hostile lock can blow the stack. The
    # RecursionError surfaces as a ManifestError the scan records.
    f = _write(tmp_path, "a = " + "[" * 3000 + "]" * 3000 + "\n")
    with pytest.raises(ManifestError):
        parse(f)
