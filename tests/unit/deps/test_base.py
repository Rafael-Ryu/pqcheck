from pathlib import Path

from pqcheck.deps.base import (
    MAX_FILE_BYTES,
    extract_pep508_name,
    maven_purl,
    pypi_purl,
    safe_read_bytes,
)


def test_pypi_purl_lowercases_name() -> None:
    assert pypi_purl("Cryptography", "43.0.0") == "pkg:pypi/cryptography@43.0.0"


def test_pypi_purl_without_version() -> None:
    assert pypi_purl("cryptography", None) == "pkg:pypi/cryptography"


def test_maven_purl_preserves_group_id_case() -> None:
    result = maven_purl("org.bouncycastle", "bcprov-jdk18on", "1.78")
    assert result == "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"


def test_maven_purl_without_version() -> None:
    result = maven_purl("org.bouncycastle", "bcprov-jdk18on", None)
    assert result == "pkg:maven/org.bouncycastle/bcprov-jdk18on"


def test_extract_pep508_name_simple() -> None:
    assert extract_pep508_name("cryptography") == "cryptography"


def test_extract_pep508_name_with_version_spec() -> None:
    assert extract_pep508_name("cryptography>=43.0.0") == "cryptography"
    assert extract_pep508_name("cryptography==43.0.0") == "cryptography"
    assert extract_pep508_name("cryptography<2") == "cryptography"
    assert extract_pep508_name("cryptography ~= 43.0") == "cryptography"


def test_extract_pep508_name_with_extras() -> None:
    assert extract_pep508_name("cryptography[ssh]>=43.0.0") == "cryptography"
    assert extract_pep508_name("cryptography[ssh,extra]") == "cryptography"


def test_extract_pep508_name_with_marker() -> None:
    expr = 'cryptography>=43.0.0 ; python_version >= "3.12"'
    assert extract_pep508_name(expr) == "cryptography"


def test_extract_pep508_name_with_underscores_and_dashes() -> None:
    assert extract_pep508_name("typing_extensions") == "typing_extensions"
    assert extract_pep508_name("python-dateutil") == "python-dateutil"
    assert extract_pep508_name("backports.functools_lru_cache") == "backports.functools_lru_cache"


def test_extract_pep508_name_returns_none_for_empty_or_invalid() -> None:
    assert extract_pep508_name("") is None
    assert extract_pep508_name("   ") is None
    assert extract_pep508_name(">=1.0") is None


def test_safe_read_bytes_returns_content_for_small_file(tmp_path: Path) -> None:
    f = tmp_path / "small.txt"
    f.write_bytes(b"hello")
    assert safe_read_bytes(f) == b"hello"


def test_safe_read_bytes_returns_none_for_oversized_file(tmp_path: Path) -> None:
    f = tmp_path / "huge.txt"
    f.write_bytes(b"\x00" * (MAX_FILE_BYTES + 1))
    assert safe_read_bytes(f) is None


def test_safe_read_bytes_returns_none_for_missing_file(tmp_path: Path) -> None:
    assert safe_read_bytes(tmp_path / "does-not-exist") is None


def test_safe_read_bytes_returns_none_for_directory(tmp_path: Path) -> None:
    assert safe_read_bytes(tmp_path) is None
