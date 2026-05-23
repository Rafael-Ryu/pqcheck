from pqcheck.deps.packages import lookup_introduces


def test_lookup_pypi_cryptography_returns_known_algorithms() -> None:
    result = lookup_introduces("pypi", "cryptography")
    assert "RSA" in result
    assert "AES" in result
    assert "SHA-256" in result


def test_lookup_is_case_insensitive_for_name() -> None:
    lower = lookup_introduces("pypi", "cryptography")
    upper = lookup_introduces("pypi", "Cryptography")
    mixed = lookup_introduces("pypi", "CrYpToGrApHy")
    assert lower == upper == mixed


def test_lookup_pypi_pycryptodome_includes_broken_algorithms() -> None:
    result = lookup_introduces("pypi", "pycryptodome")
    assert "MD5" in result
    assert "DES" in result
    assert "RC4" in result


def test_lookup_maven_bouncycastle_returns_algorithms() -> None:
    result = lookup_introduces("maven", "bcprov-jdk18on")
    assert "RSA" in result
    assert "AES" in result


def test_lookup_unknown_package_returns_empty_tuple() -> None:
    result = lookup_introduces("pypi", "nonexistent-package-xyz")
    assert result == ()


def test_lookup_unknown_ecosystem_returns_empty_tuple() -> None:
    result = lookup_introduces("conda", "cryptography")
    assert result == ()


def test_lookup_returns_a_tuple_not_a_list() -> None:
    result = lookup_introduces("pypi", "cryptography")
    assert isinstance(result, tuple)
