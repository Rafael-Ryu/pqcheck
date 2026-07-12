from pqcheck.deps.packages import _CATALOG, lookup_introduces
from pqcheck.models import _QUANTUM_MAP


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


def test_lookup_pypi_paramiko_includes_ssh_primitives() -> None:
    result = lookup_introduces("pypi", "paramiko")
    assert "RSA" in result
    assert "ECDSA" in result
    assert "AES" in result


def test_lookup_pypi_pyjwt_includes_signing_primitives() -> None:
    result = lookup_introduces("pypi", "pyjwt")
    assert "RSA" in result
    assert "ECDSA" in result
    # SHA-256/384/512 cover RS256/RS384/RS512 surface.
    assert "SHA-256" in result


def test_lookup_pypi_python_jose_resolves() -> None:
    result = lookup_introduces("pypi", "python-jose")
    assert "RSA" in result
    assert "AES" in result


def test_lookup_maven_jjwt_resolves() -> None:
    result = lookup_introduces("maven", "jjwt")
    assert "RSA" in result
    assert "ECDSA" in result


def test_lookup_maven_nimbus_jose_jwt_resolves() -> None:
    result = lookup_introduces("maven", "nimbus-jose-jwt")
    assert "AES" in result
    assert "RSA" in result


def test_lookup_maven_commons_codec_includes_legacy_hashes() -> None:
    # commons-codec ships Base64 helpers but also MD5/SHA-1 utility
    # APIs that show up as banned in BR-fintech compliance scans.
    result = lookup_introduces("maven", "commons-codec")
    assert "MD5" in result
    assert "SHA-1" in result


def test_lookup_pypi_liboqs_python_surfaces_pqc() -> None:
    result = lookup_introduces("pypi", "liboqs-python")
    assert "ML-KEM" in result
    assert "ML-DSA" in result
    assert "SLH-DSA" in result


def test_lookup_pypi_cryptography_includes_pqc() -> None:
    result = lookup_introduces("pypi", "cryptography")
    assert "ML-KEM" in result
    assert "ML-DSA" in result


def test_lookup_golang_circl_surfaces_pqc_and_classical() -> None:
    result = lookup_introduces("golang", "github.com/cloudflare/circl")
    assert "ML-KEM" in result
    assert "ML-DSA" in result
    assert "ED25519" in result


def test_lookup_golang_mlkem768_resolves() -> None:
    assert lookup_introduces("golang", "filippo.io/mlkem768") == ("ML-KEM",)


def test_lookup_npm_noble_post_quantum_resolves() -> None:
    result = lookup_introduces("npm", "@noble/post-quantum")
    assert "ML-KEM" in result
    assert "SLH-DSA" in result


def test_lookup_maven_bouncycastle_includes_pqc() -> None:
    result = lookup_introduces("maven", "bcprov-jdk18on")
    assert "ML-KEM" in result
    assert "SLH-DSA" in result


def test_every_catalog_canonical_has_a_quantum_risk() -> None:
    # Deps-side counterpart to the detector catalog guard (#45): a package
    # canonical absent from _QUANTUM_MAP would score UNKNOWN risk with no
    # failing test. The two catalogs share the canonical spelling.
    canonicals = {algo for algos in _CATALOG.values() for algo in algos}
    missing = {c for c in canonicals if c.upper() not in _QUANTUM_MAP}
    assert missing == set(), f"deps canonicals missing from _QUANTUM_MAP: {sorted(missing)}"
