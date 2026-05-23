from pqcheck.detectors.algorithms import AlgorithmHit, lookup_cipher_mode, lookup_python_symbol
from pqcheck.models import AlgorithmFamily


def test_hashlib_md5_resolves() -> None:
    hit = lookup_python_symbol("hashlib.md5")
    assert hit == AlgorithmHit(canonical="MD5", family=AlgorithmFamily.HASH)


def test_hashlib_sha1_resolves() -> None:
    hit = lookup_python_symbol("hashlib.sha1")
    assert hit == AlgorithmHit(canonical="SHA-1", family=AlgorithmFamily.HASH)


def test_cryptography_hashes_md5_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.hashes.MD5"
    )
    assert hit == AlgorithmHit(canonical="MD5", family=AlgorithmFamily.HASH)


def test_cryptography_rsa_generate_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"
    )
    assert hit == AlgorithmHit(
        canonical="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    )


def test_cryptography_ec_generate_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key"
    )
    assert hit == AlgorithmHit(
        canonical="ECDSA", family=AlgorithmFamily.SIGNATURE
    )


def test_cryptography_cipher_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.ciphers.Cipher"
    )
    assert hit is not None
    assert hit.canonical == "CIPHER-WRAPPER"
    assert hit.family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_cryptography_algorithms_aes_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.ciphers.algorithms.AES"
    )
    assert hit == AlgorithmHit(
        canonical="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER
    )


def test_pycryptodome_aes_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Cipher.AES.new")
    assert hit == AlgorithmHit(
        canonical="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER
    )


def test_pycryptodome_rsa_generate_resolves() -> None:
    hit = lookup_python_symbol("Crypto.PublicKey.RSA.generate")
    assert hit == AlgorithmHit(
        canonical="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    )


def test_pycryptodome_hash_md5_new_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Hash.MD5.new")
    assert hit == AlgorithmHit(canonical="MD5", family=AlgorithmFamily.HASH)


def test_unknown_symbol_returns_none() -> None:
    assert lookup_python_symbol("os.getcwd") is None
    assert lookup_python_symbol("") is None
    assert lookup_python_symbol("nothing.at.all") is None


def test_lookup_cipher_mode_cryptography_gcm() -> None:
    assert (
        lookup_cipher_mode("cryptography.hazmat.primitives.ciphers.modes.GCM")
        == "GCM"
    )


def test_lookup_cipher_mode_pycryptodome_mode_attr() -> None:
    assert lookup_cipher_mode("Crypto.Cipher.AES.MODE_GCM") == "GCM"


def test_lookup_cipher_mode_unknown_returns_none() -> None:
    assert lookup_cipher_mode("nothing.relevant") is None
    assert lookup_cipher_mode("") is None
