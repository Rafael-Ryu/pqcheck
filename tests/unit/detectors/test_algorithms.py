from pqcheck.detectors.algorithms import (
    AlgorithmHit,
    lookup_aead_mode,
    lookup_cipher_mode,
    lookup_python_symbol,
    lookup_rsa_padding,
)
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


def test_pycryptodome_sha3_256_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Hash.SHA3_256.new")
    assert hit == AlgorithmHit(canonical="SHA3-256", family=AlgorithmFamily.HASH)


def test_pycryptodome_blake2b_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Hash.BLAKE2b.new")
    assert hit == AlgorithmHit(canonical="BLAKE2B", family=AlgorithmFamily.HASH)


def test_hmac_resolves_as_mac_family() -> None:
    hit = lookup_python_symbol("cryptography.hazmat.primitives.hmac.HMAC")
    assert hit == AlgorithmHit(canonical="HMAC", family=AlgorithmFamily.MAC)


def test_pbkdf2hmac_resolves_as_kdf_family() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC"
    )
    assert hit == AlgorithmHit(canonical="PBKDF2", family=AlgorithmFamily.KDF)


def test_chacha20poly1305_resolves_as_aead() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305"
    )
    assert hit == AlgorithmHit(
        canonical="CHACHA20-POLY1305", family=AlgorithmFamily.AEAD
    )


def test_aesgcm_aead_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.ciphers.aead.AESGCM"
    )
    assert hit == AlgorithmHit(canonical="AES", family=AlgorithmFamily.AEAD)


def test_lookup_aead_mode_aesgcm() -> None:
    assert lookup_aead_mode(
        "cryptography.hazmat.primitives.ciphers.aead.AESGCM"
    ) == "GCM"


def test_lookup_aead_mode_aesccm() -> None:
    assert lookup_aead_mode(
        "cryptography.hazmat.primitives.ciphers.aead.AESCCM"
    ) == "CCM"


def test_lookup_aead_mode_unknown_returns_none() -> None:
    assert lookup_aead_mode("nothing.relevant") is None


def test_lookup_rsa_padding_oaep() -> None:
    result = lookup_rsa_padding(
        "cryptography.hazmat.primitives.asymmetric.padding.OAEP"
    )
    assert result == ("OAEP", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)


def test_lookup_rsa_padding_pss_is_signature() -> None:
    result = lookup_rsa_padding(
        "cryptography.hazmat.primitives.asymmetric.padding.PSS"
    )
    assert result == ("PSS", AlgorithmFamily.SIGNATURE)


def test_lookup_rsa_padding_pkcs1v15() -> None:
    result = lookup_rsa_padding(
        "cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15"
    )
    assert result == ("PKCS1v15", AlgorithmFamily.ASYMMETRIC_ENCRYPTION)


def test_lookup_rsa_padding_unknown_returns_none() -> None:
    assert lookup_rsa_padding("nothing.relevant") is None
