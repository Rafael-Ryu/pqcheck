from pqcheck.detectors.algorithms import (
    AlgorithmHit,
    hashlib_new_table,
    lookup_cipher_mode,
    lookup_go_symbol,
    lookup_python_symbol,
    normalize_curve,
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


def test_blake3_resolves() -> None:
    hit = lookup_python_symbol("blake3.blake3")
    assert hit == AlgorithmHit(canonical="BLAKE3", family=AlgorithmFamily.HASH)


# --- lookup_go_symbol ---


def test_lookup_go_symbol_rsa_generate_key() -> None:
    hit = lookup_go_symbol("crypto/rsa.GenerateKey")
    assert hit == AlgorithmHit(canonical="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION)


def test_lookup_go_symbol_ecdsa_generate_key() -> None:
    hit = lookup_go_symbol("crypto/ecdsa.GenerateKey")
    assert hit == AlgorithmHit(canonical="ECDSA", family=AlgorithmFamily.SIGNATURE)


def test_lookup_go_symbol_aes_new_cipher() -> None:
    hit = lookup_go_symbol("crypto/aes.NewCipher")
    assert hit == AlgorithmHit(canonical="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER)


def test_lookup_go_symbol_ecdh_p256_carries_curve() -> None:
    hit = lookup_go_symbol("crypto/ecdh.P256")
    assert hit == AlgorithmHit(
        canonical="ECDH", family=AlgorithmFamily.KEY_AGREEMENT, curve="P-256"
    )


def test_lookup_go_symbol_ed25519_carries_curve() -> None:
    hit = lookup_go_symbol("crypto/ed25519.GenerateKey")
    assert hit == AlgorithmHit(
        canonical="EdDSA", family=AlgorithmFamily.SIGNATURE, curve="Ed25519"
    )


def test_lookup_go_symbol_unknown_returns_none() -> None:
    assert lookup_go_symbol("os.Getenv") is None
    assert lookup_go_symbol("") is None


# --- normalize_curve ---


def test_normalize_curve_p256_short() -> None:
    assert normalize_curve("P256") == "P-256"


def test_normalize_curve_secp256r1() -> None:
    assert normalize_curve("SECP256R1") == "P-256"


def test_normalize_curve_p384() -> None:
    assert normalize_curve("P384") == "P-384"


def test_normalize_curve_already_canonical() -> None:
    assert normalize_curve("P-256") == "P-256"


def test_normalize_curve_unknown_passes_through() -> None:
    # A curve without a policy spelling keeps its original casing.
    assert normalize_curve("X25519") == "X25519"
    assert normalize_curve("brainpoolP256r1") == "brainpoolP256r1"


# --- W2 catalog additions: representative direct lookups ---


def test_hmac_new_resolves() -> None:
    hit = lookup_python_symbol("hmac.new")
    assert hit == AlgorithmHit(canonical="HMAC", family=AlgorithmFamily.MAC)


def test_hashlib_pbkdf2_hmac_resolves() -> None:
    hit = lookup_python_symbol("hashlib.pbkdf2_hmac")
    assert hit == AlgorithmHit(canonical="PBKDF2", family=AlgorithmFamily.KDF)


def test_secrets_token_bytes_resolves() -> None:
    hit = lookup_python_symbol("secrets.token_bytes")
    assert hit == AlgorithmHit(canonical="CSPRNG", family=AlgorithmFamily.RNG)


def test_cryptography_hkdf_resolves() -> None:
    hit = lookup_python_symbol("cryptography.hazmat.primitives.kdf.hkdf.HKDF")
    assert hit == AlgorithmHit(canonical="HKDF", family=AlgorithmFamily.KDF)


def test_cryptography_aesgcm_resolves() -> None:
    hit = lookup_python_symbol("cryptography.hazmat.primitives.ciphers.aead.AESGCM")
    assert hit == AlgorithmHit(canonical="AES-GCM", family=AlgorithmFamily.AEAD)


def test_cryptography_pss_padding_resolves() -> None:
    hit = lookup_python_symbol("cryptography.hazmat.primitives.asymmetric.padding.PSS")
    assert hit == AlgorithmHit(
        canonical="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION, padding="PSS"
    )


def test_cryptography_fernet_resolves() -> None:
    hit = lookup_python_symbol("cryptography.fernet.Fernet")
    assert hit == AlgorithmHit(canonical="FERNET", family=AlgorithmFamily.AEAD)


def test_argon2_password_hasher_resolves() -> None:
    hit = lookup_python_symbol("argon2.PasswordHasher")
    assert hit == AlgorithmHit(canonical="ARGON2", family=AlgorithmFamily.KDF)


def test_bcrypt_hashpw_resolves() -> None:
    hit = lookup_python_symbol("bcrypt.hashpw")
    assert hit == AlgorithmHit(canonical="BCRYPT", family=AlgorithmFamily.KDF)


def test_pycryptodome_pbkdf1_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Protocol.KDF.PBKDF1")
    assert hit == AlgorithmHit(canonical="PBKDF1", family=AlgorithmFamily.KDF)


def test_pycryptodome_pkcs1_15_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Signature.pkcs1_15.new")
    assert hit == AlgorithmHit(
        canonical="RSA", family=AlgorithmFamily.SIGNATURE, padding="PKCS1v15"
    )


def test_pycryptodome_eddsa_new_resolves_without_curve() -> None:
    hit = lookup_python_symbol("Crypto.Signature.eddsa.new")
    assert hit == AlgorithmHit(canonical="EdDSA", family=AlgorithmFamily.SIGNATURE)


def test_pycryptodome_dh_key_agreement_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Protocol.DH.key_agreement")
    assert hit == AlgorithmHit(canonical="DH", family=AlgorithmFamily.KEY_AGREEMENT)


def test_pycryptodome_dss_new_is_not_catalogued() -> None:
    assert lookup_python_symbol("Crypto.Signature.DSS.new") is None


def test_ecc_construct_is_not_catalogued() -> None:
    assert lookup_python_symbol("Crypto.PublicKey.ECC.construct") is None


def test_hashlib_new_table_excludes_kdf_entries() -> None:
    # hashlib.pbkdf2_hmac/scrypt share the hashlib.* prefix but are not
    # digest algorithms hashlib.new() can dispatch to.
    table = hashlib_new_table()
    assert "pbkdf2_hmac" not in table
    assert "scrypt" not in table
