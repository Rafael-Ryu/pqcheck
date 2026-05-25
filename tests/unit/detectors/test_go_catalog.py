from pqcheck.detectors.algorithms import (
    emittable_canonicals,
    load_go_catalog,
    lookup_go_symbol,
)
from pqcheck.models import AlgorithmFamily


def test_load_go_catalog_parses_entries() -> None:
    cat = load_go_catalog()
    rsa = cat["crypto/rsa.GenerateKey"]
    assert rsa.canonical == "RSA"
    assert rsa.family is AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    assert rsa.curve is None
    ecdh = cat["crypto/ecdh.P256"]
    assert ecdh.canonical == "ECDH"
    assert ecdh.curve == "P-256"


def test_lookup_known_hash() -> None:
    hit = lookup_go_symbol("crypto/sha256.Sum256")
    assert hit is not None
    assert hit.canonical == "SHA-256"
    assert hit.family is AlgorithmFamily.HASH


def test_lookup_rsa_keygen() -> None:
    hit = lookup_go_symbol("crypto/rsa.GenerateKey")
    assert hit is not None
    assert hit.canonical == "RSA"
    assert hit.family is AlgorithmFamily.ASYMMETRIC_ENCRYPTION


def test_lookup_ecdh_curve_baked_into_hit() -> None:
    hit = lookup_go_symbol("crypto/ecdh.P256")
    assert hit is not None
    assert hit.canonical == "ECDH"
    assert hit.curve == "P-256"


def test_lookup_x25519_is_its_own_canonical() -> None:
    hit = lookup_go_symbol("crypto/ecdh.X25519")
    assert hit is not None
    assert hit.canonical == "X25519"


def test_lookup_ed25519_carries_curve() -> None:
    hit = lookup_go_symbol("crypto/ed25519.GenerateKey")
    assert hit is not None
    assert hit.canonical == "EdDSA"
    assert hit.curve == "Ed25519"


def test_lookup_mlkem_is_kem() -> None:
    hit = lookup_go_symbol("crypto/mlkem.GenerateKey768")
    assert hit is not None
    assert hit.canonical == "ML-KEM"
    assert hit.family is AlgorithmFamily.KEM


def test_lookup_xcrypto_chacha20poly1305() -> None:
    hit = lookup_go_symbol("golang.org/x/crypto/chacha20poly1305.New")
    assert hit is not None
    assert hit.canonical == "CHACHA20"
    assert hit.family is AlgorithmFamily.AEAD


def test_unknown_symbol_returns_none() -> None:
    assert lookup_go_symbol("crypto/rsa.Unknown") is None
    assert lookup_go_symbol("fmt.Println") is None


def test_go_canonicals_are_emittable() -> None:
    canonicals = emittable_canonicals()
    assert {"RSA", "ECDSA", "ECDH", "X25519", "EdDSA", "DSA", "ML-KEM",
            "AES", "DES", "3DES", "RC4", "CHACHA20",
            "MD5", "SHA-1", "SHA-256", "SHA3-256", "BLAKE2B"} <= canonicals
