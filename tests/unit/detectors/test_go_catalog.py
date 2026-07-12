from pqcheck.detectors.algorithms import (
    emittable_canonicals,
    load_go_catalog,
    lookup_go_symbol,
)
from pqcheck.models import AlgorithmFamily

_HASH = AlgorithmFamily.HASH
_SYM = AlgorithmFamily.SYMMETRIC_CIPHER
_AEAD = AlgorithmFamily.AEAD
_ASYM = AlgorithmFamily.ASYMMETRIC_ENCRYPTION
_SIG = AlgorithmFamily.SIGNATURE
_KA = AlgorithmFamily.KEY_AGREEMENT
_KEM = AlgorithmFamily.KEM
_EC = AlgorithmFamily.ELLIPTIC_CURVE
_RNG = AlgorithmFamily.RNG

# Frozen snapshot of the per-symbol crypto knowledge that lived in the deleted
# `_GO_SYMBOLS` dict (algorithms.py, before commit e47eb8a moved it into
# crypto-catalog.json). The catalog is now the single source of truth, so this
# guards the migration: a future catalog edit that drops a symbol or changes its
# canonical/family/curve breaks the symbols the original detector covered. Each
# tuple is (qualified_symbol, canonical, family, curve).
_HISTORICAL_GO_SYMBOLS: tuple[tuple[str, str, AlgorithmFamily, str | None], ...] = (
    ("crypto/md5.New", "MD5", _HASH, None),
    ("crypto/md5.Sum", "MD5", _HASH, None),
    ("crypto/sha1.New", "SHA-1", _HASH, None),
    ("crypto/sha1.Sum", "SHA-1", _HASH, None),
    ("crypto/sha256.New", "SHA-256", _HASH, None),
    ("crypto/sha256.Sum256", "SHA-256", _HASH, None),
    ("crypto/sha256.New224", "SHA-224", _HASH, None),
    ("crypto/sha256.Sum224", "SHA-224", _HASH, None),
    ("crypto/sha512.New", "SHA-512", _HASH, None),
    ("crypto/sha512.Sum512", "SHA-512", _HASH, None),
    ("crypto/sha512.New384", "SHA-384", _HASH, None),
    ("crypto/sha512.Sum384", "SHA-384", _HASH, None),
    ("crypto/sha3.New256", "SHA3-256", _HASH, None),
    ("crypto/sha3.New384", "SHA3-384", _HASH, None),
    ("crypto/sha3.New512", "SHA3-512", _HASH, None),
    ("crypto/sha3.Sum256", "SHA3-256", _HASH, None),
    ("crypto/sha3.Sum384", "SHA3-384", _HASH, None),
    ("crypto/sha3.Sum512", "SHA3-512", _HASH, None),
    ("golang.org/x/crypto/sha3.New256", "SHA3-256", _HASH, None),
    ("golang.org/x/crypto/sha3.New384", "SHA3-384", _HASH, None),
    ("golang.org/x/crypto/sha3.New512", "SHA3-512", _HASH, None),
    ("golang.org/x/crypto/sha3.Sum256", "SHA3-256", _HASH, None),
    ("golang.org/x/crypto/sha3.Sum384", "SHA3-384", _HASH, None),
    ("golang.org/x/crypto/sha3.Sum512", "SHA3-512", _HASH, None),
    ("golang.org/x/crypto/blake2b.New256", "BLAKE2B", _HASH, None),
    ("golang.org/x/crypto/blake2b.New384", "BLAKE2B", _HASH, None),
    ("golang.org/x/crypto/blake2b.New512", "BLAKE2B", _HASH, None),
    ("golang.org/x/crypto/blake2b.New", "BLAKE2B", _HASH, None),
    ("golang.org/x/crypto/blake2s.New256", "BLAKE2S", _HASH, None),
    ("golang.org/x/crypto/blake2s.New128", "BLAKE2S", _HASH, None),
    ("crypto/aes.NewCipher", "AES", _SYM, None),
    ("crypto/des.NewCipher", "DES", _SYM, None),
    ("crypto/des.NewTripleDESCipher", "3DES", _SYM, None),
    ("crypto/rc4.NewCipher", "RC4", _SYM, None),
    ("golang.org/x/crypto/chacha20.NewUnauthenticatedCipher", "CHACHA20", _SYM, None),
    ("golang.org/x/crypto/chacha20poly1305.New", "CHACHA20", _AEAD, None),
    ("golang.org/x/crypto/chacha20poly1305.NewX", "CHACHA20", _AEAD, None),
    ("crypto/rsa.GenerateKey", "RSA", _ASYM, None),
    ("crypto/ecdsa.GenerateKey", "ECDSA", _SIG, None),
    ("crypto/dsa.GenerateParameters", "DSA", _SIG, None),
    ("crypto/dsa.GenerateKey", "DSA", _SIG, None),
    ("crypto/ed25519.GenerateKey", "EdDSA", _SIG, "Ed25519"),
    ("crypto/ecdh.X25519", "X25519", _KA, None),
    ("crypto/ecdh.P256", "ECDH", _KA, "P-256"),
    ("crypto/ecdh.P384", "ECDH", _KA, "P-384"),
    ("crypto/ecdh.P521", "ECDH", _KA, "P-521"),
    ("crypto/mlkem.GenerateKey768", "ML-KEM", _KEM, None),
    ("crypto/mlkem.GenerateKey1024", "ML-KEM", _KEM, None),
)


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


def test_lookup_mlkem_carries_parameter_set() -> None:
    # The parameter set is baked into the catalog entry, same as EdDSA's
    # curve — the policy's approved ML-KEM rule matches on parameter-sets,
    # so without it the finding falls to default/medium instead of
    # approved/info (issue #217).
    hit768 = lookup_go_symbol("crypto/mlkem.GenerateKey768")
    hit1024 = lookup_go_symbol("crypto/mlkem.GenerateKey1024")
    assert hit768 is not None and hit768.key_size == 768
    assert hit1024 is not None and hit1024.key_size == 1024


def test_lookup_elliptic_p256_is_ambiguous_ecc_family() -> None:
    # Neither ECDSA nor ECDH: elliptic.PXXX() returns a curve object usable
    # for both, so it gets its own family rather than guessing.
    hit = lookup_go_symbol("crypto/elliptic.P256")
    assert hit is not None
    assert hit.canonical == "ECC"
    assert hit.family is _EC
    assert hit.curve == "P-256"


def test_lookup_elliptic_p384_and_p521_carry_curve() -> None:
    hit384 = lookup_go_symbol("crypto/elliptic.P384")
    hit521 = lookup_go_symbol("crypto/elliptic.P521")
    assert hit384 is not None and hit384.curve == "P-384"
    assert hit521 is not None and hit521.curve == "P-521"


def test_lookup_curve25519_symbols_are_x25519() -> None:
    x25519 = lookup_go_symbol("golang.org/x/crypto/curve25519.X25519")
    scalar = lookup_go_symbol("golang.org/x/crypto/curve25519.ScalarBaseMult")
    assert x25519 is not None and x25519.canonical == "X25519"
    assert x25519.family is _KA
    assert scalar is not None and scalar.canonical == "X25519"


def test_lookup_crypto_rand_symbols_are_csprng() -> None:
    for symbol in ("crypto/rand.Read", "crypto/rand.Int", "crypto/rand.Prime"):
        hit = lookup_go_symbol(symbol)
        assert hit is not None, symbol
        assert hit.canonical == "CSPRNG"
        assert hit.family is _RNG


def test_lookup_xcrypto_chacha20poly1305() -> None:
    hit = lookup_go_symbol("golang.org/x/crypto/chacha20poly1305.New")
    assert hit is not None
    assert hit.canonical == "CHACHA20"
    assert hit.family is AlgorithmFamily.AEAD


def test_unknown_symbol_returns_none() -> None:
    assert lookup_go_symbol("crypto/rsa.Unknown") is None
    assert lookup_go_symbol("fmt.Println") is None


def test_catalog_preserves_every_migrated_go_symbol() -> None:
    cat = load_go_catalog()
    for symbol, canonical, family, curve in _HISTORICAL_GO_SYMBOLS:
        hit = cat.get(symbol)
        assert hit is not None, f"{symbol} was dropped from the catalog"
        assert hit.canonical == canonical, f"{symbol}: canonical drifted"
        assert hit.family is family, f"{symbol}: family drifted"
        assert hit.curve == curve, f"{symbol}: curve drifted"


def test_go_canonicals_are_emittable() -> None:
    canonicals = emittable_canonicals()
    assert {"RSA", "ECDSA", "ECDH", "X25519", "EdDSA", "DSA", "ML-KEM",
            "AES", "DES", "3DES", "RC4", "CHACHA20",
            "MD5", "SHA-1", "SHA-256", "SHA3-256", "BLAKE2B",
            "ECC", "CSPRNG"} <= canonicals
