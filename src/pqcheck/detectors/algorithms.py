"""Static catalog mapping language-level symbols to canonical algorithms.

Python-specific lookups for v0.1. Go and Java detectors extend the
catalog with their own lookup functions; canonical names are shared
across languages so downstream policy rules apply uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcheck.models import AlgorithmFamily


@dataclass(frozen=True, slots=True)
class AlgorithmHit:
    canonical: str
    family: AlgorithmFamily
    # Implicit curve for symbols that encode it in the class name rather than a
    # call argument (Ed25519/Ed448). None means "extract from the call, if any".
    curve: str | None = None


_HASH = AlgorithmFamily.HASH
_ASYM = AlgorithmFamily.ASYMMETRIC_ENCRYPTION
_SIG = AlgorithmFamily.SIGNATURE
_KA = AlgorithmFamily.KEY_AGREEMENT
_SYM = AlgorithmFamily.SYMMETRIC_CIPHER
_KEM = AlgorithmFamily.KEM
_AEAD = AlgorithmFamily.AEAD


# Fully-qualified callee name → AlgorithmHit.
# Canonical names are the exact policy §2/§3 spelling so findings match policy
# rules directly. That is usually uppercase + hyphenated (RSA, SHA-256, 3DES)
# but not always — EdDSA is mixed-case. Never assume canonicals are all-caps;
# compare case-insensitively, as CryptoFinding.quantum_risk does.
_PYTHON_SYMBOLS: dict[str, AlgorithmHit] = {
    # ---- hashlib (stdlib) ----
    "hashlib.md5": AlgorithmHit("MD5", _HASH),
    "hashlib.sha1": AlgorithmHit("SHA-1", _HASH),
    "hashlib.sha224": AlgorithmHit("SHA-224", _HASH),
    "hashlib.sha256": AlgorithmHit("SHA-256", _HASH),
    "hashlib.sha384": AlgorithmHit("SHA-384", _HASH),
    "hashlib.sha512": AlgorithmHit("SHA-512", _HASH),
    "hashlib.sha3_256": AlgorithmHit("SHA3-256", _HASH),
    "hashlib.sha3_384": AlgorithmHit("SHA3-384", _HASH),
    "hashlib.sha3_512": AlgorithmHit("SHA3-512", _HASH),
    "hashlib.blake2b": AlgorithmHit("BLAKE2B", _HASH),
    "hashlib.blake2s": AlgorithmHit("BLAKE2S", _HASH),
    # ---- cryptography.hazmat.primitives.hashes ----
    "cryptography.hazmat.primitives.hashes.MD5": AlgorithmHit("MD5", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA1": AlgorithmHit("SHA-1", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA224": AlgorithmHit("SHA-224", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA256": AlgorithmHit("SHA-256", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA384": AlgorithmHit("SHA-384", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA512": AlgorithmHit("SHA-512", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA3_256": AlgorithmHit("SHA3-256", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA3_384": AlgorithmHit("SHA3-384", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA3_512": AlgorithmHit("SHA3-512", _HASH),
    "cryptography.hazmat.primitives.hashes.BLAKE2b": AlgorithmHit("BLAKE2B", _HASH),
    "cryptography.hazmat.primitives.hashes.BLAKE2s": AlgorithmHit("BLAKE2S", _HASH),
    # ---- cryptography asymmetric keygens ----
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key":
        AlgorithmHit("RSA", _ASYM),
    "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key":
        AlgorithmHit("DSA", _SIG),
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key":
        AlgorithmHit("ECDSA", _SIG),
    # ec keygen can't reveal sign-vs-exchange use, so it stays ECDSA above.
    # Standalone NIST-curve ECDH surfaces here instead: ec.ECDH() is the marker
    # passed to key.exchange(), detectable at the call site without dataflow.
    "cryptography.hazmat.primitives.asymmetric.ec.ECDH": AlgorithmHit("ECDH", _KA),
    "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters": AlgorithmHit("DH", _KA),
    # EdDSA carries its curve so findings match the policy rule
    # `algorithm: EdDSA, curves: [Ed25519, Ed448]` (02 §3), the same shape
    # ECDSA already uses.
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate":
        AlgorithmHit("EdDSA", _SIG, curve="Ed25519"),
    "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate":
        AlgorithmHit("EdDSA", _SIG, curve="Ed448"),
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate":
        AlgorithmHit("X25519", _KA),
    "cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.generate":
        AlgorithmHit("X448", _KA),
    # ---- cryptography ciphers wrapper + algorithms + modes ----
    # The Cipher(...) wrapper is detected as a marker so the visitor can
    # walk its args to extract the concrete algorithm + mode.
    "cryptography.hazmat.primitives.ciphers.Cipher": AlgorithmHit("CIPHER-WRAPPER", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.AES": AlgorithmHit("AES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.AES128": AlgorithmHit("AES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.AES256": AlgorithmHit("AES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": AlgorithmHit("3DES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.ARC4": AlgorithmHit("RC4", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20": AlgorithmHit("CHACHA20", _SYM),
    # ---- pycryptodome ----
    "Crypto.Hash.MD5.new": AlgorithmHit("MD5", _HASH),
    "Crypto.Hash.SHA1.new": AlgorithmHit("SHA-1", _HASH),
    "Crypto.Hash.SHA256.new": AlgorithmHit("SHA-256", _HASH),
    "Crypto.Hash.SHA384.new": AlgorithmHit("SHA-384", _HASH),
    "Crypto.Hash.SHA512.new": AlgorithmHit("SHA-512", _HASH),
    "Crypto.Hash.SHA3_256.new": AlgorithmHit("SHA3-256", _HASH),
    "Crypto.Hash.SHA3_384.new": AlgorithmHit("SHA3-384", _HASH),
    "Crypto.Hash.SHA3_512.new": AlgorithmHit("SHA3-512", _HASH),
    "Crypto.Hash.BLAKE2b.new": AlgorithmHit("BLAKE2B", _HASH),
    "Crypto.Hash.BLAKE2s.new": AlgorithmHit("BLAKE2S", _HASH),
    "Crypto.Cipher.AES.new": AlgorithmHit("AES", _SYM),
    "Crypto.Cipher.DES.new": AlgorithmHit("DES", _SYM),
    "Crypto.Cipher.DES3.new": AlgorithmHit("3DES", _SYM),
    "Crypto.Cipher.ARC4.new": AlgorithmHit("RC4", _SYM),
    "Crypto.Cipher.ChaCha20.new": AlgorithmHit("CHACHA20", _SYM),
    "Crypto.PublicKey.RSA.generate": AlgorithmHit("RSA", _ASYM),
    "Crypto.PublicKey.DSA.generate": AlgorithmHit("DSA", _SIG),
    "Crypto.PublicKey.ECC.generate": AlgorithmHit("ECDSA", _SIG),
}


# Fully-qualified Go callee (<import-path>.<Func>) -> AlgorithmHit. Canonical
# names match the policy spelling and are shared with the Python catalog so
# downstream policy rules apply uniformly across languages. Package name is
# the import-path's last segment (the std convention for every package here).
_GO_SYMBOLS: dict[str, AlgorithmHit] = {
    # ---- hashes (stdlib) ----
    "crypto/md5.New": AlgorithmHit("MD5", _HASH),
    "crypto/md5.Sum": AlgorithmHit("MD5", _HASH),
    "crypto/sha1.New": AlgorithmHit("SHA-1", _HASH),
    "crypto/sha1.Sum": AlgorithmHit("SHA-1", _HASH),
    "crypto/sha256.New": AlgorithmHit("SHA-256", _HASH),
    "crypto/sha256.Sum256": AlgorithmHit("SHA-256", _HASH),
    "crypto/sha256.New224": AlgorithmHit("SHA-224", _HASH),
    "crypto/sha256.Sum224": AlgorithmHit("SHA-224", _HASH),
    "crypto/sha512.New": AlgorithmHit("SHA-512", _HASH),
    "crypto/sha512.Sum512": AlgorithmHit("SHA-512", _HASH),
    "crypto/sha512.New384": AlgorithmHit("SHA-384", _HASH),
    "crypto/sha512.Sum384": AlgorithmHit("SHA-384", _HASH),
    "crypto/sha3.New256": AlgorithmHit("SHA3-256", _HASH),
    "crypto/sha3.New384": AlgorithmHit("SHA3-384", _HASH),
    "crypto/sha3.New512": AlgorithmHit("SHA3-512", _HASH),
    "crypto/sha3.Sum256": AlgorithmHit("SHA3-256", _HASH),
    "crypto/sha3.Sum384": AlgorithmHit("SHA3-384", _HASH),
    "crypto/sha3.Sum512": AlgorithmHit("SHA3-512", _HASH),
    "golang.org/x/crypto/sha3.New256": AlgorithmHit("SHA3-256", _HASH),
    "golang.org/x/crypto/sha3.New384": AlgorithmHit("SHA3-384", _HASH),
    "golang.org/x/crypto/sha3.New512": AlgorithmHit("SHA3-512", _HASH),
    "golang.org/x/crypto/sha3.Sum256": AlgorithmHit("SHA3-256", _HASH),
    "golang.org/x/crypto/sha3.Sum384": AlgorithmHit("SHA3-384", _HASH),
    "golang.org/x/crypto/sha3.Sum512": AlgorithmHit("SHA3-512", _HASH),
    "golang.org/x/crypto/blake2b.New256": AlgorithmHit("BLAKE2B", _HASH),
    "golang.org/x/crypto/blake2b.New384": AlgorithmHit("BLAKE2B", _HASH),
    "golang.org/x/crypto/blake2b.New512": AlgorithmHit("BLAKE2B", _HASH),
    "golang.org/x/crypto/blake2b.New": AlgorithmHit("BLAKE2B", _HASH),
    "golang.org/x/crypto/blake2s.New256": AlgorithmHit("BLAKE2S", _HASH),
    "golang.org/x/crypto/blake2s.New128": AlgorithmHit("BLAKE2S", _HASH),
    # ---- symmetric ----
    "crypto/aes.NewCipher": AlgorithmHit("AES", _SYM),
    "crypto/des.NewCipher": AlgorithmHit("DES", _SYM),
    "crypto/des.NewTripleDESCipher": AlgorithmHit("3DES", _SYM),
    "crypto/rc4.NewCipher": AlgorithmHit("RC4", _SYM),
    "golang.org/x/crypto/chacha20.NewUnauthenticatedCipher": AlgorithmHit("CHACHA20", _SYM),
    "golang.org/x/crypto/chacha20poly1305.New": AlgorithmHit("CHACHA20", _AEAD),
    "golang.org/x/crypto/chacha20poly1305.NewX": AlgorithmHit("CHACHA20", _AEAD),
    # ---- asymmetric / signature / key-agreement ----
    "crypto/rsa.GenerateKey": AlgorithmHit("RSA", _ASYM),
    "crypto/ecdsa.GenerateKey": AlgorithmHit("ECDSA", _SIG),  # curve from arg 0
    "crypto/dsa.GenerateParameters": AlgorithmHit("DSA", _SIG),
    "crypto/dsa.GenerateKey": AlgorithmHit("DSA", _SIG),
    "crypto/ed25519.GenerateKey": AlgorithmHit("EdDSA", _SIG, curve="Ed25519"),
    # crypto/ecdh.<Curve>() returns the curve marker; the curve is baked into
    # the hit because it lives in the function name, not an argument.
    "crypto/ecdh.X25519": AlgorithmHit("X25519", _KA),
    "crypto/ecdh.P256": AlgorithmHit("ECDH", _KA, curve="P-256"),
    "crypto/ecdh.P384": AlgorithmHit("ECDH", _KA, curve="P-384"),
    "crypto/ecdh.P521": AlgorithmHit("ECDH", _KA, curve="P-521"),
    # ---- PQC ----
    "crypto/mlkem.GenerateKey768": AlgorithmHit("ML-KEM", _KEM),
    "crypto/mlkem.GenerateKey1024": AlgorithmHit("ML-KEM", _KEM),
}


def lookup_go_symbol(qualified_name: str) -> AlgorithmHit | None:
    return _GO_SYMBOLS.get(qualified_name)


# Cipher-mode classes: dotted suffix → mode name. Used when the visitor
# walks `Cipher(algorithms.AES(...), modes.GCM(...))` to extract the mode.
_CIPHER_MODES: dict[str, str] = {
    "cryptography.hazmat.primitives.ciphers.modes.GCM": "GCM",
    "cryptography.hazmat.primitives.ciphers.modes.CBC": "CBC",
    "cryptography.hazmat.primitives.ciphers.modes.ECB": "ECB",
    "cryptography.hazmat.primitives.ciphers.modes.CTR": "CTR",
    "cryptography.hazmat.primitives.ciphers.modes.OFB": "OFB",
    "cryptography.hazmat.primitives.ciphers.modes.CFB": "CFB",
    "cryptography.hazmat.primitives.ciphers.modes.XTS": "XTS",
}


# pycryptodome <Cipher>.MODE_* attribute → mode name. Block ciphers only;
# stream ciphers (ChaCha20, ARC4) do not take a mode argument.
_PYCRYPTODOME_MODE_ATTRS: dict[str, str] = {
    # AES
    "Crypto.Cipher.AES.MODE_GCM": "GCM",
    "Crypto.Cipher.AES.MODE_CBC": "CBC",
    "Crypto.Cipher.AES.MODE_ECB": "ECB",
    "Crypto.Cipher.AES.MODE_CTR": "CTR",
    "Crypto.Cipher.AES.MODE_OFB": "OFB",
    "Crypto.Cipher.AES.MODE_CFB": "CFB",
    # DES
    "Crypto.Cipher.DES.MODE_CBC": "CBC",
    "Crypto.Cipher.DES.MODE_ECB": "ECB",
    "Crypto.Cipher.DES.MODE_CTR": "CTR",
    "Crypto.Cipher.DES.MODE_OFB": "OFB",
    "Crypto.Cipher.DES.MODE_CFB": "CFB",
    # DES3 (TripleDES)
    "Crypto.Cipher.DES3.MODE_CBC": "CBC",
    "Crypto.Cipher.DES3.MODE_ECB": "ECB",
    "Crypto.Cipher.DES3.MODE_CTR": "CTR",
    "Crypto.Cipher.DES3.MODE_OFB": "OFB",
    "Crypto.Cipher.DES3.MODE_CFB": "CFB",
}


_HASHLIB_PREFIX = "hashlib."

# Marker canonical that is never emitted as a finding — the visitor unwraps
# it into the concrete inner algorithm. Excluded from the emittable set.
CIPHER_WRAPPER = "CIPHER-WRAPPER"


def lookup_python_symbol(qualified_name: str) -> AlgorithmHit | None:
    return _PYTHON_SYMBOLS.get(qualified_name)


def hashlib_new_table() -> dict[str, AlgorithmHit]:
    """Map each `hashlib.new("name")` string argument to its AlgorithmHit.

    Derived from the `hashlib.*` catalog entries so the string-dispatch path
    in the detector shares a single source of truth with direct-call lookups.
    Keys are the hashlib constructor suffixes (``md5``, ``sha3_256`` …), which
    match the normalized argument accepted by ``hashlib.new``.
    """
    return {
        name[len(_HASHLIB_PREFIX) :]: hit
        for name, hit in _PYTHON_SYMBOLS.items()
        if name.startswith(_HASHLIB_PREFIX)
    }


def emittable_canonicals() -> set[str]:
    """Canonical names a detector can attach to a finding.

    Excludes the CIPHER_WRAPPER marker. Used by the invariant test that
    guards against catalog / QuantumRisk-map drift across all languages.
    """
    catalog = {hit.canonical for hit in _PYTHON_SYMBOLS.values()}
    catalog |= {hit.canonical for hit in _GO_SYMBOLS.values()}
    return catalog - {CIPHER_WRAPPER}


def lookup_cipher_mode(qualified_name: str) -> str | None:
    result = _CIPHER_MODES.get(qualified_name)
    if result is not None:
        return result
    return _PYCRYPTODOME_MODE_ATTRS.get(qualified_name)


# Curve name → policy §3 curve vocabulary. Keyed by the upcased name so both
# the `cryptography` class names (SECP256R1) and the pycryptodome / OpenSSL
# string aliases (p256, P-256, prime256v1) collapse to one policy spelling.
# NIST P-curves take their policy spelling; secp256k1 is lowercased to match.
# Names not listed pass through unchanged (keeping their original casing) so a
# curve without a policy spelling keeps its library name rather than dropping.
_CURVE_NAMES: dict[str, str] = {
    "SECP192R1": "P-192", "P192": "P-192", "P-192": "P-192", "PRIME192V1": "P-192",
    "SECP224R1": "P-224", "P224": "P-224", "P-224": "P-224", "PRIME224V1": "P-224",
    "SECP256R1": "P-256", "P256": "P-256", "P-256": "P-256", "PRIME256V1": "P-256",
    "SECP384R1": "P-384", "P384": "P-384", "P-384": "P-384", "PRIME384V1": "P-384",
    "SECP521R1": "P-521", "P521": "P-521", "P-521": "P-521", "PRIME521V1": "P-521",
    "SECP256K1": "secp256k1",
}


def normalize_curve(name: str) -> str:
    return _CURVE_NAMES.get(name.upper(), name)
