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


_HASH = AlgorithmFamily.HASH
_ASYM = AlgorithmFamily.ASYMMETRIC_ENCRYPTION
_SIG = AlgorithmFamily.SIGNATURE
_KA = AlgorithmFamily.KEY_AGREEMENT
_SYM = AlgorithmFamily.SYMMETRIC_CIPHER


# Fully-qualified callee name → AlgorithmHit.
# Canonical names follow policy §2/§3 spelling (uppercase, hyphenated).
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
    "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters": AlgorithmHit("DH", _KA),
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate":
        AlgorithmHit("ED25519", _SIG),
    "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate":
        AlgorithmHit("ED448", _SIG),
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
    "Crypto.Cipher.AES.new": AlgorithmHit("AES", _SYM),
    "Crypto.Cipher.DES.new": AlgorithmHit("DES", _SYM),
    "Crypto.Cipher.DES3.new": AlgorithmHit("3DES", _SYM),
    "Crypto.Cipher.ARC4.new": AlgorithmHit("RC4", _SYM),
    "Crypto.Cipher.ChaCha20.new": AlgorithmHit("CHACHA20", _SYM),
    "Crypto.PublicKey.RSA.generate": AlgorithmHit("RSA", _ASYM),
    "Crypto.PublicKey.DSA.generate": AlgorithmHit("DSA", _SIG),
    "Crypto.PublicKey.ECC.generate": AlgorithmHit("ECDSA", _SIG),
}


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


# pycryptodome AES.MODE_* attribute → mode name.
_PYCRYPTODOME_MODE_ATTRS: dict[str, str] = {
    "Crypto.Cipher.AES.MODE_GCM": "GCM",
    "Crypto.Cipher.AES.MODE_CBC": "CBC",
    "Crypto.Cipher.AES.MODE_ECB": "ECB",
    "Crypto.Cipher.AES.MODE_CTR": "CTR",
    "Crypto.Cipher.AES.MODE_OFB": "OFB",
    "Crypto.Cipher.AES.MODE_CFB": "CFB",
}


def lookup_python_symbol(qualified_name: str) -> AlgorithmHit | None:
    return _PYTHON_SYMBOLS.get(qualified_name)


def lookup_cipher_mode(qualified_name: str) -> str | None:
    result = _CIPHER_MODES.get(qualified_name)
    if result is not None:
        return result
    return _PYCRYPTODOME_MODE_ATTRS.get(qualified_name)
