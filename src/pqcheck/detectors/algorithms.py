"""Static catalog mapping language-level symbols to canonical algorithms.

Python-specific lookups for v0.1. Go and Java detectors extend the
catalog with their own lookup functions; canonical names are shared
across languages so downstream policy rules apply uniformly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import cache
from importlib.resources import files

from pqcheck.models import AlgorithmFamily


@dataclass(frozen=True, slots=True)
class AlgorithmHit:
    canonical: str
    family: AlgorithmFamily
    # Implicit curve for symbols that encode it in the class name rather than a
    # call argument (Ed25519/Ed448). None means "extract from the call, if any".
    curve: str | None = None
    # Padding scheme the symbol encodes. "OAEP" is a marker: the detector
    # resolves the actual hash from the call's `algorithm=` argument rather
    # than trusting this placeholder (RSA-OAEP-SHA256 is fine; only
    # RSA-OAEP-SHA1 is §3-banned). Direct schemes (PKCS1v15) set the final
    # value here.
    padding: str | None = None
    # Implicit PQC parameter set for symbols that encode it in the module/class
    # name rather than a runtime argument (ML-KEM-768, ML-DSA-65, SLH-DSA
    # SHA2-128s). Same "baked into the hit" pattern as `curve` above — the
    # detector falls back to this when it cannot extract a key_size from the
    # call site. None means "no static variant" (e.g. oqs.KeyEncapsulation,
    # whose variant is a runtime string argument the catalog does not resolve).
    key_size: int | str | None = None


_HASH = AlgorithmFamily.HASH
_ASYM = AlgorithmFamily.ASYMMETRIC_ENCRYPTION
_SIG = AlgorithmFamily.SIGNATURE
_KA = AlgorithmFamily.KEY_AGREEMENT
_SYM = AlgorithmFamily.SYMMETRIC_CIPHER
_KEM = AlgorithmFamily.KEM
_AEAD = AlgorithmFamily.AEAD
_KDF = AlgorithmFamily.KDF


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
    # Not a hashlib module attribute, but hashlib_new_table() derives the
    # hashlib.new("ripemd160") string-dispatch from this entry (OpenSSL name).
    "hashlib.ripemd160": AlgorithmHit("RIPEMD-160", _HASH),
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
    # ---- RSA padding schemes (§3: "Padding | RSA-PKCS1v1.5, RSA-OAEP-SHA1") ----
    # padding.PKCS1v15() / padding.OAEP(...) are themselves Call nodes at the
    # site they're constructed (e.g. `key.encrypt(msg, padding.PKCS1v15())`),
    # so they resolve like any other catalog symbol — no dataflow needed.
    # RSA is already unconditionally banned regardless of padding; this
    # extraction exists so a padding-specific policy rule (and the CBOM) can
    # name the concrete weakness rather than only "RSA".
    "cryptography.hazmat.primitives.asymmetric.padding.PKCS1v15":
        AlgorithmHit("RSA", _ASYM, padding="PKCS1v15"),
    "cryptography.hazmat.primitives.asymmetric.padding.OAEP":
        AlgorithmHit("RSA", _ASYM, padding="OAEP"),
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
    "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish": AlgorithmHit("Blowfish", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.IDEA": AlgorithmHit("IDEA", _SYM),
    # cryptography 43 moved the legacy ciphers to hazmat.decrepit; both import
    # paths appear in the wild, so both must hit (§3 reconciliation, M2).
    "cryptography.hazmat.decrepit.ciphers.algorithms.Blowfish": AlgorithmHit("Blowfish", _SYM),
    "cryptography.hazmat.decrepit.ciphers.algorithms.IDEA": AlgorithmHit("IDEA", _SYM),
    "cryptography.hazmat.decrepit.ciphers.algorithms.TripleDES": AlgorithmHit("3DES", _SYM),
    "cryptography.hazmat.decrepit.ciphers.algorithms.ARC4": AlgorithmHit("RC4", _SYM),
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
    "Crypto.Hash.RIPEMD160.new": AlgorithmHit("RIPEMD-160", _HASH),
    "Crypto.Cipher.AES.new": AlgorithmHit("AES", _SYM),
    "Crypto.Cipher.DES.new": AlgorithmHit("DES", _SYM),
    "Crypto.Cipher.DES3.new": AlgorithmHit("3DES", _SYM),
    "Crypto.Cipher.ARC4.new": AlgorithmHit("RC4", _SYM),
    "Crypto.Cipher.ChaCha20.new": AlgorithmHit("CHACHA20", _SYM),
    "Crypto.Cipher.Blowfish.new": AlgorithmHit("Blowfish", _SYM),
    "Crypto.PublicKey.RSA.generate": AlgorithmHit("RSA", _ASYM),
    "Crypto.PublicKey.DSA.generate": AlgorithmHit("DSA", _SIG),
    "Crypto.PublicKey.ECC.generate": AlgorithmHit("ECDSA", _SIG),
    # ---- liboqs-python (oqs) ----
    # oqs.KeyEncapsulation("ML-KEM-768") / oqs.Signature("ML-DSA-65") take the
    # concrete variant as a runtime string argument that also accepts legacy
    # liboqs names (e.g. "Kyber768", "Dilithium3") for the same underlying
    # mechanism. Unlike the entries below, there is no static class/module
    # name to bake a parameter set into — the variant only exists as a
    # runtime string the detector does not evaluate — so key_size stays
    # None and these findings fall through to the policy default-action
    # rather than an approved rule that names specific parameter sets.
    # That is the honest answer: static analysis cannot prove which
    # variant a runtime string selects. Emitted without a variant, same
    # tradeoff the Go mlkem.GenerateKey768/GenerateKey1024 entries already
    # make in crypto-catalog.json (their key_size is also None today).
    "oqs.KeyEncapsulation": AlgorithmHit("ML-KEM", _KEM),
    "oqs.Signature": AlgorithmHit("ML-DSA", _SIG),
    # ---- kyber-py (kyber_py.ml_kem) ----
    # ML_KEM_512/768/1024 are pre-built instances (not classes to construct),
    # so `ML_KEM_768.keygen()` resolves as a plain attribute chain. The
    # parameter set is baked into the hit (key_size) so it survives to the
    # finding without dataflow, the same way EdDSA/X25519 bake in `curve`.
    "kyber_py.ml_kem.ML_KEM_512.keygen": AlgorithmHit("ML-KEM", _KEM, key_size=512),
    "kyber_py.ml_kem.ML_KEM_512.encaps": AlgorithmHit("ML-KEM", _KEM, key_size=512),
    "kyber_py.ml_kem.ML_KEM_512.decaps": AlgorithmHit("ML-KEM", _KEM, key_size=512),
    "kyber_py.ml_kem.ML_KEM_768.keygen": AlgorithmHit("ML-KEM", _KEM, key_size=768),
    "kyber_py.ml_kem.ML_KEM_768.encaps": AlgorithmHit("ML-KEM", _KEM, key_size=768),
    "kyber_py.ml_kem.ML_KEM_768.decaps": AlgorithmHit("ML-KEM", _KEM, key_size=768),
    "kyber_py.ml_kem.ML_KEM_1024.keygen": AlgorithmHit("ML-KEM", _KEM, key_size=1024),
    "kyber_py.ml_kem.ML_KEM_1024.encaps": AlgorithmHit("ML-KEM", _KEM, key_size=1024),
    "kyber_py.ml_kem.ML_KEM_1024.decaps": AlgorithmHit("ML-KEM", _KEM, key_size=1024),
    # ---- dilithium-py (dilithium_py.ml_dsa) ----
    "dilithium_py.ml_dsa.ML_DSA_44.keygen": AlgorithmHit("ML-DSA", _SIG, key_size=44),
    "dilithium_py.ml_dsa.ML_DSA_44.sign": AlgorithmHit("ML-DSA", _SIG, key_size=44),
    "dilithium_py.ml_dsa.ML_DSA_44.verify": AlgorithmHit("ML-DSA", _SIG, key_size=44),
    "dilithium_py.ml_dsa.ML_DSA_65.keygen": AlgorithmHit("ML-DSA", _SIG, key_size=65),
    "dilithium_py.ml_dsa.ML_DSA_65.sign": AlgorithmHit("ML-DSA", _SIG, key_size=65),
    "dilithium_py.ml_dsa.ML_DSA_65.verify": AlgorithmHit("ML-DSA", _SIG, key_size=65),
    "dilithium_py.ml_dsa.ML_DSA_87.keygen": AlgorithmHit("ML-DSA", _SIG, key_size=87),
    "dilithium_py.ml_dsa.ML_DSA_87.sign": AlgorithmHit("ML-DSA", _SIG, key_size=87),
    "dilithium_py.ml_dsa.ML_DSA_87.verify": AlgorithmHit("ML-DSA", _SIG, key_size=87),
    # ---- cryptography (pyca) ML-KEM / ML-DSA (43.0+ / 47.0+) ----
    # No MLKEM512PrivateKey exists — cryptography only ships the FIPS 203
    # levels it has upstream OpenSSL/AWS-LC support for (768, 1024).
    "cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM768PrivateKey.generate":
        AlgorithmHit("ML-KEM", _KEM, key_size=768),
    "cryptography.hazmat.primitives.asymmetric.mlkem.MLKEM1024PrivateKey.generate":
        AlgorithmHit("ML-KEM", _KEM, key_size=1024),
    "cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA44PrivateKey.generate":
        AlgorithmHit("ML-DSA", _SIG, key_size=44),
    "cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA65PrivateKey.generate":
        AlgorithmHit("ML-DSA", _SIG, key_size=65),
    "cryptography.hazmat.primitives.asymmetric.mldsa.MLDSA87PrivateKey.generate":
        AlgorithmHit("ML-DSA", _SIG, key_size=87),
    # ---- pyspx (SLH-DSA / SPHINCS+) ----
    # Submodule name comes from the compiled parameter set (verified against
    # the installed 0.5.0 wheel: `pyspx.shake_128f`, not the stale
    # `shake256_128f` shown in the project README). Only the FIPS 205 hash
    # families (SHA2, SHAKE) are catalogued; `haraka_*` is a non-standardized
    # SPHINCS+ parameter set pyspx also builds from source, left out because
    # it never shipped in a PyPI wheel and isn't part of SLH-DSA.
    # The parameter set is baked into key_size from the submodule name
    # (sha2_128s -> "SHA2-128s") so it survives to the policy layer without
    # dataflow. Only the string form matches: policy rules key on the
    # exact "SHA2-128s"-style token (02 SS13 / cryptoct-default.yaml), so
    # key_size is str here, unlike ML-KEM/ML-DSA's int parameter sets.
    "pyspx.sha2_128f.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-128f"),
    "pyspx.sha2_128f.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-128f"),
    "pyspx.sha2_128f.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-128f"),
    "pyspx.sha2_128s.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-128s"),
    "pyspx.sha2_128s.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-128s"),
    "pyspx.sha2_128s.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-128s"),
    "pyspx.sha2_192f.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-192f"),
    "pyspx.sha2_192f.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-192f"),
    "pyspx.sha2_192f.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-192f"),
    "pyspx.sha2_192s.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-192s"),
    "pyspx.sha2_192s.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-192s"),
    "pyspx.sha2_192s.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-192s"),
    "pyspx.sha2_256f.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-256f"),
    "pyspx.sha2_256f.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-256f"),
    "pyspx.sha2_256f.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-256f"),
    "pyspx.sha2_256s.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-256s"),
    "pyspx.sha2_256s.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-256s"),
    "pyspx.sha2_256s.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHA2-256s"),
    "pyspx.shake_128f.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-128f"),
    "pyspx.shake_128f.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-128f"),
    "pyspx.shake_128f.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-128f"),
    "pyspx.shake_128s.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-128s"),
    "pyspx.shake_128s.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-128s"),
    "pyspx.shake_128s.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-128s"),
    "pyspx.shake_192f.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-192f"),
    "pyspx.shake_192f.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-192f"),
    "pyspx.shake_192f.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-192f"),
    "pyspx.shake_192s.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-192s"),
    "pyspx.shake_192s.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-192s"),
    "pyspx.shake_192s.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-192s"),
    "pyspx.shake_256f.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-256f"),
    "pyspx.shake_256f.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-256f"),
    "pyspx.shake_256f.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-256f"),
    "pyspx.shake_256s.generate_keypair": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-256s"),
    "pyspx.shake_256s.sign": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-256s"),
    "pyspx.shake_256s.verify": AlgorithmHit("SLH-DSA", _SIG, key_size="SHAKE-256s"),
    # ---- pynacl (libsodium bindings) ----
    # SigningKey/PrivateKey.generate() follow the same shape as the
    # cryptography ed25519/x25519 entries above; only the *.generate()
    # call sites are catalogued (not VerifyKey/PublicKey, which load an
    # already-existing key rather than mint one — same scope decision as
    # the cryptography Ed25519/X25519 entries, which only cover .generate()).
    "nacl.signing.SigningKey.generate": AlgorithmHit("EdDSA", _SIG, curve="Ed25519"),
    "nacl.public.PrivateKey.generate": AlgorithmHit("X25519", _KA),
    # SecretBox is XSalsa20-Poly1305 (libsodium's crypto_secretbox); Box/
    # SealedBox are left out because a single call site would conflate two
    # primitives (X25519 key agreement + XSalsa20-Poly1305 AEAD) under one
    # canonical, which the one-hit-per-symbol catalog shape can't represent
    # without a new multi-emit path.
    "nacl.secret.SecretBox": AlgorithmHit("XSALSA20-POLY1305", _AEAD),
    "nacl.hash.blake2b": AlgorithmHit("BLAKE2B", _HASH),
    "nacl.pwhash.argon2id.str": AlgorithmHit("ARGON2", _KDF),
    "nacl.pwhash.argon2id.kdf": AlgorithmHit("ARGON2", _KDF),
    "nacl.pwhash.argon2i.str": AlgorithmHit("ARGON2", _KDF),
    "nacl.pwhash.argon2i.kdf": AlgorithmHit("ARGON2", _KDF),
    # nacl.pwhash.str is the un-suffixed convenience wrapper, aliased to
    # argon2id.str in pynacl 1.6 (verified via inspect on the installed
    # wheel). There is no top-level nacl.pwhash.kdf — pynacl only exposes
    # kdf_scryptsalsa208sha256 at that scope — so no matching entry exists.
    "nacl.pwhash.str": AlgorithmHit("ARGON2", _KDF),
}


# Fully-qualified Go callee (<import-path>.<Func>) -> AlgorithmHit lives in the
# language-agnostic data file crypto-catalog.json (single source of truth), so
# the future Go analyzer binary can go:embed the same catalog the Python lookup
# reads. Canonical names match the policy spelling and are shared with the
# Python catalog so downstream policy rules apply uniformly across languages.
@cache
def load_go_catalog() -> dict[str, AlgorithmHit]:
    raw = json.loads(
        files("pqcheck.data").joinpath("crypto-catalog.json").read_text("utf-8")
    )
    return {
        symbol: AlgorithmHit(
            canonical=entry["canonical"],
            family=AlgorithmFamily(entry["family"]),
            curve=entry.get("curve"),
        )
        for symbol, entry in raw.items()
    }


def lookup_go_symbol(qualified_name: str) -> AlgorithmHit | None:
    return load_go_catalog().get(qualified_name)


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
    canonicals = {hit.canonical for hit in _PYTHON_SYMBOLS.values()}
    canonicals |= {hit.canonical for hit in load_go_catalog().values()}
    return canonicals - {CIPHER_WRAPPER}


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
