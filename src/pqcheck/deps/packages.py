"""Static catalog: (ecosystem, package_name) -> tuple of canonical algorithms.

Seeded with the 10-15 packages most relevant to the v0.1 BR-fintech
vertical. Expansion is customer-signal driven (trigger-based
provisioning principle). Canonical algorithm names match those in
pqcheck.detectors.algorithms — when adding a new entry, use the same
spelling so downstream policy rules apply uniformly.

A package's presence in this catalog does NOT mean it always uses every
listed algorithm at runtime — it means the package SURFACES the
algorithm in its public API. The policy engine treats the dep list as a
"potentially uses" set, combined with detector findings (which prove
actual call sites) to score severity.
"""

from __future__ import annotations

# (ecosystem, lowercased_name) -> tuple of canonical algorithm names.
_CATALOG: dict[tuple[str, str], tuple[str, ...]] = {
    # ---- PyPI ----
    ("pypi", "cryptography"): (
        "RSA", "DSA", "ECDSA", "DH", "ED25519", "ED448", "X25519", "X448",
        "AES", "CHACHA20", "3DES", "RC4",
        "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B", "BLAKE2S",
        "ML-KEM", "ML-DSA",  # 43.0+ / 47.0+
    ),
    ("pypi", "pycryptodome"): (
        "RSA", "DSA", "ECDSA",
        "AES", "DES", "3DES", "RC4", "CHACHA20",
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B", "BLAKE2S",
    ),
    ("pypi", "pycryptodomex"): (
        "RSA", "DSA", "ECDSA",
        "AES", "DES", "3DES", "RC4", "CHACHA20",
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B", "BLAKE2S",
    ),
    ("pypi", "rsa"): ("RSA",),
    ("pypi", "ecdsa"): ("ECDSA",),
    ("pypi", "pynacl"): ("ED25519", "X25519", "CHACHA20"),
    ("pypi", "pyopenssl"): ("RSA", "ECDSA", "AES", "SHA-256"),
    ("pypi", "bcrypt"): (),  # BCRYPT is a KDF; not in QuantumRisk map; flagged via family
    ("pypi", "passlib"): ("MD5", "SHA-1", "SHA-256", "SHA-512"),
    ("pypi", "paramiko"): ("RSA", "DSA", "ECDSA", "AES", "SHA-1", "SHA-256"),
    ("pypi", "pyjwt"): ("RSA", "ECDSA", "SHA-256", "SHA-384", "SHA-512"),
    ("pypi", "python-jose"): ("RSA", "ECDSA", "AES", "SHA-256"),
    # ---- PyPI: PQC (mirrors the PQC source-detector catalog, PR #216) ----
    ("pypi", "liboqs-python"): ("ML-KEM", "ML-DSA", "SLH-DSA"),
    ("pypi", "kyber-py"): ("ML-KEM",),
    ("pypi", "dilithium-py"): ("ML-DSA",),
    ("pypi", "pyspx"): ("SLH-DSA",),
    # ---- Go modules: PQC ----
    ("golang", "github.com/open-quantum-safe/liboqs-go"): ("ML-KEM", "ML-DSA", "SLH-DSA"),
    ("golang", "github.com/cloudflare/circl"): (
        "ML-KEM", "ML-DSA", "SLH-DSA", "ED25519", "ED448", "X25519", "X448",
    ),
    ("golang", "filippo.io/mlkem768"): ("ML-KEM",),
    # ---- npm: PQC ----
    ("npm", "@noble/post-quantum"): ("ML-KEM", "ML-DSA", "SLH-DSA"),
    ("npm", "mlkem"): ("ML-KEM",),
    # ---- Maven ----
    ("maven", "bcprov-jdk18on"): (
        "RSA", "DSA", "ECDSA", "DH", "ED25519", "ED448", "X25519", "X448",
        "AES", "DES", "3DES", "RC4", "CHACHA20",
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "BLAKE2B", "BLAKE2S",
        "ML-KEM", "ML-DSA", "SLH-DSA",  # BC 1.78+
    ),
    ("maven", "bcpkix-jdk18on"): ("RSA", "ECDSA", "AES", "SHA-256"),
    ("maven", "bctls-jdk18on"): ("RSA", "ECDSA", "AES", "CHACHA20", "SHA-256"),
    ("maven", "tink"): ("AES", "ECDSA", "ED25519", "X25519", "SHA-256"),
    ("maven", "tink-android"): ("AES", "ECDSA", "ED25519", "X25519", "SHA-256"),
    ("maven", "jjwt"): ("RSA", "ECDSA", "SHA-256", "SHA-384", "SHA-512"),
    ("maven", "nimbus-jose-jwt"): ("RSA", "ECDSA", "AES", "SHA-256"),
    ("maven", "commons-codec"): ("MD5", "SHA-1", "SHA-256"),
}


def lookup_introduces(ecosystem: str, name: str) -> tuple[str, ...]:
    """Return the algorithms a package is known to introduce, or () if unknown."""
    return _CATALOG.get((ecosystem, name.lower()), ())
