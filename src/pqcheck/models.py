"""Domain types for the pqcheck analysis pipeline.

Detector and dependency-parser outputs — `CryptoFinding` and
`CryptoDependency` — live here alongside the policy/scan result types
(`RuleAction`, `PolicyDecision`, `ScanResult`) consumed by the policy
engine and scanner orchestrator.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator


class AlgorithmFamily(StrEnum):
    SYMMETRIC_CIPHER = "symmetric-cipher"
    ASYMMETRIC_ENCRYPTION = "asymmetric-encryption"
    KEY_AGREEMENT = "key-agreement"
    KEM = "key-encapsulation"
    SIGNATURE = "signature"
    HASH = "hash"
    MAC = "message-authentication"
    KDF = "key-derivation"
    RNG = "random"
    AEAD = "authenticated-encryption"
    # crypto/elliptic.P256/384/521 return a curve object usable for either
    # ECDSA or ECDH — static analysis cannot tell which without following the
    # value into its consumer, so this family is deliberately neither.
    ELLIPTIC_CURVE = "elliptic-curve"


class QuantumRisk(StrEnum):
    SAFE = "quantum-safe"
    HYBRID = "hybrid"
    VULNERABLE = "quantum-vulnerable"
    BROKEN = "broken"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    # Declaration order is the tier ranking: INFO (lowest) … CRITICAL (highest).
    # StrEnum compares by string value, so do NOT use < / > on severities —
    # rank via list(Severity).index(s).
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceBand(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RuleAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    FAIL = "fail"


_QUANTUM_MAP: dict[str, QuantumRisk] = {
    "RSA": QuantumRisk.VULNERABLE,
    "DSA": QuantumRisk.VULNERABLE,
    "ECDSA": QuantumRisk.VULNERABLE,
    "ECDH": QuantumRisk.VULNERABLE,
    "DH": QuantumRisk.VULNERABLE,
    # EdDSA is the canonical the Python detector emits; ED25519/ED448 remain
    # for the dependency catalog, which lists per-curve algorithm names.
    "EDDSA": QuantumRisk.VULNERABLE,
    "ED25519": QuantumRisk.VULNERABLE,
    "ED448": QuantumRisk.VULNERABLE,
    "X25519": QuantumRisk.VULNERABLE,
    "X448": QuantumRisk.VULNERABLE,
    "ELGAMAL": QuantumRisk.VULNERABLE,
    "GOST-R-34.10-2001": QuantumRisk.VULNERABLE,
    "SM2": QuantumRisk.VULNERABLE,
    "BLS12-381": QuantumRisk.VULNERABLE,
    # crypto/elliptic curve constructors (family ELLIPTIC_CURVE, not
    # signature/key-agreement — see the family's docstring): whatever the
    # curve object ends up doing, an elliptic curve is Shor-breakable, so
    # VULNERABLE is correct either way the ambiguity resolves.
    "ECC": QuantumRisk.VULNERABLE,
    "AES": QuantumRisk.SAFE,
    "CHACHA20": QuantumRisk.SAFE,
    # Same threat model as AES-256/ChaCha20 above: a symmetric AEAD with no
    # Shor-vulnerable structure, and a 256-bit key gives 128-bit post-Grover
    # margin like the others. Not a policy-approved algorithm
    # (02 SS2.3 names AES-256-GCM specifically) but not banned either —
    # SAFE reflects the quantum-risk verdict this field exists to encode,
    # leaving the "not the house-approved AEAD" call to the policy layer.
    "XSALSA20-POLY1305": QuantumRisk.SAFE,
    # Policy 02 SS2.5 approves Argon2id by name for password hashing; the
    # canonical does not carry the id/i variant (mirrors AES not carrying
    # its mode), so ARGON2 covers both — argon2i lacks side-channel
    # resistance but is still memory-hard and not a quantum concern either
    # way.
    "ARGON2": QuantumRisk.SAFE,
    # Same precedent as ARGON2 above: bcrypt_pbkdf is a memory/CPU-hard KDF,
    # not a quantum concern either way.
    "BCRYPT": QuantumRisk.SAFE,
    "SHA-224": QuantumRisk.SAFE,
    "SHA-256": QuantumRisk.SAFE,
    "SHA-384": QuantumRisk.SAFE,
    "SHA-512": QuantumRisk.SAFE,
    "SHA3-256": QuantumRisk.SAFE,
    "SHA3-384": QuantumRisk.SAFE,
    "SHA3-512": QuantumRisk.SAFE,
    "BLAKE2B": QuantumRisk.SAFE,
    "BLAKE2S": QuantumRisk.SAFE,
    "ML-KEM": QuantumRisk.SAFE,
    "ML-DSA": QuantumRisk.SAFE,
    "SLH-DSA": QuantumRisk.SAFE,
    # FALCON (future FN-DSA; FIPS 206 is still draft, so the deployed name
    # stays canonical) and HQC (NIST backup KEM, selected 2025-03). SAFE
    # encodes the quantum-risk verdict only — neither is a policy-approved
    # algorithm, same split as XSALSA20-POLY1305 above.
    "FALCON": QuantumRisk.SAFE,
    "HQC": QuantumRisk.SAFE,
    # X25519MLKEM768 (filippo.io/hpke's hybrid KEM, also age's post-quantum
    # recipient): classical X25519 plus ML-KEM-768 in one construct. HYBRID,
    # not SAFE — the classical component is still there as defense in depth,
    # not because the PQC component is in doubt.
    "X25519MLKEM768": QuantumRisk.HYBRID,
    "MD5": QuantumRisk.BROKEN,
    "SHA-1": QuantumRisk.BROKEN,
    "DES": QuantumRisk.BROKEN,
    "3DES": QuantumRisk.BROKEN,
    "RC4": QuantumRisk.BROKEN,
    # §3 reconciliation (M2): 64-bit-block ciphers are Sweet32-class broken
    # like 3DES; RIPEMD-160 has no practical collision but its 160-bit margin
    # is policy-banned — vulnerable, not broken.
    "BLOWFISH": QuantumRisk.BROKEN,
    "IDEA": QuantumRisk.BROKEN,
    "RIPEMD-160": QuantumRisk.VULNERABLE,
    # Not a quantum concern — a classically predictable/seedable PRNG used
    # where crypto/rand is required (policy §2.6). Treated as BROKEN like
    # MD5/SHA-1/RC4: a practical, non-quantum break available today.
    "MATH-RAND": QuantumRisk.BROKEN,
    # crypto/rand.Read/Int/Prime: a cryptographically secure RNG, the
    # opposite finding from MATH-RAND above. SAFE here is a positive
    # attestation — pqcheck surfaces correct RNG choice, not just violations.
    "CSPRNG": QuantumRisk.SAFE,
    # Python catalog depth (W2): MACs/KDFs/AEADs added for pyca/cryptography,
    # argon2-cffi, bcrypt, and pycryptodome coverage. None of these carry a
    # Shor-breakable structure — they are hash/block-cipher-based
    # constructions, so classification follows the SHA-2/AES/ARGON2/BCRYPT
    # precedents above rather than introducing a new risk tier.
    "HMAC": QuantumRisk.SAFE,
    "HKDF": QuantumRisk.SAFE,
    "PBKDF2": QuantumRisk.SAFE,
    "SCRYPT": QuantumRisk.SAFE,
    # PBKDF1 (RFC 2898 legacy, deprecated by RFC 8018 SS3): capped at the
    # underlying hash's digest length and long superseded by PBKDF2.
    # Not quantum-relevant either way, but the classical weakness is real
    # enough that treating it as equivalent to PBKDF2 would be dishonest —
    # VULNERABLE mirrors RIPEMD-160's "known-weak but not practically
    # broken" tier above, not PBKDF2's SAFE.
    "PBKDF1": QuantumRisk.VULNERABLE,
    # Direct AEAD constructions (cryptography.hazmat.primitives.ciphers.aead):
    # each fuses a symmetric cipher with its mode into one canonical, same
    # SAFE verdict as the underlying AES/ChaCha20 entries above.
    "AES-GCM": QuantumRisk.SAFE,
    "AES-GCM-SIV": QuantumRisk.SAFE,
    "AES-OCB3": QuantumRisk.SAFE,
    "AES-SIV": QuantumRisk.SAFE,
    "AES-CCM": QuantumRisk.SAFE,
    "CHACHA20-POLY1305": QuantumRisk.SAFE,
    # Fernet: AES-128-CBC + HMAC-SHA256 fused behind one API (cryptography.
    # fernet.Fernet). Same precedent as XSALSA20-POLY1305 above — a
    # symmetric construction with no Shor-vulnerable structure, SAFE on the
    # quantum-risk axis even though AES-128-in-new-code is a separate
    # policy-severity concern (02 SS3) this field does not encode.
    "FERNET": QuantumRisk.SAFE,
    # Go catalog depth (W1). HMAC/HKDF/PBKDF2/SCRYPT are shared with the
    # Python catalog entries above (same canonicals, same SAFE verdict —
    # cross-language parity by construction).
    # x/crypto/salsa20: same threat model as CHACHA20 above — a stream
    # cipher with a 256-bit key and no Shor-vulnerable structure.
    "SALSA20": QuantumRisk.SAFE,
    # Twofish: AES-finalist block cipher, 128/192/256-bit keys. Same
    # precedent as AES/CHACHA20 — not Shor-breakable, not policy-approved
    # either (mirrors XSALSA20-POLY1305's split above).
    "TWOFISH": QuantumRisk.SAFE,
    # §3-reconciliation style (see BLOWFISH/IDEA above): CAST5 and TEA are
    # 64-bit-block ciphers, Sweet32-class broken regardless of quantum
    # computing.
    "CAST5": QuantumRisk.BROKEN,
    "TEA": QuantumRisk.BROKEN,
    # MD4: weaker than MD5, practical collisions long since demonstrated.
    "MD4": QuantumRisk.BROKEN,
    # circl's pre-standardization NIST submission names for the algorithms
    # that became ML-KEM/ML-DSA (FIPS 203/204). Same quantum-risk verdict as
    # their standardized counterparts; kept as distinct canonicals because
    # the encodings are not bit-compatible (see catalog entries).
    "KYBER": QuantumRisk.SAFE,
    "DILITHIUM": QuantumRisk.SAFE,
    # circl's hpke.NewSuite: the concrete KEM is a runtime constant argument
    # (KEM_P256_HKDF_SHA256 … KEM_X25519_HKDF_SHA256, but also the hybrid
    # KEM_X25519_KYBER768_DRAFT00 / KEM_XWING) that static analysis cannot
    # resolve — the same dataflow-opaque situation as ECC above. Most
    # deployed suites still pick a classical-only KEM, so this defaults to
    # the conservative (flagged) verdict rather than assuming the hybrid
    # case; a real hybrid deployment should be verified manually.
    "HPKE": QuantumRisk.VULNERABLE,
}


class SourceLocation(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: Path
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    end_line: int | None = None
    end_column: int | None = None


class CryptoFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str
    family: AlgorithmFamily
    # int for classical bit-lengths (AES-256, RSA-2048); str for PQC parameter-set
    # identifiers that aren't numeric (SLH-DSA's "SHA2-128s"). Both stringify the
    # same way for policy `parameter-sets` matching and the CBOM
    # parameterSetIdentifier property — see policy/engine.py rule_matches.
    key_size: int | str | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    location: SourceLocation
    evidence: str
    detector_id: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @field_validator("key_size")
    @classmethod
    def _key_size_must_be_positive(cls, value: int | str | None) -> int | str | None:
        # PQC parameter-set identifiers (str) pass through untouched; only
        # the classical bit-length (int) case has a meaningful lower bound.
        if isinstance(value, int) and value <= 0:
            raise ValueError(f"key_size must be positive, got {value}")
        return value

    @computed_field  # type: ignore[prop-decorator]
    @property
    def quantum_risk(self) -> QuantumRisk:
        return _QUANTUM_MAP.get(self.algorithm.upper(), QuantumRisk.UNKNOWN)


class CryptoDependency(BaseModel):
    """A dependency declared in a manifest or lockfile.

    Emitted by parsers in pqcheck.deps. The `introduces_algorithms` tuple
    is populated by the parser from the static catalog in
    pqcheck.deps.packages — it lists canonical algorithm names the package
    is known to introduce (e.g., pycryptodome introduces RSA, AES, DES,
    MD5). Empty tuple means "unknown / no entry in catalog", not "no
    crypto" — downstream policy treats unknown packages as INFO findings.
    """

    model_config = ConfigDict(frozen=True)

    purl: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str | None = None
    ecosystem: str = Field(min_length=1)
    declared_in: Path
    introduces_algorithms: tuple[str, ...] = ()
    # False only when a companion checksum file (e.g. go.sum) is present but
    # carries no entry for this (name, version) — a not-pinned / tampered
    # signal. True when verified, or when no checksum file applies.
    integrity_verified: bool = True

    @field_validator("purl")
    @classmethod
    def _purl_must_round_trip(cls, value: str) -> str:
        # Round-trip through packageurl-python so malformed strings (e.g.
        # "not-a-purl", missing scheme, bad type) fail at model-construction
        # time rather than slipping into the CBOM / SARIF outputs.
        try:
            PackageURL.from_string(value)
        except ValueError as exc:
            raise ValueError(f"invalid PURL: {value!r}") from exc
        return value


class PolicyDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    finding: CryptoFinding
    action: RuleAction
    base_severity: Severity
    severity: Severity
    confidence_band: ConfidenceBand
    rule_kind: Literal["approved", "banned", "default"]
    # The policy rule's algorithm token that matched, or "default-action".
    matched: str
    reason: str | None = None
    # A consciously-deferred audit hint: a matching exception exists but is NOT
    # auto-applied in v0.1 (findings carry no usage-context). None otherwise.
    exception_id: str | None = None


class ScanResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    target: Path
    scanner_version: str = Field(min_length=1)
    findings: tuple[CryptoFinding, ...] = ()
    dependencies: tuple[CryptoDependency, ...] = ()
    policy_decisions: tuple[PolicyDecision, ...] = ()
    policy_id: str | None = None
    # Per-file error messages from the walk, surfaced rather than hidden.
    errors: tuple[str, ...] = ()
