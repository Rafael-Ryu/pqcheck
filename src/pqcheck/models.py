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


class QuantumRisk(StrEnum):
    SAFE = "quantum-safe"
    # Reserved for hybrid PQC constructs (e.g., X25519MLKEM768) once detectors emit them.
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
    "AES": QuantumRisk.SAFE,
    "CHACHA20": QuantumRisk.SAFE,
    # Same threat model as AES-256/ChaCha20 above: a symmetric AEAD with no
    # Shor-vulnerable structure, and a 256-bit key gives 128-bit post-Grover
    # margin like the others. Not one of the 8 policy-approved algorithms
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
    # encodes the quantum-risk verdict only — neither is among the 8
    # policy-approved algorithms, same split as XSALSA20-POLY1305 above.
    "FALCON": QuantumRisk.SAFE,
    "HQC": QuantumRisk.SAFE,
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
