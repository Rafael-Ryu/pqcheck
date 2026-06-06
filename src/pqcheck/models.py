"""Domain types emitted by language detectors and dependency parsers.

Slice consumed by the Python AST detector and the v0.1 deps parsers
(pyproject.toml, uv.lock, pom.xml) lives here today.
Downstream computed fields (severity, base_severity, confidence_band,
ScanResult, policy_decisions) are added when the
policy engine and scanner orchestrator land.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

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
    "AES": QuantumRisk.SAFE,
    "CHACHA20": QuantumRisk.SAFE,
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
    "MD5": QuantumRisk.BROKEN,
    "SHA-1": QuantumRisk.BROKEN,
    "DES": QuantumRisk.BROKEN,
    "3DES": QuantumRisk.BROKEN,
    "RC4": QuantumRisk.BROKEN,
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
    key_size: int | None = None
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
