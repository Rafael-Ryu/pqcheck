"""Domain types emitted by language detectors.

Only the slice consumed by the Python AST detector lives here today.
Downstream computed fields (severity, base_severity, confidence_band,
ScanResult, CryptoDependency, policy_decisions) are added when the
policy engine and scanner orchestrator land.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, computed_field


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


_QUANTUM_MAP: dict[str, QuantumRisk] = {
    "RSA": QuantumRisk.VULNERABLE,
    "DSA": QuantumRisk.VULNERABLE,
    "ECDSA": QuantumRisk.VULNERABLE,
    "ECDH": QuantumRisk.VULNERABLE,
    "DH": QuantumRisk.VULNERABLE,
    "ED25519": QuantumRisk.VULNERABLE,
    "ED448": QuantumRisk.VULNERABLE,
    "X25519": QuantumRisk.VULNERABLE,
    "X448": QuantumRisk.VULNERABLE,
    "AES": QuantumRisk.SAFE,
    "CHACHA20": QuantumRisk.SAFE,
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
