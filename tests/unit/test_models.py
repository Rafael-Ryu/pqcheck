from pathlib import Path

import pytest
from pydantic import ValidationError

from pqcheck.models import (
    AlgorithmFamily,
    CryptoFinding,
    QuantumRisk,
    SourceLocation,
)


def test_source_location_requires_positive_line() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path=Path("a.py"), line=0, column=0)


def test_source_location_is_frozen() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    with pytest.raises(ValidationError):
        loc.line = 2  # type: ignore[misc]


def test_crypto_finding_minimal_construction() -> None:
    loc = SourceLocation(path=Path("a.py"), line=10, column=4)
    finding = CryptoFinding(
        algorithm="MD5",
        family=AlgorithmFamily.HASH,
        location=loc,
        evidence="hashlib.md5()",
        detector_id="python-ast",
    )
    assert finding.algorithm == "MD5"
    assert finding.family is AlgorithmFamily.HASH
    assert finding.confidence == 1.0


def test_quantum_risk_resolved_from_algorithm_name() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    md5 = CryptoFinding(
        algorithm="MD5", family=AlgorithmFamily.HASH, location=loc,
        evidence="x", detector_id="python-ast",
    )
    rsa = CryptoFinding(
        algorithm="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION, location=loc,
        evidence="x", detector_id="python-ast",
    )
    aes = CryptoFinding(
        algorithm="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER, location=loc,
        evidence="x", detector_id="python-ast",
    )
    unknown = CryptoFinding(
        algorithm="WHIRLPOOL", family=AlgorithmFamily.HASH, location=loc,
        evidence="x", detector_id="python-ast",
    )
    assert md5.quantum_risk is QuantumRisk.BROKEN
    assert rsa.quantum_risk is QuantumRisk.VULNERABLE
    assert aes.quantum_risk is QuantumRisk.SAFE
    assert unknown.quantum_risk is QuantumRisk.UNKNOWN


def test_new_safe_primitives_resolve_to_safe() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    for algo in ("CHACHA20-POLY1305", "PBKDF2", "SCRYPT", "HKDF"):
        f = CryptoFinding(
            algorithm=algo, family=AlgorithmFamily.HASH, location=loc,
            evidence="x", detector_id="python-ast",
        )
        assert f.quantum_risk is QuantumRisk.SAFE, algo


def test_confidence_bounded_0_to_1() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    with pytest.raises(ValidationError):
        CryptoFinding(
            algorithm="MD5", family=AlgorithmFamily.HASH, location=loc,
            evidence="x", detector_id="python-ast", confidence=1.5,
        )
    with pytest.raises(ValidationError):
        CryptoFinding(
            algorithm="MD5", family=AlgorithmFamily.HASH, location=loc,
            evidence="x", detector_id="python-ast", confidence=-0.1,
        )
