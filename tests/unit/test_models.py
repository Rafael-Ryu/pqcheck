from pathlib import Path

import pytest
from pydantic import ValidationError

from pqcheck.models import (
    AlgorithmFamily,
    CryptoDependency,
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


def test_crypto_dependency_minimal_construction() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/cryptography@43.0.0",
        name="cryptography",
        version="43.0.0",
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
    )
    assert dep.name == "cryptography"
    assert dep.version == "43.0.0"
    assert dep.ecosystem == "pypi"
    assert dep.introduces_algorithms == ()


def test_crypto_dependency_with_algorithms_tuple() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/pycryptodome@3.20.0",
        name="pycryptodome",
        version="3.20.0",
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
        introduces_algorithms=("RSA", "AES", "DES", "MD5"),
    )
    assert dep.introduces_algorithms == ("RSA", "AES", "DES", "MD5")


def test_crypto_dependency_is_frozen() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/rsa@4.9",
        name="rsa",
        version="4.9",
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
    )
    with pytest.raises(ValidationError):
        dep.version = "5.0"  # type: ignore[misc]


def test_crypto_dependency_accepts_missing_version() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/cryptography",
        name="cryptography",
        version=None,
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
    )
    assert dep.version is None


def test_crypto_dependency_rejects_malformed_purl() -> None:
    with pytest.raises(ValidationError):
        CryptoDependency(
            purl="not-a-purl-at-all",
            name="x",
            ecosystem="pypi",
            declared_in=Path("pyproject.toml"),
        )


def test_crypto_dependency_rejects_empty_scheme_purl() -> None:
    with pytest.raises(ValidationError):
        CryptoDependency(
            purl="pkg:",
            name="x",
            ecosystem="pypi",
            declared_in=Path("pyproject.toml"),
        )


def test_crypto_dependency_accepts_valid_maven_purl() -> None:
    dep = CryptoDependency(
        purl="pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78",
        name="bcprov-jdk18on",
        version="1.78",
        ecosystem="maven",
        declared_in=Path("pom.xml"),
    )
    assert dep.purl.startswith("pkg:maven/")
