from pathlib import Path

import pytest
from pydantic import ValidationError

from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoDependency,
    CryptoFinding,
    PolicyDecision,
    QuantumRisk,
    RuleAction,
    ScanResult,
    Severity,
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


@pytest.mark.parametrize("algo", ["ELGAMAL", "GOST-R-34.10-2001", "SM2", "BLS12-381"])
def test_quantum_risk_new_asymmetric_algorithms_are_vulnerable(algo: str) -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    finding = CryptoFinding(
        algorithm=algo, family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION, location=loc,
        evidence="x", detector_id="python-ast",
    )
    assert finding.quantum_risk is QuantumRisk.VULNERABLE


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


@pytest.mark.parametrize("bad_size", [0, -1, -256])
def test_crypto_finding_rejects_non_positive_int_key_size(bad_size: int) -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    with pytest.raises(ValidationError):
        CryptoFinding(
            algorithm="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER, location=loc,
            evidence="x", detector_id="python-ast", key_size=bad_size,
        )


@pytest.mark.parametrize("good_size", [1, 128, 256, "SHA2-128s", None])
def test_crypto_finding_accepts_valid_key_size(good_size: int | str | None) -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    finding = CryptoFinding(
        algorithm="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER, location=loc,
        evidence="x", detector_id="python-ast", key_size=good_size,
    )
    assert finding.key_size == good_size


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


def test_severity_members_and_order():
    assert [s.value for s in Severity] == ["info", "low", "medium", "high", "critical"]


def test_confidence_band_members():
    assert {b.value for b in ConfidenceBand} == {"low", "medium", "high"}


def _finding() -> CryptoFinding:
    return CryptoFinding(
        algorithm="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
        location=SourceLocation(path=Path("a.py"), line=1, column=0),
        evidence="rsa.generate_private_key(...)", detector_id="python-ast", confidence=0.4,
    )


def test_policy_decision_holds_base_and_demoted_severity():
    d = PolicyDecision(
        finding=_finding(), action=RuleAction.FAIL,
        base_severity=Severity.CRITICAL, severity=Severity.MEDIUM,
        confidence_band=ConfidenceBand.LOW, rule_kind="banned",
        matched="RSA", reason="Shor", exception_id=None,
    )
    assert d.base_severity == Severity.CRITICAL
    assert d.severity == Severity.MEDIUM
    assert d.action == RuleAction.FAIL


def test_scan_result_defaults_are_empty_tuples():
    r = ScanResult(target=Path(), scanner_version="0.0.1")
    assert r.findings == () and r.dependencies == ()
    assert r.policy_decisions == () and r.policy_id is None and r.errors == ()


def test_scan_result_rejects_empty_scanner_version():
    with pytest.raises(ValidationError):
        ScanResult(target=Path(), scanner_version="")
