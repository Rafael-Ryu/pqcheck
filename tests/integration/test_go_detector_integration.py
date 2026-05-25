from pathlib import Path

import pytest

from pqcheck.detectors.go_detector import detect_go_file
from pqcheck.models import QuantumRisk

FIXTURES = Path(__file__).parent.parent / "fixtures" / "go"


@pytest.mark.integration
def test_known_good_emits_only_safe() -> None:
    findings = detect_go_file(FIXTURES / "known_good.go")
    assert findings, "expected detections in known_good.go"
    for f in findings:
        assert f.quantum_risk is QuantumRisk.SAFE, f"{f.algorithm} should be safe"


@pytest.mark.integration
def test_known_bad_emits_only_vulnerable_or_broken() -> None:
    findings = detect_go_file(FIXTURES / "known_bad.go")
    assert findings, "expected detections in known_bad.go"
    for f in findings:
        assert f.quantum_risk in {QuantumRisk.BROKEN, QuantumRisk.VULNERABLE}, (
            f"{f.algorithm} should be flagged"
        )


@pytest.mark.integration
def test_known_bad_includes_expected_algorithms() -> None:
    findings = detect_go_file(FIXTURES / "known_bad.go")
    algorithms = {f.algorithm for f in findings}
    assert {"MD5", "SHA-1", "RSA", "ECDSA", "DES", "RC4", "EdDSA", "X25519"} <= algorithms


@pytest.mark.integration
def test_known_bad_rsa_key_size_and_ecdsa_curve() -> None:
    findings = detect_go_file(FIXTURES / "known_bad.go")
    rsa = next(f for f in findings if f.algorithm == "RSA")
    assert rsa.key_size == 2048
    ecdsa = next(f for f in findings if f.algorithm == "ECDSA")
    assert ecdsa.curve == "P-256"


@pytest.mark.integration
def test_mixed_separates_banned_from_safe() -> None:
    findings = detect_go_file(FIXTURES / "mixed.go")
    banned = {f.algorithm for f in findings if f.quantum_risk is not QuantumRisk.SAFE}
    safe = {f.algorithm for f in findings if f.quantum_risk is QuantumRisk.SAFE}
    assert {"RSA", "MD5"} <= banned
    assert {"AES", "SHA-256"} <= safe
    rsa = next(f for f in findings if f.algorithm == "RSA")
    assert rsa.key_size == 4096


@pytest.mark.integration
def test_edge_syntax_error_returns_empty() -> None:
    assert detect_go_file(FIXTURES / "edge_syntax_error.go") == []
