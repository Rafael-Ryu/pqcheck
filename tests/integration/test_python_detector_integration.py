from pathlib import Path

import pytest

from pqcheck.detectors.python_detector import detect_python_file
from pqcheck.models import QuantumRisk

FIXTURES = Path(__file__).parent.parent / "fixtures" / "python"


@pytest.mark.integration
def test_known_bad_emits_only_vulnerable_or_broken() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    assert findings, "expected detections in known_bad.py"
    # AES appears with ECB mode (tested separately); AES itself is quantum-safe.
    for f in findings:
        if f.algorithm == "AES":
            continue
        assert f.quantum_risk in {QuantumRisk.BROKEN, QuantumRisk.VULNERABLE}, (
            f"{f.algorithm} should be flagged"
        )


@pytest.mark.integration
def test_known_bad_includes_expected_algorithms() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    algorithms = {f.algorithm for f in findings}
    assert {"MD5", "SHA-1", "RSA", "ECDSA", "DH", "3DES", "AES"} <= algorithms


@pytest.mark.integration
def test_known_bad_rsa_key_size_extracted() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    rsa = [f for f in findings if f.algorithm == "RSA"]
    assert len(rsa) == 1
    assert rsa[0].key_size == 2048


@pytest.mark.integration
def test_known_bad_aes_ecb_mode_extracted() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    aes = [f for f in findings if f.algorithm == "AES"]
    assert len(aes) == 1
    assert aes[0].mode == "ECB"


@pytest.mark.integration
def test_known_good_emits_no_broken_or_vulnerable() -> None:
    findings = detect_python_file(FIXTURES / "known_good.py")
    assert findings, "expected detections in known_good.py"
    for f in findings:
        assert f.quantum_risk is QuantumRisk.SAFE


@pytest.mark.integration
def test_mixed_pycryptodome_separates_banned_from_acceptable() -> None:
    findings = detect_python_file(FIXTURES / "mixed_pycryptodome.py")
    banned = {f.algorithm for f in findings if f.quantum_risk is not QuantumRisk.SAFE}
    safe = {f.algorithm for f in findings if f.quantum_risk is QuantumRisk.SAFE}
    assert {"DES", "MD5", "RSA"} <= banned
    assert {"SHA-256", "AES"} <= safe
    # AES finding must carry mode='GCM' and DES finding mode='ECB' —
    # before #5 the pycryptodome mode extractor was dead and these were
    # both None.
    aes = next(f for f in findings if f.algorithm == "AES")
    des = next(f for f in findings if f.algorithm == "DES")
    assert aes.mode == "GCM"
    assert des.mode == "ECB"


@pytest.mark.integration
def test_edge_syntax_error_returns_empty() -> None:
    assert detect_python_file(FIXTURES / "edge_syntax_error.py") == []
