from pathlib import Path

import pytest

from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoFinding,
    PolicyDecision,
    RuleAction,
    Severity,
    SourceLocation,
)
from pqcheck.policy.engine import evaluate, gate
from pqcheck.policy.loader import load_default_policy


def _finding(algo: str = "RSA", conf: float = 1.0) -> CryptoFinding:
    return CryptoFinding(
        algorithm=algo, family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
        location=SourceLocation(path=Path("a.py"), line=1, column=0),
        evidence="e", detector_id="t", confidence=conf,
    )


def _decision(action: RuleAction, base: Severity) -> PolicyDecision:
    return PolicyDecision(
        finding=_finding(), action=action, base_severity=base, severity=base,
        confidence_band=ConfidenceBand.HIGH, rule_kind="banned", matched="RSA",
    )


def test_policy_mode_trips_on_fail_only() -> None:
    decisions = [
        _decision(RuleAction.ALLOW, Severity.INFO),
        _decision(RuleAction.WARN, Severity.MEDIUM),
    ]
    assert gate(decisions) is None
    decisions.append(_decision(RuleAction.FAIL, Severity.CRITICAL))
    assert gate(decisions) == Severity.CRITICAL


def test_policy_mode_strict_upgrades_warn_to_fail() -> None:
    decisions = [_decision(RuleAction.WARN, Severity.MEDIUM)]
    assert gate(decisions) is None
    assert gate(decisions, strict=True) == Severity.MEDIUM


def test_severity_mode_reads_base_severity_threshold() -> None:
    warn_high = _decision(RuleAction.WARN, Severity.HIGH)
    assert gate([warn_high], fail_on="high") == Severity.HIGH
    assert gate([warn_high], fail_on="critical") is None
    # approved findings never trip a severity gate
    assert gate([_decision(RuleAction.ALLOW, Severity.CRITICAL)], fail_on="info") is None


def test_gate_returns_worst_tripping_severity() -> None:
    decisions = [
        _decision(RuleAction.FAIL, Severity.HIGH),
        _decision(RuleAction.FAIL, Severity.CRITICAL),
        _decision(RuleAction.FAIL, Severity.MEDIUM),
    ]
    assert gate(decisions) == Severity.CRITICAL


def test_gate_rejects_unknown_fail_on() -> None:
    with pytest.raises(ValueError, match="fail_on"):
        gate([], fail_on="sometimes")


def test_acceptance_fail_on_high_trips_on_rsa_at_low_confidence() -> None:
    # Acceptance criterion (03): the gate reads base_severity, never the
    # demoted UI severity — RSA at 0.4 confidence demotes to MEDIUM for
    # display but still gates as CRITICAL.
    policy = load_default_policy("cryptoct-default")
    decisions = evaluate([_finding(conf=0.4)], policy)
    assert decisions[0].severity == Severity.MEDIUM
    assert gate(decisions, fail_on="high") == Severity.CRITICAL
