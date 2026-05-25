import pytest
from pydantic import ValidationError

from pqcheck.policy.schema import (
    AlgorithmRule,
    HybridRule,
    PolicyException,
    RuleAction,
    SeverityRule,
    SeveritySelector,
)


def test_algorithm_rule_accepts_kebab_keys():
    rule = AlgorithmRule.model_validate(
        {"family": "symmetric-cipher", "algorithm": "AES",
         "parameter-sets": ["256"], "modes": ["GCM"], "action": "allow"}
    )
    assert rule.parameter_sets == ["256"]
    assert rule.action is RuleAction.ALLOW


def test_algorithm_rule_rejects_bad_action():
    with pytest.raises(ValidationError):
        AlgorithmRule.model_validate({"family": "hash", "algorithm": "MD5", "action": "nuke"})


def test_algorithm_rule_rejects_unknown_key():
    with pytest.raises(ValidationError):
        AlgorithmRule.model_validate({"family": "hash", "algorithm": "MD5", "modez": ["x"]})


def test_hybrid_rule_round_trips():
    rule = HybridRule.model_validate(
        {"context": "tls-external", "classical": ["X25519"],
         "pqc": ["ML-KEM-768"], "action": "allow"}
    )
    assert rule.pqc == ["ML-KEM-768"]


def test_exception_id_pattern_enforced():
    with pytest.raises(ValidationError):
        PolicyException.model_validate({"id": "EX-1", "description": "x"})
    ok = PolicyException.model_validate({"id": "EXC-001", "description": "x"})
    assert ok.id == "EXC-001"


def test_severity_rule_and_selector():
    sr = SeverityRule.model_validate({"confidence-band": "high", "action": "as-declared"})
    assert sr.action.value == "as-declared"
    sel = SeveritySelector.model_validate({"severity": "high", "confidence-band": ["high"]})
    assert sel.confidence_band == ["high"]
