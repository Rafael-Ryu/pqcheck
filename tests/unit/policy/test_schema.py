import pytest
from pydantic import ValidationError

from pqcheck.models import ConfidenceBand
from pqcheck.models import RuleAction as ModelsRuleAction
from pqcheck.policy.schema import (
    AlgorithmRule,
    CryptoPolicy,
    HybridRule,
    PolicyException,
    PolicyFamily,
    PolicyMetadata,
    PolicySpec,
    RuleAction,
    SeverityRule,
    SeverityRuleAction,
    SeveritySelector,
)


def test_algorithm_rule_accepts_kebab_keys():
    rule = AlgorithmRule.model_validate(
        {"family": "symmetric-cipher", "algorithm": "AES",
         "parameter-sets": ["256"], "modes": ["GCM"], "action": "allow"}
    )
    assert rule.parameter_sets == ["256"]
    assert rule.action is RuleAction.ALLOW


def test_algorithm_rule_accepts_parameter_sets_below_kebab_alias():
    rule = AlgorithmRule.model_validate(
        {"family": "kdf", "algorithm": "PBKDF2",
         "parameter-sets-below": 600000, "action": "fail"}
    )
    assert rule.parameter_sets_below == 600000
    assert rule.action is RuleAction.FAIL


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


_FULL_EXCEPTION = {
    "id": "EXC-001",
    "description": "x",
    "adr": "docs/adr/001-x.md",
    "review-date": "2026-12-31",
}


def test_exception_id_pattern_enforced():
    with pytest.raises(ValidationError):
        PolicyException.model_validate({**_FULL_EXCEPTION, "id": "EX-1"})
    ok = PolicyException.model_validate(_FULL_EXCEPTION)
    assert ok.id == "EXC-001"


def test_exception_requires_adr_and_review_date():
    # An exception is where a banned algorithm gets a temporary pass, so it
    # must carry an ADR reference and a review date for the audit trail.
    for missing in ("adr", "review-date"):
        incomplete = {k: v for k, v in _FULL_EXCEPTION.items() if k != missing}
        with pytest.raises(ValidationError):
            PolicyException.model_validate(incomplete)
    ok = PolicyException.model_validate(_FULL_EXCEPTION)
    assert ok.adr == "docs/adr/001-x.md"
    assert ok.review_date.isoformat() == "2026-12-31"


def test_severity_rule_and_selector():
    sr = SeverityRule.model_validate({"confidence-band": "high", "action": "as-declared"})
    assert sr.action.value == "as-declared"
    sel = SeveritySelector.model_validate({"severity": "high", "confidence-band": ["high"]})
    assert sel.confidence_band == ["high"]


_VALID = {
    "apiVersion": "pqcheck.cryptoct.com/v1",
    "kind": "CryptoPolicy",
    "metadata": {
        "name": "cryptoct-default", "version": "1.0.0", "publisher": "CryptoCT",
        "applies-to": "All new code", "effective-from": "2026-05-22",
        "review-date": "2026-11-22",
    },
    "spec": {
        "default-action": "warn",
        "approved": [{"family": "hash", "algorithm": "SHA-256", "action": "allow"}],
        "banned": [{"family": "hash", "algorithm": "MD5", "action": "fail",
                    "severity": "critical", "reason": "Collision-broken"}],
        "severity-rules": [{"confidence-band": "high", "action": "as-declared"}],
        "fail-on": [{"severity": "critical"}],
    },
}


def test_valid_policy_parses():
    policy = CryptoPolicy.model_validate(_VALID)
    assert policy.metadata.name == "cryptoct-default"
    assert policy.spec.banned[0].algorithm == "MD5"


def test_wrong_api_version_rejected():
    bad = {**_VALID, "apiVersion": "v2"}
    with pytest.raises(ValidationError):
        CryptoPolicy.model_validate(bad)


def test_wrong_kind_rejected():
    bad = {**_VALID, "kind": "Pod"}
    with pytest.raises(ValidationError):
        CryptoPolicy.model_validate(bad)


def test_invalid_semver_rejected():
    bad = {**_VALID, "metadata": {**_VALID["metadata"], "version": "1.0"}}
    with pytest.raises(ValidationError):
        CryptoPolicy.model_validate(bad)


def test_missing_metadata_field_rejected():
    md = {k: v for k, v in _VALID["metadata"].items() if k != "version"}
    with pytest.raises(ValidationError):
        CryptoPolicy.model_validate({**_VALID, "metadata": md})


def test_rule_action_is_reexported_from_schema():
    assert RuleAction is ModelsRuleAction
    assert {a.value for a in RuleAction} == {"allow", "warn", "fail"}


def test_policyspec_rejects_banned_rule_with_allow_action():
    rule = AlgorithmRule(
        family=PolicyFamily.ASYMMETRIC_ENCRYPTION, algorithm="RSA", action=RuleAction.ALLOW
    )
    with pytest.raises(ValidationError, match="must use action fail or warn"):
        PolicySpec(default_action=RuleAction.WARN, banned=[rule])


def test_policyspec_rejects_approved_rule_with_non_allow_action():
    rule = AlgorithmRule(family=PolicyFamily.HASH, algorithm="SHA-256", action=RuleAction.FAIL)
    with pytest.raises(ValidationError, match="must use action allow"):
        PolicySpec(default_action=RuleAction.WARN, approved=[rule])


def test_metadata_rejects_review_date_before_effective_from():
    with pytest.raises(ValidationError, match="review-date"):
        PolicyMetadata(
            name="t", version="1.0.0", publisher="t", applies_to="t",
            effective_from="2030-01-01", review_date="2020-01-01",
        )


def test_metadata_accepts_review_date_on_or_after_effective_from():
    same_day = PolicyMetadata(
        name="t", version="1.0.0", publisher="t", applies_to="t",
        effective_from="2026-05-22", review_date="2026-05-22",
    )
    assert same_day.review_date == same_day.effective_from
    later = PolicyMetadata(
        name="t", version="1.0.0", publisher="t", applies_to="t",
        effective_from="2026-05-22", review_date="2026-11-22",
    )
    assert later.review_date > later.effective_from


def test_policyspec_rejects_duplicate_confidence_band_in_severity_rules():
    rules = [
        SeverityRule(
            confidence_band=ConfidenceBand.HIGH, action=SeverityRuleAction.AS_DECLARED
        ),
        SeverityRule(
            confidence_band=ConfidenceBand.HIGH,
            action=SeverityRuleAction.DEMOTE_ONE_TIER,
        ),
    ]
    with pytest.raises(ValidationError, match="duplicate confidence-band"):
        PolicySpec(default_action=RuleAction.WARN, severity_rules=rules)
