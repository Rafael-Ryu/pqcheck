from pathlib import Path

import pytest

from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoFinding,
    RuleAction,
    Severity,
    SourceLocation,
)
from pqcheck.policy.engine import confidence_to_band, demote, evaluate, rule_matches
from pqcheck.policy.loader import load_default_policy
from pqcheck.policy.schema import AlgorithmRule, PolicyFamily, SeverityRuleAction


@pytest.mark.parametrize("conf,band", [
    (1.0, ConfidenceBand.HIGH), (0.8, ConfidenceBand.HIGH),
    (0.79, ConfidenceBand.MEDIUM), (0.5, ConfidenceBand.MEDIUM),
    (0.49, ConfidenceBand.LOW), (0.0, ConfidenceBand.LOW),
])
def test_confidence_to_band_cutoffs(conf, band):
    assert confidence_to_band(conf) == band


@pytest.mark.parametrize("base,action,expected", [
    (Severity.CRITICAL, SeverityRuleAction.AS_DECLARED, Severity.CRITICAL),
    (Severity.CRITICAL, SeverityRuleAction.DEMOTE_ONE_TIER, Severity.HIGH),
    (Severity.CRITICAL, SeverityRuleAction.DEMOTE_TWO_TIERS, Severity.MEDIUM),
    (Severity.LOW, SeverityRuleAction.DEMOTE_TWO_TIERS, Severity.INFO),  # floors
])
def test_demote_tiers(base, action, expected):
    assert demote(base, action) == expected


def _loc() -> SourceLocation:
    return SourceLocation(path=Path("a.py"), line=1, column=0)


def _find(algo: str, fam: AlgorithmFamily, **kw: object) -> CryptoFinding:
    return CryptoFinding(algorithm=algo, family=fam, location=_loc(),
                         evidence="e", detector_id="t", **kw)  # type: ignore[arg-type]


def test_rule_matches_family_and_algorithm_case_insensitive():
    rule = AlgorithmRule(
        family=PolicyFamily.ASYMMETRIC_ENCRYPTION, algorithm="RSA", action=RuleAction.FAIL
    )
    assert rule_matches(rule, _find("rsa", AlgorithmFamily.ASYMMETRIC_ENCRYPTION))
    assert not rule_matches(rule, _find("ECDSA", AlgorithmFamily.SIGNATURE))


def test_rule_matches_refines_on_key_size_curve_mode():
    aes128 = AlgorithmRule(family=PolicyFamily.SYMMETRIC_CIPHER, algorithm="AES",
                           parameter_sets=["128"], action=RuleAction.FAIL)
    assert rule_matches(aes128, _find("AES", AlgorithmFamily.SYMMETRIC_CIPHER, key_size=128))
    assert not rule_matches(aes128, _find("AES", AlgorithmFamily.SYMMETRIC_CIPHER, key_size=256))

    ecb = AlgorithmRule(family=PolicyFamily.SYMMETRIC_CIPHER, algorithm="AES",
                        modes=["ECB", "CBC"], action=RuleAction.WARN)
    assert rule_matches(ecb, _find("AES", AlgorithmFamily.SYMMETRIC_CIPHER, mode="ECB"))
    assert not rule_matches(ecb, _find("AES", AlgorithmFamily.SYMMETRIC_CIPHER, mode="GCM"))


def _f(algo: str, fam: AlgorithmFamily, conf: float, **kw: object) -> CryptoFinding:
    return CryptoFinding(algorithm=algo, family=fam, confidence=conf,
                         location=SourceLocation(path=Path("a.py"), line=1, column=0),
                         evidence="e", detector_id="t", **kw)  # type: ignore[arg-type]


def test_evaluate_banned_rsa_low_confidence_keeps_base_critical_demotes_ui():
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, 0.4)], policy)
    assert d.rule_kind == "banned"
    assert d.action == RuleAction.FAIL
    assert d.base_severity == Severity.CRITICAL          # gate reads this
    assert d.confidence_band == ConfidenceBand.LOW
    assert d.severity == Severity.MEDIUM                 # demote-two-tiers, UI-only


def test_evaluate_approved_aes256_gcm_is_allow_info():
    policy = load_default_policy("cryptoct-default")
    finding = _f("AES", AlgorithmFamily.SYMMETRIC_CIPHER, 1.0, key_size=256, mode="GCM")
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW
    assert d.base_severity == Severity.INFO


def test_evaluate_unmatched_uses_default_action():
    policy = load_default_policy("cryptoct-default")  # default-action: warn
    [d] = evaluate([_f("Whirlpool", AlgorithmFamily.HASH, 0.9)], policy)
    assert d.rule_kind == "default"
    assert d.action == RuleAction.WARN
    assert d.matched == "default-action"


def test_evaluate_does_not_auto_apply_exception_to_rsa():
    # default policy has EXC-001 (RSA under github-app-jwt). A bare RSA finding
    # must still FAIL — the exception is audit metadata, not an auto-pass.
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, 0.95)], policy)
    assert d.action == RuleAction.FAIL
    assert d.rule_kind == "banned"
    assert d.exception_id == "EXC-001"  # recorded for audit, disposition unchanged
