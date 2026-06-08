from pathlib import Path

import pytest

from pqcheck.models import AlgorithmFamily, ConfidenceBand, CryptoFinding, Severity, SourceLocation
from pqcheck.policy.engine import confidence_to_band, demote, rule_matches
from pqcheck.policy.schema import AlgorithmRule, PolicyFamily, RuleAction, SeverityRuleAction


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
