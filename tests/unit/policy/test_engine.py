import pytest

from pqcheck.models import ConfidenceBand, Severity
from pqcheck.policy.engine import confidence_to_band, demote
from pqcheck.policy.schema import SeverityRuleAction


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
