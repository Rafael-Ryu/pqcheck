import pytest

from pqcheck.policy import PolicyError, load_default_policy
from pqcheck.policy.schema import RuleAction

TIERS = ["cryptoct-default", "cryptoct-strict", "cryptoct-advisory"]


def _algo_set(policy, section):
    rules = getattr(policy.spec, section)
    return {(r.family.value, r.algorithm) for r in rules}


@pytest.mark.parametrize("name", TIERS)
def test_default_policy_loads_and_names_match(name):
    policy = load_default_policy(name)
    assert policy.metadata.name == name
    assert policy.metadata.version == "1.0.0"


def test_unknown_default_rejected():
    with pytest.raises(PolicyError):
        load_default_policy("does-not-exist")


def test_all_tiers_share_same_algorithm_sets():
    policies = {n: load_default_policy(n) for n in TIERS}
    approved = [_algo_set(policies[n], "approved") for n in TIERS]
    banned = [_algo_set(policies[n], "banned") for n in TIERS]
    assert approved[0] == approved[1] == approved[2]
    assert banned[0] == banned[1] == banned[2]
    exc = {n: [e.model_dump() for e in p.spec.exceptions] for n, p in policies.items()}
    assert exc["cryptoct-default"] == exc["cryptoct-strict"] == exc["cryptoct-advisory"]
    sr = {n: [r.model_dump() for r in p.spec.severity_rules] for n, p in policies.items()}
    assert sr["cryptoct-default"] == sr["cryptoct-strict"] == sr["cryptoct-advisory"]


def test_tier_gating_differences():
    default = load_default_policy("cryptoct-default")
    strict = load_default_policy("cryptoct-strict")
    advisory = load_default_policy("cryptoct-advisory")
    assert strict.spec.default_action is RuleAction.FAIL
    assert advisory.spec.fail_on == []
    assert all(r.action is RuleAction.WARN for r in advisory.spec.banned)
    assert any(r.action is RuleAction.FAIL for r in default.spec.banned)
