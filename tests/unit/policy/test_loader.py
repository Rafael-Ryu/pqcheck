from pathlib import Path

import pytest

from pqcheck.policy import CryptoPolicy, PolicyError, load_policy

FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "policy"


def test_load_valid_policy():
    policy = load_policy(FIXTURES / "valid_minimal.yaml")
    assert isinstance(policy, CryptoPolicy)
    assert policy.metadata.name == "fixture-minimal"


def test_missing_file_raises_policy_error():
    with pytest.raises(PolicyError):
        load_policy(FIXTURES / "does_not_exist.yaml")


def test_malformed_yaml_raises_policy_error():
    with pytest.raises(PolicyError):
        load_policy(FIXTURES / "malformed.yaml")


def test_non_policy_document_raises_policy_error():
    with pytest.raises(PolicyError):
        load_policy(FIXTURES / "not_a_policy.yaml")


def test_alias_bomb_rejected_not_expanded():
    # Must fail fast on the anchor/alias, never expand into gigabytes.
    with pytest.raises(PolicyError):
        load_policy(FIXTURES / "alias_bomb.yaml")
