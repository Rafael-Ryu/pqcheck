from pathlib import Path

import pytest

from pqcheck.policy import CryptoPolicy, PolicyError, load_default_policy, load_policy

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


def test_scalar_document_raises_policy_error():
    with pytest.raises(PolicyError, match="must be a mapping"):
        load_policy(FIXTURES / "scalar.yaml")


def test_python_object_tag_rejected():
    with pytest.raises(PolicyError):
        load_policy(FIXTURES / "python_object.yaml")


def test_deeply_nested_yaml_raises_policy_error(tmp_path):
    bomb = tmp_path / "deep.yaml"
    bomb.write_text("a: " + "[" * 3000 + "]" * 3000)
    with pytest.raises(PolicyError):
        load_policy(bomb)


@pytest.mark.parametrize("evil", ["../evil", "../../etc/passwd", "..", ".", "a/b"])
def test_load_default_policy_rejects_traversal(evil):
    with pytest.raises(PolicyError):
        load_default_policy(evil)


def test_load_default_policy_over_long_name_raises_policy_error():
    # Name passes the allowlist but yields a path over the filename limit; the
    # underlying OSError must surface as PolicyError, not leak (issue #56).
    with pytest.raises(PolicyError):
        load_default_policy("a" * 5000)


def test_load_policy_non_utf8_file_raises_policy_error(tmp_path):
    # A non-UTF-8 policy file makes read_text raise UnicodeDecodeError, which is
    # a ValueError (not an OSError). It must surface as PolicyError, not leak a
    # traceback through the CLI.
    f = tmp_path / "latin1.yaml"
    f.write_bytes(b"metadata:\n  name: caf\xe9\n")
    with pytest.raises(PolicyError):
        load_policy(f)


def test_duplicate_mapping_key_rejected():
    # YAML's last-key-wins would silently erase the banned MD5 rule and still
    # validate — a fail-open policy gate.
    with pytest.raises(PolicyError, match="duplicate key"):
        load_policy(FIXTURES / "duplicate_key.yaml")
