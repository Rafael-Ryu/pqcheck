"""BR vertical policies + the no-dead-semantics invariant for all defaults.

The pitch promised BR-tuned policies; the 2026-06-11 review found they
did not exist and that the shipped defaults referenced semantics the
engine cannot evaluate (`context:` qualifiers, `hybrid-required`,
`fail-on`/`warn-on`/`info-only` selectors). Bundled policies must only
say things the engine actually does — anything else is silent
over-blocking or dead text a customer will read as a feature.
"""

import pytest

from pqcheck.policy.loader import load_default_policy

BR_POLICIES = ("br-bcb-conservative", "br-drex-piloto", "br-vendor-dd")
ALL_BUNDLED = (
    "cryptoct-default", "cryptoct-strict", "cryptoct-advisory", *BR_POLICIES,
)
S3_GAP = {"RIPEMD-160", "Blowfish", "IDEA"}


@pytest.mark.parametrize("name", BR_POLICIES)
def test_br_policy_loads_and_name_matches(name: str) -> None:
    policy = load_default_policy(name)
    assert policy.metadata.name == name


@pytest.mark.parametrize("name", BR_POLICIES)
def test_br_policy_framing_is_honest(name: str) -> None:
    # Review finding C2: no Brazilian regulation mandates crypto inventory
    # today. BR policies must frame alignment/anticipation, never obligation.
    text = load_default_policy(name).metadata.applies_to.lower()
    # Negated forms ("not required by any current regulation") are exactly
    # the honest disclosure we want — only affirmative obligation is banned.
    affirmative = text.replace("not required by", "").replace("not mandated by", "")
    assert "required by" not in affirmative and "mandated by" not in affirmative
    assert any(word in text for word in ("align", "advisory", "anticipat", "forward-looking"))


@pytest.mark.parametrize("name", BR_POLICIES)
def test_br_policies_ban_the_full_s3_set(name: str) -> None:
    banned = {r.algorithm for r in load_default_policy(name).spec.banned}
    assert {"RSA", "ECDSA", "DH", "MD5", "SHA-1", "DES", "3DES", "RC4"} | S3_GAP <= banned


def test_drex_profile_is_the_forward_looking_strictest() -> None:
    policy = load_default_policy("br-drex-piloto")
    banned = {r.algorithm for r in policy.spec.banned}
    assert {"X25519", "X448"} <= banned  # classical-only key agreement
    assert policy.spec.default_action.value == "fail"


def test_vendor_dd_profile_only_warns() -> None:
    policy = load_default_policy("br-vendor-dd")
    assert all(r.action.value == "warn" for r in policy.spec.banned)
    assert policy.spec.default_action.value == "warn"


@pytest.mark.parametrize("name", ALL_BUNDLED)
def test_bundled_policies_carry_no_unevaluable_semantics(name: str) -> None:
    # The engine matches family+algorithm+params only (engine.py: context is
    # not emitted by detectors in v0.1) and gates on decision actions, not on
    # the fail-on/warn-on selector lists. Shipping rules that depend on either
    # would promise behavior the engine does not have.
    policy = load_default_policy(name)
    for rule in (*policy.spec.approved, *policy.spec.banned):
        assert rule.context is None, f"{name}: rule {rule.algorithm} has context"
    assert policy.spec.hybrid_required == []
    assert policy.spec.fail_on == []
    assert policy.spec.warn_on == []
    assert policy.spec.info_only == []
