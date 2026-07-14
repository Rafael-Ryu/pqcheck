from datetime import date
from pathlib import Path

import pytest

from pqcheck.detectors.go_detector import detect_go_file
from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoFinding,
    QuantumRisk,
    RuleAction,
    Severity,
    SourceLocation,
)
from pqcheck.policy.engine import (
    confidence_to_band,
    demote,
    evaluate,
    gate,
    rule_matches,
    unevaluated_constructs,
)
from pqcheck.policy.loader import load_default_policy
from pqcheck.policy.schema import (
    AlgorithmRule,
    CryptoPolicy,
    PolicyFamily,
    PolicyMetadata,
    PolicySpec,
    SeverityRuleAction,
)


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


def test_rule_matches_refines_on_paddings():
    pkcs1v15 = AlgorithmRule(family=PolicyFamily.ASYMMETRIC_ENCRYPTION, algorithm="RSA",
                             paddings=["PKCS1v15", "OAEP-SHA1"], action=RuleAction.FAIL)
    assert rule_matches(
        pkcs1v15, _find("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, padding="PKCS1v15")
    )
    assert not rule_matches(
        pkcs1v15, _find("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, padding="OAEP-SHA256")
    )
    assert not rule_matches(pkcs1v15, _find("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION))


def test_rule_matches_rng_family_maps_to_policy_rng():
    rule = AlgorithmRule(family=PolicyFamily.RNG, algorithm="MATH-RAND", action=RuleAction.WARN)
    assert rule_matches(rule, _find("MATH-RAND", AlgorithmFamily.RNG))


def test_rule_matches_parameter_sets_below_threshold():
    rule = AlgorithmRule(family=PolicyFamily.KDF, algorithm="PBKDF2",
                         parameter_sets_below=600000, action=RuleAction.FAIL)
    assert rule_matches(rule, _find("PBKDF2", AlgorithmFamily.KDF, key_size=100000))
    assert not rule_matches(rule, _find("PBKDF2", AlgorithmFamily.KDF, key_size=600000))
    assert not rule_matches(rule, _find("PBKDF2", AlgorithmFamily.KDF, key_size=650000))


def test_rule_matches_parameter_sets_below_no_match_without_literal_key_size():
    # None (variable/computed argument the detector could not extract) and a
    # str (a PQC parameter-set identifier, never a KDF cost) both fail to
    # match a numeric threshold rule -- the finding must fall through to
    # whatever else would have matched, not silently trip a threshold it
    # cannot actually evaluate.
    rule = AlgorithmRule(family=PolicyFamily.KDF, algorithm="PBKDF2",
                         parameter_sets_below=600000, action=RuleAction.FAIL)
    assert not rule_matches(rule, _find("PBKDF2", AlgorithmFamily.KDF, key_size=None))
    assert not rule_matches(rule, _find("PBKDF2", AlgorithmFamily.KDF, key_size="768"))


def test_rule_matches_parameter_sets_below_composes_with_other_filters():
    rule = AlgorithmRule(family=PolicyFamily.KDF, algorithm="PBKDF2",
                         parameter_sets_below=600000, hash=["SHA-256"], action=RuleAction.FAIL)
    # `hash` is not checked by rule_matches (no detector emits it for KDF
    # findings today; same documented gap as `params`/`context`), so only the
    # threshold clause actually gates here -- composability means the rule
    # object accepts both fields without erroring, not that every field is
    # wired into matching yet.
    assert rule_matches(rule, _find("PBKDF2", AlgorithmFamily.KDF, key_size=1000))


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


def test_evaluate_sha512_unmatched_deliberately_warns_despite_quantum_safe():
    # SHA-512 is QuantumRisk.SAFE (models._QUANTUM_MAP) but the policy's approved
    # hash list is curated to {SHA-256, SHA-384} per plan 02 §2.4 — a minimal
    # 8-algorithm set, not "every hash Grover doesn't break". SHA-512 therefore
    # falls through to default-action WARN, same as any other unlisted hash.
    # This is deliberate, not a gap: expanding the approved set is customer-demand
    # driven (plan 02 §2 preamble), not preemptive.
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("SHA-512", AlgorithmFamily.HASH, 0.9)], policy)
    assert d.finding.quantum_risk == QuantumRisk.SAFE
    assert d.rule_kind == "default"
    assert d.action == RuleAction.WARN
    assert d.matched == "default-action"


def test_evaluate_ml_kem_768_via_kyber_py_is_allow_info():
    # kyber-py bakes the parameter set into key_size (see algorithms.py) so
    # this reaches the same approved/info disposition as the Go
    # mlkem.GenerateKey768 path.
    policy = load_default_policy("cryptoct-default")
    finding = _f("ML-KEM", AlgorithmFamily.KEM, 1.0, key_size=768)
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW
    assert d.base_severity == Severity.INFO


def test_evaluate_go_mlkem_findings_are_allow_info(tmp_path):
    # End-to-end for issue #217: the Go catalog bakes the parameter set into
    # the crypto/mlkem entries, so real detector findings — not hand-built
    # ones — match the approved parameter-sets rule instead of falling to
    # default/warn.
    src = tmp_path / "main.go"
    src.write_text(
        'package m\nimport "crypto/mlkem"\n'
        "func f() { mlkem.GenerateKey768(); mlkem.GenerateKey1024() }\n"
    )
    findings = detect_go_file(src)
    assert [f.key_size for f in findings] == [768, 1024]
    policy = load_default_policy("cryptoct-default")
    decisions = evaluate(findings, policy)
    assert all(d.rule_kind == "approved" for d in decisions)
    assert all(d.action == RuleAction.ALLOW for d in decisions)
    assert all(d.base_severity == Severity.INFO for d in decisions)


def test_evaluate_ml_dsa_65_is_allow_info():
    policy = load_default_policy("cryptoct-default")
    finding = _f("ML-DSA", AlgorithmFamily.SIGNATURE, 1.0, key_size=65)
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW


def test_evaluate_slh_dsa_sha2_128s_is_allow_info():
    policy = load_default_policy("cryptoct-default")
    finding = _f("SLH-DSA", AlgorithmFamily.SIGNATURE, 1.0, key_size="SHA2-128s")
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW


def test_evaluate_slh_dsa_other_parameter_set_falls_to_default():
    # Only SHA2-128s is policy-approved (02 §13); SHAKE-128f is a valid FIPS
    # 205 parameter set but not the curated one, so it stays default/warn —
    # same "curated subset, not every safe option" pattern as SHA-512.
    policy = load_default_policy("cryptoct-default")
    finding = _f("SLH-DSA", AlgorithmFamily.SIGNATURE, 1.0, key_size="SHAKE-128f")
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "default"
    assert d.action == RuleAction.WARN


def test_evaluate_ml_kem_unknown_variant_from_oqs_falls_to_default():
    # oqs.KeyEncapsulation's variant is a runtime string; the detector cannot
    # prove which parameter set it selects, so key_size is None and the
    # finding cannot match a parameter-sets-scoped approved rule. Honest
    # default/warn, not a silent approve.
    policy = load_default_policy("cryptoct-default")
    finding = _f("ML-KEM", AlgorithmFamily.KEM, 1.0)
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "default"
    assert d.action == RuleAction.WARN


@pytest.mark.parametrize(
    "algo,weak,strong",
    [("PBKDF2", 100000, 650000), ("SCRYPT", 65536, 131072), ("BCRYPT", 4, 12)],
)
def test_evaluate_weak_kdf_parameter_is_banned_fail_high(algo, weak, strong):
    # cryptoct-default is a strict-profile file: fail+high per the B2 rules
    # (mirrors AES-128's fail+high pattern in the same file).
    policy = load_default_policy("cryptoct-default")
    [weak_decision] = evaluate([_f(algo, AlgorithmFamily.KDF, 1.0, key_size=weak)], policy)
    assert weak_decision.rule_kind == "banned"
    assert weak_decision.action == RuleAction.FAIL
    assert weak_decision.base_severity == Severity.HIGH

    [strong_decision] = evaluate([_f(algo, AlgorithmFamily.KDF, 1.0, key_size=strong)], policy)
    assert strong_decision.rule_kind == "default"


@pytest.mark.parametrize("algo", ["PBKDF2", "SCRYPT", "BCRYPT"])
def test_evaluate_weak_kdf_parameter_variable_arg_falls_to_default(algo):
    # A variable/computed cost argument extracts no literal (key_size=None),
    # so the threshold rule cannot evaluate it and the finding falls through
    # to the same default-action every other unmatched KDF finding gets --
    # it must not silently pass as "approved" nor silently fail as "banned".
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f(algo, AlgorithmFamily.KDF, 1.0)], policy)
    assert d.rule_kind == "default"
    assert d.action == RuleAction.WARN


def test_evaluate_weak_kdf_parameter_advisory_profile_is_warn_high():
    policy = load_default_policy("cryptoct-advisory")
    [d] = evaluate([_f("PBKDF2", AlgorithmFamily.KDF, 1.0, key_size=100000)], policy)
    assert d.rule_kind == "banned"
    assert d.action == RuleAction.WARN
    assert d.base_severity == Severity.HIGH


def test_evaluate_argon2_still_approved_alongside_pbkdf2_threshold_rule():
    # The new PBKDF2/SCRYPT/BCRYPT threshold rules must not shadow the
    # pre-existing ARGON2 approved rule -- different algorithm, same family.
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("ARGON2", AlgorithmFamily.KDF, 1.0)], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW


def test_evaluate_argon2_is_allow_info():
    # Detector canonical is "ARGON2" (nacl.pwhash argon2id/argon2i collapse
    # to it); the approved rule matches on that, not the display name
    # "Argon2id" — see the fix in policy/defaults/*.yaml.
    policy = load_default_policy("cryptoct-default")
    finding = _f("ARGON2", AlgorithmFamily.KDF, 1.0)
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW
    assert d.base_severity == Severity.INFO


def test_evaluate_xsalsa20_poly1305_stays_default_warn():
    # XSALSA20-POLY1305 (pynacl SecretBox) is quantum-safe but not one of
    # the 8 curated algorithms (plan 02 §2) — same deliberate-gap precedent
    # as SHA-512. It stays outside the approved list, not banned.
    policy = load_default_policy("cryptoct-default")
    finding = _f("XSALSA20-POLY1305", AlgorithmFamily.AEAD, 1.0)
    [d] = evaluate([finding], policy)
    assert d.finding.quantum_risk == QuantumRisk.SAFE
    assert d.rule_kind == "default"
    assert d.action == RuleAction.WARN


def test_evaluate_does_not_auto_apply_exception_to_rsa():
    # default policy has EXC-001 (RSA under github-app-jwt). A bare RSA finding
    # must still FAIL — the exception is audit metadata, not an auto-pass.
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, 0.95)], policy)
    assert d.action == RuleAction.FAIL
    assert d.rule_kind == "banned"
    assert d.exception_id == "EXC-001"  # recorded for audit, disposition unchanged


def test_rule_matches_size_scoped_no_match_when_key_size_absent():
    aes128 = AlgorithmRule(family=PolicyFamily.SYMMETRIC_CIPHER, algorithm="AES",
                           parameter_sets=["128"], action=RuleAction.FAIL)
    # key_size absent: the token becomes None, which is not in ["128"]
    assert not rule_matches(aes128, _find("AES", AlgorithmFamily.SYMMETRIC_CIPHER))


def test_rule_matches_curves_scoped_no_match_when_curve_differs():
    eddsa = AlgorithmRule(family=PolicyFamily.SIGNATURE, algorithm="EdDSA",
                          curves=["Ed25519"], action=RuleAction.FAIL)
    assert not rule_matches(eddsa, _find("EdDSA", AlgorithmFamily.SIGNATURE, curve="Ed448"))


def test_evaluate_banned_ecdsa_default_policy_exception_id_is_none():
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("ECDSA", AlgorithmFamily.SIGNATURE, 0.9)], policy)
    assert d.rule_kind == "banned"
    assert d.action == RuleAction.FAIL
    assert d.exception_id is None


def test_banned_rule_without_severity_falls_back_to_high():
    rule = AlgorithmRule(family=PolicyFamily.ASYMMETRIC_ENCRYPTION, algorithm="RSA",
                         action=RuleAction.FAIL)
    policy = CryptoPolicy(
        apiVersion="pqcheck.cryptoct.com/v1", kind="CryptoPolicy",
        metadata=PolicyMetadata(name="t", version="0.0.1", publisher="t",
                                applies_to="t", effective_from=date.today(),
                                review_date=date.today()),
        spec=PolicySpec(default_action=RuleAction.WARN, banned=[rule]),
    )
    [d] = evaluate([_f("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, 1.0)], policy)
    assert d.base_severity == Severity.HIGH
    assert d.rule_kind == "banned"


def test_evaluate_accepts_a_tuple_of_findings():
    # ScanResult.findings is a tuple; evaluate must accept any Sequence, not only list.
    policy = load_default_policy("cryptoct-default")
    decisions = evaluate((_f("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, 0.9),), policy)
    assert len(decisions) == 1


def test_strict_gate_trips_on_unknown_quantum_risk():
    # Whirlpool is unbanned/unapproved in the default policy, so it hits
    # default-action WARN; strict must also trip it via UNKNOWN quantum_risk.
    policy = load_default_policy("cryptoct-default")
    decisions = evaluate([_f("Whirlpool", AlgorithmFamily.HASH, 0.9)], policy)
    assert decisions[0].finding.quantum_risk == QuantumRisk.UNKNOWN
    assert gate(decisions, strict=True) is not None


def test_non_strict_gate_does_not_trip_on_unknown_quantum_risk():
    policy = load_default_policy("cryptoct-default")
    decisions = evaluate([_f("Whirlpool", AlgorithmFamily.HASH, 0.9)], policy)
    assert gate(decisions, strict=False) is None


def test_strict_gate_does_not_trip_when_unknown_algorithm_is_explicitly_approved():
    rule = AlgorithmRule(
        family=PolicyFamily.HASH, algorithm="Whirlpool", action=RuleAction.ALLOW
    )
    policy = CryptoPolicy(
        apiVersion="pqcheck.cryptoct.com/v1", kind="CryptoPolicy",
        metadata=PolicyMetadata(name="t", version="0.0.1", publisher="t",
                                applies_to="t", effective_from=date.today(),
                                review_date=date.today()),
        spec=PolicySpec(default_action=RuleAction.WARN, approved=[rule]),
    )
    decisions = evaluate([_f("Whirlpool", AlgorithmFamily.HASH, 0.9)], policy)
    assert decisions[0].rule_kind == "approved"
    assert gate(decisions, strict=True) is None


def test_evaluate_banned_medium_confidence_demotes_one_tier():
    # AES-128 is banned at HIGH; 0.6 confidence is the MEDIUM band -> demote-one-tier -> MEDIUM.
    policy = load_default_policy("cryptoct-default")
    [d] = evaluate([_f("AES", AlgorithmFamily.SYMMETRIC_CIPHER, 0.6, key_size=128)], policy)
    assert d.rule_kind == "banned"
    assert d.base_severity == Severity.HIGH
    assert d.confidence_band == ConfidenceBand.MEDIUM
    assert d.severity == Severity.MEDIUM


@pytest.mark.parametrize("policy_name", ["cryptoct-default", "cryptoct-strict"])
@pytest.mark.parametrize(
    "algorithm", ["X25519MLKEM768", "X-WING", "X25519KYBER768-DRAFT"]
)
def test_evaluate_hybrid_kem_is_allow_info_not_default_warn(policy_name, algorithm):
    # Without an approved rule, a HYBRID finding would fall to default-action
    # (warn/fail) — mislabeling the best available TLS key-agreement posture
    # as a policy concern. The approved rule added for W3 must classify it
    # allow/info on both the permissive and the maximum-gate profile.
    policy = load_default_policy(policy_name)
    finding = _f(algorithm, AlgorithmFamily.KEM, 1.0)
    assert finding.quantum_risk == QuantumRisk.HYBRID
    [d] = evaluate([finding], policy)
    assert d.rule_kind == "approved"
    assert d.action == RuleAction.ALLOW
    assert d.base_severity == Severity.INFO


@pytest.mark.parametrize("policy_name", ["cryptoct-default", "cryptoct-strict"])
def test_strict_gate_does_not_trip_on_hybrid_kem_finding(policy_name):
    policy = load_default_policy(policy_name)
    decisions = evaluate([_f("X25519MLKEM768", AlgorithmFamily.KEM, 1.0)], policy)
    assert gate(decisions, strict=True) is None


def test_unevaluated_constructs_on_bundled_default_policy():
    # cryptoct-default declares hash/params/context-scoped rules the v0.1
    # engine cannot evaluate; the CLI surfaces them so the gate is never
    # silently wider-open than the policy reads.
    policy = load_default_policy("cryptoct-default")
    assert unevaluated_constructs(policy) == ["hash", "params"]


def test_unevaluated_constructs_empty_for_fully_evaluated_policy():
    policy = CryptoPolicy(
        apiVersion="pqcheck.cryptoct.com/v1",
        kind="CryptoPolicy",
        metadata=PolicyMetadata(
            name="t", version="1.0.0", publisher="t", applies_to="t",
            effective_from=date(2026, 1, 1), review_date=date(2026, 6, 1),
        ),
        spec=PolicySpec(
            default_action=RuleAction.WARN,
            approved=[AlgorithmRule(
                family=PolicyFamily.SYMMETRIC_CIPHER, algorithm="AES",
                parameter_sets=["256"], action=RuleAction.ALLOW,
            )],
        ),
    )
    assert unevaluated_constructs(policy) == []
