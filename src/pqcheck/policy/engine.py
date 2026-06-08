"""Evaluate detector findings against a CryptoPolicy.

Pure, I/O-free: takes findings + a parsed policy, returns one PolicyDecision
per finding. The scanner calls this; the CLI gates on the results.
"""

from __future__ import annotations

from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoFinding,
    PolicyDecision,
    RuleAction,
    Severity,
)
from pqcheck.policy.schema import AlgorithmRule, CryptoPolicy, PolicyFamily, SeverityRuleAction

_SEVERITY_ORDER: list[Severity] = list(Severity)  # INFO .. CRITICAL

_BAND_HIGH_THRESHOLD = 0.8
_BAND_MEDIUM_THRESHOLD = 0.5

_FAMILY_MAP: dict[AlgorithmFamily, PolicyFamily | None] = {
    AlgorithmFamily.KEM: PolicyFamily.KEM,
    AlgorithmFamily.SIGNATURE: PolicyFamily.SIGNATURE,
    AlgorithmFamily.SYMMETRIC_CIPHER: PolicyFamily.SYMMETRIC_CIPHER,
    AlgorithmFamily.AEAD: PolicyFamily.SYMMETRIC_CIPHER,
    AlgorithmFamily.HASH: PolicyFamily.HASH,
    AlgorithmFamily.MAC: PolicyFamily.MAC,
    AlgorithmFamily.KDF: PolicyFamily.KDF,
    AlgorithmFamily.KEY_AGREEMENT: PolicyFamily.KEY_AGREEMENT,
    AlgorithmFamily.ASYMMETRIC_ENCRYPTION: PolicyFamily.ASYMMETRIC_ENCRYPTION,
    AlgorithmFamily.RNG: None,
}


def confidence_to_band(confidence: float) -> ConfidenceBand:
    if confidence >= _BAND_HIGH_THRESHOLD:
        return ConfidenceBand.HIGH
    if confidence >= _BAND_MEDIUM_THRESHOLD:
        return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


def demote(severity: Severity, action: SeverityRuleAction) -> Severity:
    idx = _SEVERITY_ORDER.index(severity)
    if action == SeverityRuleAction.DEMOTE_ONE_TIER:
        idx = max(0, idx - 1)
    elif action == SeverityRuleAction.DEMOTE_TWO_TIERS:
        idx = max(0, idx - 2)
    return _SEVERITY_ORDER[idx]


def rule_matches(rule: AlgorithmRule, finding: CryptoFinding) -> bool:
    if _FAMILY_MAP.get(finding.family) != rule.family:
        return False
    if rule.algorithm.upper() != finding.algorithm.upper():
        return False
    if rule.parameter_sets is not None:
        token = str(finding.key_size) if finding.key_size is not None else None
        if token not in rule.parameter_sets:
            return False
    if rule.curves is not None and finding.curve not in rule.curves:
        return False
    # `context` (standalone / new-code / without-aead) needs usage-context the
    # detector does not emit in v0.1; context-scoped rules are matched on
    # family+algorithm+params only. Documented limitation, not a silent gap.
    return rule.modes is None or finding.mode in rule.modes


_DEFAULT_BASE = Severity.MEDIUM  # base for default-action (unmatched) findings


def _band_action(policy: CryptoPolicy) -> dict[ConfidenceBand, SeverityRuleAction]:
    return {r.confidence_band: r.action for r in policy.spec.severity_rules}


def _exception_id(policy: CryptoPolicy, finding: CryptoFinding) -> str | None:
    for exc in policy.spec.exceptions:
        if exc.banned_algorithm and exc.banned_algorithm.upper() == finding.algorithm.upper():
            return exc.id
    return None


def _decide(finding: CryptoFinding, policy: CryptoPolicy,
            band_action: dict[ConfidenceBand, SeverityRuleAction]) -> PolicyDecision:
    band = confidence_to_band(finding.confidence)
    sev_action = band_action.get(band, SeverityRuleAction.AS_DECLARED)

    for rule in policy.spec.banned:
        if rule_matches(rule, finding):
            base = rule.severity or Severity.HIGH
            return PolicyDecision(
                finding=finding, action=rule.action, base_severity=base,
                severity=demote(base, sev_action), confidence_band=band,
                rule_kind="banned", matched=rule.algorithm, reason=rule.reason,
                exception_id=_exception_id(policy, finding),
            )
    for rule in policy.spec.approved:
        if rule_matches(rule, finding):
            return PolicyDecision(
                finding=finding, action=RuleAction.ALLOW, base_severity=Severity.INFO,
                severity=Severity.INFO, confidence_band=band,
                rule_kind="approved", matched=rule.algorithm, reason=rule.reason,
            )
    return PolicyDecision(
        finding=finding, action=policy.spec.default_action, base_severity=_DEFAULT_BASE,
        severity=demote(_DEFAULT_BASE, sev_action), confidence_band=band,
        rule_kind="default", matched="default-action", reason=None,
    )


def evaluate(findings: list[CryptoFinding], policy: CryptoPolicy) -> list[PolicyDecision]:
    band_action = _band_action(policy)
    return [_decide(f, policy, band_action) for f in findings]
