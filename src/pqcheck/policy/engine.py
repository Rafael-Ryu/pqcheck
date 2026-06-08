"""Evaluate detector findings against a CryptoPolicy.

Pure, I/O-free: takes findings + a parsed policy, returns one PolicyDecision
per finding. The scanner calls this; the CLI gates on the results.
"""

from __future__ import annotations

from pqcheck.models import AlgorithmFamily, ConfidenceBand, Severity
from pqcheck.policy.schema import PolicyFamily, SeverityRuleAction

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
