"""Emit SARIF 2.1.0 from a ScanResult, GitHub Code Scanning compatible.

`message.text` passes through a control-character filter rather than an
HTML sanitizer: bleach-style escaping of `<>&` breaks downstream SARIF
consumers, while raw control characters (ANSI escapes in hostile
evidence strings) are the actual injection vector for terminals and log
viewers.
"""

from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

from pqcheck.models import CryptoFinding, PolicyDecision, RuleAction, ScanResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_FINGERPRINT_KEY = "pqcheckFingerprint/v1"

_LEVEL_BY_ACTION: dict[RuleAction, str] = {
    RuleAction.FAIL: "error",
    RuleAction.WARN: "warning",
    RuleAction.ALLOW: "note",
}


def _sanitize(raw: str) -> str:
    # Strip control (Cc) and format (Cf) characters. Cf covers the bidirectional
    # override codes (U+202A-202E, U+2066-2069) behind Trojan-Source visual
    # spoofing (CVE-2021-42574): evidence text is taken verbatim from untrusted
    # scanned source, so a hostile comment could otherwise reorder how a SARIF
    # consumer renders the finding. Newlines and tabs are kept for readability.
    return "".join(
        c for c in raw if unicodedata.category(c) not in ("Cc", "Cf") or c in ("\n", "\t")
    )


def _relative_uri(path: Path, target: Path) -> str:
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return path.as_posix()


def _fingerprint(finding: CryptoFinding, uri: str) -> str:
    material = "|".join(
        [
            finding.algorithm,
            finding.family.value,
            uri,
            str(finding.location.line),
            finding.detector_id,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def _rule_id(finding: CryptoFinding, decision: PolicyDecision | None) -> str:
    kind = decision.rule_kind if decision is not None else "finding"
    return f"pqcheck/{kind}/{finding.algorithm}"


def _message(finding: CryptoFinding, decision: PolicyDecision | None) -> str:
    parts = [f"{finding.algorithm} ({finding.family.value})"]
    if decision is not None and decision.reason:
        parts.append(decision.reason)
    parts.append(f"evidence: {finding.evidence}")
    return _sanitize(" — ".join(parts))


def _result_entry(
    finding: CryptoFinding,
    decision: PolicyDecision | None,
    target: Path,
    rule_index: int,
) -> dict[str, object]:
    uri = _relative_uri(finding.location.path, target)
    properties: dict[str, object] = {
        "confidence": finding.confidence,
        "quantum_risk": finding.quantum_risk.value,
        "detector_id": finding.detector_id,
    }
    if decision is not None:
        properties["base_severity"] = decision.base_severity.value
        properties["severity"] = decision.severity.value
        properties["confidence_band"] = decision.confidence_band.value
    return {
        "ruleId": _rule_id(finding, decision),
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_ACTION.get(decision.action, "note") if decision else "note",
        "message": {"text": _message(finding, decision)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {
                        "startLine": finding.location.line,
                        # SourceLocation.column is 0-based; SARIF is 1-based.
                        "startColumn": finding.location.column + 1,
                    },
                }
            }
        ],
        "partialFingerprints": {_FINGERPRINT_KEY: _fingerprint(finding, uri)},
        "properties": properties,
    }


def build_sarif(result: ScanResult) -> dict[str, object]:
    decisions: dict[int, PolicyDecision] = {}
    if len(result.policy_decisions) == len(result.findings):
        decisions = dict(enumerate(result.policy_decisions))

    rule_indexes: dict[str, int] = {}
    rules: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    for i, finding in enumerate(result.findings):
        decision = decisions.get(i)
        rule_id = _rule_id(finding, decision)
        if rule_id not in rule_indexes:
            rule_indexes[rule_id] = len(rules)
            short = f"{finding.algorithm} usage detected"
            if decision is not None:
                short = f"{finding.algorithm} is {decision.rule_kind} by policy"
            rules.append({"id": rule_id, "shortDescription": {"text": _sanitize(short)}})
        results.append(_result_entry(finding, decision, result.target, rule_indexes[rule_id]))

    run_properties: dict[str, object] = {}
    if result.policy_id is not None:
        run_properties["policy_id"] = result.policy_id
    if result.errors:
        run_properties["scan_errors"] = list(result.errors)

    run: dict[str, object] = {
        "tool": {
            "driver": {
                "name": "pqcheck",
                "semanticVersion": result.scanner_version,
                "informationUri": "https://github.com/Rafael-Ryu/pqcheck",
                "rules": rules,
            }
        },
        "results": results,
    }
    if run_properties:
        run["properties"] = run_properties

    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }
