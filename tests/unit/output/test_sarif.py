from pathlib import Path
from typing import Any, cast

from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoFinding,
    PolicyDecision,
    RuleAction,
    ScanResult,
    Severity,
    SourceLocation,
)
from pqcheck.output.sarif import build_sarif
from pqcheck.output.sarif_validator import validate_sarif_210


def _finding(**kw: Any) -> CryptoFinding:
    base: dict[str, Any] = {
        "algorithm": "RSA",
        "family": AlgorithmFamily.ASYMMETRIC_ENCRYPTION,
        "location": SourceLocation(path=Path("/repo/src/auth.py"), line=42, column=4),
        "evidence": "rsa.generate_private_key(...)",
        "detector_id": "python-ast",
        "confidence": 0.95,
    }
    base.update(kw)
    return CryptoFinding(**base)


def _decision(finding: CryptoFinding, action: RuleAction) -> PolicyDecision:
    return PolicyDecision(
        finding=finding, action=action,
        base_severity=Severity.CRITICAL, severity=Severity.CRITICAL,
        confidence_band=ConfidenceBand.HIGH, rule_kind="banned",
        matched=finding.algorithm, reason="Shor",
    )


def _result(**kw: Any) -> ScanResult:
    base: dict[str, Any] = {
        "target": Path("/repo"),
        "scanner_version": "0.1.0",
        "findings": (_finding(),),
    }
    base.update(kw)
    return ScanResult(**base)


def _run(doc: dict[str, Any]) -> dict[str, Any]:
    return cast("list[dict[str, Any]]", doc["runs"])[0]


def test_sarif_top_level_shape() -> None:
    doc = build_sarif(_result())
    assert doc["version"] == "2.1.0"
    driver = _run(doc)["tool"]["driver"]
    assert driver["name"] == "pqcheck"
    assert driver["semanticVersion"] == "0.1.0"


def test_levels_follow_policy_action() -> None:
    f = _finding()
    for action, level in [
        (RuleAction.FAIL, "error"),
        (RuleAction.WARN, "warning"),
        (RuleAction.ALLOW, "note"),
    ]:
        doc = build_sarif(_result(policy_decisions=(_decision(f, action),)))
        [res] = _run(doc)["results"]
        assert res["level"] == level


def test_no_policy_results_are_notes_with_finding_rule_ids() -> None:
    doc = build_sarif(_result())
    [res] = _run(doc)["results"]
    assert res["level"] == "note"
    assert res["ruleId"] == "pqcheck/finding/RSA"


def test_location_is_relative_with_one_based_column() -> None:
    doc = build_sarif(_result())
    [res] = _run(doc)["results"]
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/auth.py"
    # SourceLocation.column is 0-based; SARIF startColumn is 1-based.
    assert loc["region"] == {"startLine": 42, "startColumn": 5}


def test_fingerprint_is_stable_and_line_sensitive() -> None:
    doc1 = build_sarif(_result())
    doc2 = build_sarif(_result())
    moved = _finding(location=SourceLocation(path=Path("/repo/src/auth.py"), line=43, column=4))
    doc3 = build_sarif(_result(findings=(moved,)))
    fp = "pqcheckFingerprint/v1"
    [r1], [r2], [r3] = (_run(d)["results"] for d in (doc1, doc2, doc3))
    assert r1["partialFingerprints"][fp] == r2["partialFingerprints"][fp]
    assert r1["partialFingerprints"][fp] != r3["partialFingerprints"][fp]


def test_message_strips_control_characters() -> None:
    hostile = _finding(evidence="rsa\x1b[31m.generate\x00_private_key(2048)")
    doc = build_sarif(_result(findings=(hostile,)))
    [res] = _run(doc)["results"]
    text = res["message"]["text"]
    assert "\x1b" not in text and "\x00" not in text
    assert "generate" in text


def test_message_strips_bidi_override_characters() -> None:
    # U+202E/U+202C and the isolate codes (Cf) are the Trojan-Source visual
    # spoofing vector; evidence comes from untrusted source, so they must not
    # reach a SARIF consumer that honors Unicode bidi.
    bidi = ("\u202e", "\u202c", "\u2066", "\u2069")
    hostile = _finding(evidence=f"md5(b'x')  # {bidi[0]}evil{bidi[1]} {bidi[2]}spoof{bidi[3]}")
    doc = build_sarif(_result(findings=(hostile,)))
    [res] = _run(doc)["results"]
    text = res["message"]["text"]
    assert all(c not in text for c in bidi)
    assert "evil" in text and "spoof" in text


def test_rules_are_deduplicated_and_indexed() -> None:
    f1, f2 = _finding(), _finding(
        location=SourceLocation(path=Path("/repo/b.py"), line=1, column=0)
    )
    sha = _finding(algorithm="SHA-1", family=AlgorithmFamily.HASH)
    doc = build_sarif(_result(findings=(f1, f2, sha)))
    run = _run(doc)
    rules = run["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["pqcheck/finding/RSA", "pqcheck/finding/SHA-1"]
    assert [res["ruleIndex"] for res in run["results"]] == [0, 0, 1]


def test_policy_id_lands_in_run_properties() -> None:
    f = _finding()
    doc = build_sarif(_result(
        policy_decisions=(_decision(f, RuleAction.FAIL),), policy_id="cryptoct-default-1.0.0",
    ))
    assert _run(doc)["properties"]["policy_id"] == "cryptoct-default-1.0.0"
    [res] = _run(doc)["results"]
    assert res["ruleId"] == "pqcheck/banned/RSA"


def test_built_sarif_validates_against_official_schema() -> None:
    f = _finding()
    doc = build_sarif(_result(
        policy_decisions=(_decision(f, RuleAction.FAIL),), policy_id="cryptoct-default-1.0.0",
    ))
    assert validate_sarif_210(doc) == []


def test_validator_rejects_malformed_document() -> None:
    errors = validate_sarif_210({"version": "2.1.0"})
    assert errors
    assert any("runs" in error for error in errors)


def test_scan_errors_are_sanitized() -> None:
    doc = build_sarif(_result(errors=("path/\x1b[31mevil\x1b[0m: denied",)))
    errors = _run(doc)["properties"]["scan_errors"]
    assert errors == ["path/[31mevil[0m: denied"]


def test_artifact_uri_is_sanitized() -> None:
    hostile = _finding(
        location=SourceLocation(path=Path("/repo/src/\x1b[2Jwipe.py"), line=1, column=0)
    )
    doc = build_sarif(_result(findings=(hostile,)))
    uri = _run(doc)["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\x1b" not in uri
    assert uri == "src/[2Jwipe.py"
