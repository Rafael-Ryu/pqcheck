from pathlib import Path
from typing import Any, cast

from pqcheck.cbom import build_cbom
from pqcheck.cbom.validator import validate_cyclonedx_16
from pqcheck.models import (
    AlgorithmFamily,
    ConfidenceBand,
    CryptoDependency,
    CryptoFinding,
    PolicyDecision,
    RuleAction,
    ScanResult,
    Severity,
    SourceLocation,
)


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


def _dep() -> CryptoDependency:
    return CryptoDependency(
        purl="pkg:pypi/pycryptodome@3.20.0",
        name="pycryptodome",
        version="3.20.0",
        ecosystem="pypi",
        declared_in=Path("/repo/pyproject.toml"),
        introduces_algorithms=("RSA", "AES"),
    )


def _result(**kw: Any) -> ScanResult:
    base: dict[str, Any] = {
        "target": Path("/repo"),
        "scanner_version": "0.1.0",
        "findings": (_finding(),),
        "dependencies": (_dep(),),
    }
    base.update(kw)
    return ScanResult(**base)


def _components(doc: dict[str, Any]) -> list[dict[str, Any]]:
    return cast("list[dict[str, Any]]", doc["components"])


def test_build_cbom_top_level_shape() -> None:
    doc = build_cbom(_result())
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert str(doc["serialNumber"]).startswith("urn:uuid:")
    tools = cast("dict[str, Any]", doc["metadata"])["tools"]
    assert tools["components"][0]["name"] == "pqcheck"


def test_finding_becomes_cryptographic_asset_with_occurrence() -> None:
    doc = build_cbom(_result())
    [asset] = [c for c in _components(doc) if c["type"] == "cryptographic-asset"]
    assert asset["cryptoProperties"]["assetType"] == "algorithm"
    assert asset["cryptoProperties"]["algorithmProperties"]["primitive"] == "pke"
    [occ] = asset["evidence"]["occurrences"]
    # location must be relative to the scan target so CBOMs are portable
    assert occ["location"] == "src/auth.py"
    assert occ["line"] == 42


def test_dependency_becomes_library_component_with_purl() -> None:
    doc = build_cbom(_result())
    [lib] = [c for c in _components(doc) if c["type"] == "library"]
    assert lib["purl"] == "pkg:pypi/pycryptodome@3.20.0"
    assert lib["version"] == "3.20.0"


def test_mode_and_padding_map_to_schema_enums() -> None:
    aes_eax = _finding(
        algorithm="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER,
        key_size=256, mode="EAX", padding="OAEP",
    )
    chacha = _finding(algorithm="ChaCha20", family=AlgorithmFamily.SYMMETRIC_CIPHER, mode="GCM")
    doc = build_cbom(_result(findings=(aes_eax, chacha), dependencies=()))
    aes_props, chacha_props = (
        c["cryptoProperties"]["algorithmProperties"] for c in _components(doc)
    )
    assert aes_props["mode"] == "other"  # EAX is not in the 1.6 mode enum
    assert aes_props["padding"] == "oaep"
    assert aes_props["parameterSetIdentifier"] == "256"
    assert chacha_props["primitive"] == "stream-cipher"
    assert chacha_props["mode"] == "gcm"


def test_policy_decisions_are_attached_as_properties() -> None:
    finding = _finding()
    decision = PolicyDecision(
        finding=finding, action=RuleAction.FAIL,
        base_severity=Severity.CRITICAL, severity=Severity.CRITICAL,
        confidence_band=ConfidenceBand.HIGH, rule_kind="banned",
        matched="RSA", reason="Shor",
    )
    doc = build_cbom(_result(
        findings=(finding,), policy_decisions=(decision,), policy_id="cryptoct-default-1.0.0",
    ))
    metadata = cast("dict[str, Any]", doc["metadata"])
    meta_props = {p["name"]: p["value"] for p in metadata["properties"]}
    assert meta_props["pqcheck:policy_id"] == "cryptoct-default-1.0.0"
    [asset] = [c for c in _components(doc) if c["type"] == "cryptographic-asset"]
    props = {p["name"]: p["value"] for p in asset["properties"]}
    assert props["pqcheck:policy_action"] == "fail"
    assert props["pqcheck:base_severity"] == "critical"
    assert props["pqcheck:quantum_risk"] == "quantum-vulnerable"


def test_certificate_finding_becomes_certificate_asset() -> None:
    finding = _finding(
        key_size=2048,
        material_kind="certificate",
        cert_subject="CN=test",
        cert_issuer="CN=test",
        cert_not_valid_before="2020-01-01T00:00:00+00:00",
        cert_not_valid_after="2030-01-01T00:00:00+00:00",
        cert_format="PEM",
    )
    doc = build_cbom(_result(findings=(finding,), dependencies=()))
    [asset] = [c for c in _components(doc) if c["type"] == "cryptographic-asset"]
    crypto_props = asset["cryptoProperties"]
    assert crypto_props["assetType"] == "certificate"
    assert crypto_props["algorithmProperties"]["primitive"] == "pke"
    assert crypto_props["algorithmProperties"]["parameterSetIdentifier"] == "2048"
    cert_props = crypto_props["certificateProperties"]
    assert cert_props["subjectName"] == "CN=test"
    assert cert_props["issuerName"] == "CN=test"
    assert cert_props["notValidBefore"] == "2020-01-01T00:00:00+00:00"
    assert cert_props["notValidAfter"] == "2030-01-01T00:00:00+00:00"
    assert cert_props["certificateFormat"] == "PEM"
    assert validate_cyclonedx_16(doc) == []


def test_private_key_finding_becomes_related_crypto_material_asset() -> None:
    finding = _finding(key_size=2048, material_kind="private-key")
    doc = build_cbom(_result(findings=(finding,), dependencies=()))
    [asset] = [c for c in _components(doc) if c["type"] == "cryptographic-asset"]
    crypto_props = asset["cryptoProperties"]
    assert crypto_props["assetType"] == "related-crypto-material"
    assert crypto_props["relatedCryptoMaterialProperties"]["type"] == "private-key"
    assert crypto_props["algorithmProperties"]["primitive"] == "pke"
    assert validate_cyclonedx_16(doc) == []


def test_public_key_finding_becomes_related_crypto_material_asset() -> None:
    finding = _finding(
        algorithm="EdDSA", family=AlgorithmFamily.SIGNATURE, curve="Ed25519",
        material_kind="public-key",
    )
    doc = build_cbom(_result(findings=(finding,), dependencies=()))
    [asset] = [c for c in _components(doc) if c["type"] == "cryptographic-asset"]
    crypto_props = asset["cryptoProperties"]
    assert crypto_props["assetType"] == "related-crypto-material"
    assert crypto_props["relatedCryptoMaterialProperties"]["type"] == "public-key"
    assert validate_cyclonedx_16(doc) == []


def test_built_cbom_validates_against_official_schema() -> None:
    finding = _finding()
    decision = PolicyDecision(
        finding=finding, action=RuleAction.FAIL,
        base_severity=Severity.CRITICAL, severity=Severity.MEDIUM,
        confidence_band=ConfidenceBand.LOW, rule_kind="banned",
        matched="RSA", reason="Shor", exception_id="EXC-001",
    )
    doc = build_cbom(_result(
        findings=(finding,), policy_decisions=(decision,),
        policy_id="cryptoct-default-1.0.0", errors=("warm: oops",),
    ))
    assert validate_cyclonedx_16(doc) == []


def test_validator_rejects_malformed_document() -> None:
    errors = validate_cyclonedx_16({"specVersion": "1.6"})
    assert errors and any("bomFormat" in e for e in errors)


def test_bom_refs_are_unique_even_for_identical_findings() -> None:
    f = _finding()
    doc = build_cbom(_result(findings=(f, f), dependencies=()))
    refs = [c["bom-ref"] for c in _components(doc)]
    assert len(refs) == len(set(refs))
