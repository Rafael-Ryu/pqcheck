"""Hand-emit a CycloneDX 1.6 CBOM from a ScanResult.

Emitted by hand against the vendored official schema instead of through
`cyclonedx-python-lib` — the document shape is small and stable, and a
hand emitter keeps the dependency surface down (see the M1 plan and the
minimize-deps decision). `validator.validate_cyclonedx_16` is the guard
that the shape stays correct.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from pqcheck.models import (
    AlgorithmFamily,
    CryptoDependency,
    CryptoFinding,
    PolicyDecision,
    ScanResult,
)

_STREAM_CIPHERS = frozenset({"RC4", "CHACHA20"})

_PRIMITIVE_BY_FAMILY: dict[AlgorithmFamily, str] = {
    AlgorithmFamily.SYMMETRIC_CIPHER: "block-cipher",
    AlgorithmFamily.ASYMMETRIC_ENCRYPTION: "pke",
    AlgorithmFamily.KEY_AGREEMENT: "key-agree",
    AlgorithmFamily.KEM: "kem",
    AlgorithmFamily.SIGNATURE: "signature",
    AlgorithmFamily.HASH: "hash",
    AlgorithmFamily.MAC: "mac",
    AlgorithmFamily.KDF: "kdf",
    AlgorithmFamily.RNG: "drbg",
    AlgorithmFamily.AEAD: "ae",
}

# CycloneDX 1.6 closed enums; anything the detectors emit outside these
# (e.g. pycryptodome's EAX/SIV modes) degrades to "other", never an
# invalid document.
_MODES = frozenset({"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"})
_PADDINGS = frozenset({"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw"})


def _primitive(finding: CryptoFinding) -> str:
    if finding.algorithm.upper() in _STREAM_CIPHERS:
        return "stream-cipher"
    return _PRIMITIVE_BY_FAMILY.get(finding.family, "unknown")


def _enum_or_other(value: str, allowed: frozenset[str]) -> str:
    lowered = value.lower()
    return lowered if lowered in allowed else "other"


def _relative_location(path: Path, target: Path) -> str:
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return path.as_posix()


def _finding_component(
    index: int, finding: CryptoFinding, decision: PolicyDecision | None, target: Path
) -> dict[str, object]:
    algorithm_properties: dict[str, object] = {"primitive": _primitive(finding)}
    if finding.key_size is not None:
        algorithm_properties["parameterSetIdentifier"] = str(finding.key_size)
    if finding.curve is not None:
        algorithm_properties["curve"] = finding.curve
    if finding.mode is not None:
        algorithm_properties["mode"] = _enum_or_other(finding.mode, _MODES)
    if finding.padding is not None:
        algorithm_properties["padding"] = _enum_or_other(finding.padding, _PADDINGS)

    properties: list[dict[str, str]] = [
        {"name": "pqcheck:detector_id", "value": finding.detector_id},
        {"name": "pqcheck:confidence", "value": f"{finding.confidence:.2f}"},
        {"name": "pqcheck:quantum_risk", "value": finding.quantum_risk.value},
    ]
    if decision is not None:
        properties.extend(
            [
                {"name": "pqcheck:policy_action", "value": decision.action.value},
                {"name": "pqcheck:base_severity", "value": decision.base_severity.value},
                {"name": "pqcheck:severity", "value": decision.severity.value},
                {"name": "pqcheck:rule_kind", "value": decision.rule_kind},
            ]
        )
        if decision.exception_id is not None:
            properties.append({"name": "pqcheck:exception_id", "value": decision.exception_id})

    return {
        "type": "cryptographic-asset",
        "bom-ref": f"finding-{index}",
        "name": finding.algorithm,
        "evidence": {
            "occurrences": [
                {
                    "location": _relative_location(finding.location.path, target),
                    "line": finding.location.line,
                }
            ]
        },
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
        "properties": properties,
    }


def _dependency_component(index: int, dep: CryptoDependency, target: Path) -> dict[str, object]:
    component: dict[str, object] = {
        "type": "library",
        "bom-ref": f"dep-{index}",
        "name": dep.name,
        "purl": dep.purl,
    }
    if dep.version is not None:
        component["version"] = dep.version
    properties: list[dict[str, str]] = [
        {"name": "pqcheck:ecosystem", "value": dep.ecosystem},
        {"name": "pqcheck:declared_in", "value": _relative_location(dep.declared_in, target)},
        {"name": "pqcheck:integrity_verified", "value": str(dep.integrity_verified).lower()},
    ]
    if dep.introduces_algorithms:
        properties.append(
            {"name": "pqcheck:introduces", "value": ",".join(dep.introduces_algorithms)}
        )
    component["properties"] = properties
    return component


def build_cbom(result: ScanResult) -> dict[str, object]:
    decisions: dict[int, PolicyDecision] = {}
    if len(result.policy_decisions) == len(result.findings):
        decisions = dict(enumerate(result.policy_decisions))

    metadata: dict[str, object] = {
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "tools": {
            "components": [
                {"type": "application", "name": "pqcheck", "version": result.scanner_version}
            ]
        },
    }
    metadata_properties: list[dict[str, str]] = []
    if result.policy_id is not None:
        metadata_properties.append({"name": "pqcheck:policy_id", "value": result.policy_id})
    if result.errors:
        metadata_properties.append(
            {"name": "pqcheck:scan_errors", "value": str(len(result.errors))}
        )
    if metadata_properties:
        metadata["properties"] = metadata_properties

    components: list[dict[str, object]] = [
        _finding_component(i, finding, decisions.get(i), result.target)
        for i, finding in enumerate(result.findings)
    ]
    components.extend(
        _dependency_component(i, dep, result.target)
        for i, dep in enumerate(result.dependencies)
    )

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
