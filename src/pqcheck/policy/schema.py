"""Pydantic models for the pqcheck crypto policy document.

These models are the single source of truth for the policy format. The shipped
``pqcheck-policy.schema.json`` is generated from them (see ``export_json_schema``),
so the two never drift. Mirrors the template in
``.context/plans/02-quantum-safe-crypto-policy.md`` §13.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from pqcheck.models import ConfidenceBand, Severity


def _to_kebab(name: str) -> str:
    return name.replace("_", "-")


_CONFIG = ConfigDict(alias_generator=_to_kebab, populate_by_name=True, extra="forbid")


class RuleAction(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    FAIL = "fail"


class SeverityRuleAction(StrEnum):
    AS_DECLARED = "as-declared"
    DEMOTE_ONE_TIER = "demote-one-tier"
    DEMOTE_TWO_TIERS = "demote-two-tiers"


class PolicyFamily(StrEnum):
    # Tokens as used by the policy YAML (02 §13). These intentionally differ from
    # models.AlgorithmFamily (kem vs key-encapsulation, etc.); mapping is the engine's job.
    KEM = "kem"
    SIGNATURE = "signature"
    SYMMETRIC_CIPHER = "symmetric-cipher"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    KEY_AGREEMENT = "key-agreement"
    ASYMMETRIC_ENCRYPTION = "asymmetric-encryption"


class AlgorithmRule(BaseModel):
    """One approved or banned algorithm rule. Optional fields cover both shapes."""

    model_config = _CONFIG

    family: PolicyFamily
    algorithm: str
    parameter_sets: list[str] | None = None
    curves: list[str] | None = None
    modes: list[str] | None = None
    hash: list[str] | None = None
    params: dict[str, Any] | None = None
    context: str | None = None
    action: RuleAction | None = None
    severity: Severity | None = None
    reason: str | None = None
    migration_doc: str | None = None
    preferred: bool | None = None


class HybridRule(BaseModel):
    model_config = _CONFIG

    context: str
    classical: list[str]
    pqc: list[str]
    action: RuleAction | None = None


class PolicyException(BaseModel):
    model_config = _CONFIG

    id: str = Field(pattern=r"^EXC-\d{3}$")
    description: str
    banned_algorithm: str | None = None
    context: str | None = None
    adr: str | None = None
    review_date: date | None = None
    compensating_controls: list[str] | None = None


class SeverityRule(BaseModel):
    model_config = _CONFIG

    confidence_band: ConfidenceBand
    action: SeverityRuleAction


class SeveritySelector(BaseModel):
    model_config = _CONFIG

    severity: Severity
    confidence_band: list[ConfidenceBand] | None = None


class PolicyMetadata(BaseModel):
    model_config = _CONFIG

    name: str = Field(min_length=1)
    # Simple MAJOR.MINOR.PATCH — policies do not use pre-release/build metadata.
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    publisher: str = Field(min_length=1)
    applies_to: str
    effective_from: date
    review_date: date


class PolicySpec(BaseModel):
    model_config = _CONFIG

    default_action: RuleAction
    approved: list[AlgorithmRule] = Field(default_factory=list)
    hybrid_required: list[HybridRule] = Field(default_factory=list)
    banned: list[AlgorithmRule] = Field(default_factory=list)
    exceptions: list[PolicyException] = Field(default_factory=list)
    severity_rules: list[SeverityRule] = Field(default_factory=list)
    fail_on: list[SeveritySelector] = Field(default_factory=list)
    warn_on: list[SeveritySelector] = Field(default_factory=list)
    info_only: list[SeveritySelector] = Field(default_factory=list)


class CryptoPolicy(BaseModel):
    model_config = _CONFIG

    api_version: Literal["pqcheck.cryptoct.com/v1"] = Field(alias="apiVersion")
    kind: Literal["CryptoPolicy"]
    metadata: PolicyMetadata
    spec: PolicySpec


def export_json_schema() -> dict[str, Any]:
    """Generate the JSON Schema for a policy document, keyed by YAML aliases."""
    return CryptoPolicy.model_json_schema(by_alias=True)
