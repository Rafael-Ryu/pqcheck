"""Typer CLI entry point.

`scan` runs the end-to-end pipeline (walk → detect → parse → evaluate)
and emits a terminal report, a CycloneDX 1.6 CBOM, or SARIF 2.1.0.
Exit codes: 0 clean, 1 policy gate tripped, 2 usage/policy error,
70 internal error (emitted CBOM failed self-validation).
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from pqcheck import __version__
from pqcheck.cbom.builder import build_cbom
from pqcheck.cbom.validator import validate_cyclonedx_16
from pqcheck.models import ScanResult
from pqcheck.output.sarif import build_sarif
from pqcheck.policy.engine import gate
from pqcheck.policy.loader import PolicyError, load_default_policy, load_policy
from pqcheck.policy.schema import CryptoPolicy
from pqcheck.scanner import scan as run_scan

app = typer.Typer(
    name="pqcheck",
    help="Post-quantum cryptography risk scanner.",
    no_args_is_help=True,
    add_completion=False,
)
policy_app = typer.Typer(help="Inspect and validate crypto policies.", no_args_is_help=True)
app.add_typer(policy_app, name="policy")


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    CBOM = "cbom"
    SARIF = "sarif"


class FailOn(StrEnum):
    POLICY = "policy"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_ACTION_MARKS = {"fail": "✗", "warn": "⚠", "allow": "✓"}


@app.command()
def version() -> None:
    """Print the installed pqcheck version."""
    typer.echo(__version__)


def _load_policy_arg(value: str) -> CryptoPolicy:
    path = Path(value)
    try:
        if value.endswith((".yaml", ".yml")) or path.exists():
            return load_policy(path)
        return load_default_policy(value)
    except PolicyError as exc:
        raise typer.BadParameter(str(exc), param_hint="--policy") from exc


def _emit_json(doc: dict[str, object], output: Path | None) -> None:
    text = json.dumps(doc, indent=2) + "\n"
    if output is None:
        typer.echo(text, nl=False)
    else:
        output.write_text(text, encoding="utf-8")


def _relative(path: Path, target: Path) -> str:
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return path.as_posix()


def _terminal_report(result: ScanResult) -> None:
    target = result.target
    if result.policy_decisions:
        for decision in result.policy_decisions:
            loc = decision.finding.location
            mark = _ACTION_MARKS[decision.action.value]
            line = (
                f"{mark} {_relative(loc.path, target)}:{loc.line}"
                f" — {decision.finding.algorithm}"
                f" [{decision.rule_kind}/{decision.base_severity.value}"
                f", confidence {decision.confidence_band.value}]"
            )
            if decision.reason:
                line += f" — {decision.reason}"
            typer.echo(line)
    else:
        for finding in result.findings:
            loc = finding.location
            typer.echo(
                f"• {_relative(loc.path, target)}:{loc.line} — {finding.algorithm}"
                f" ({finding.family.value})"
            )
    if result.dependencies:
        typer.echo(f"dependencies: {len(result.dependencies)} parsed")
    for error in result.errors:
        typer.echo(f"warning: {error}", err=True)
    if result.policy_id is not None:
        actions = [d.action.value for d in result.policy_decisions]
        typer.echo(
            f"policy {result.policy_id}: "
            f"{actions.count('fail')} fail, {actions.count('warn')} warn, "
            f"{actions.count('allow')} allow"
        )


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(help="Path to scan.", exists=True, file_okay=False, resolve_path=True),
    ],
    policy: Annotated[
        str | None,
        typer.Option(
            "--policy",
            "-p",
            help="Bundled policy name (e.g. cryptoct-default) or path to a policy YAML.",
        ),
    ] = None,
    output_format: Annotated[
        OutputFormat, typer.Option("--format", "-f", help="Report format.")
    ] = OutputFormat.TERMINAL,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write cbom/sarif here instead of stdout."),
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option(
            "--fail-on",
            help="Gate mode: 'policy' trips on FAIL decisions; a severity trips on "
            "base_severity at or above it.",
        ),
    ] = FailOn.POLICY,
    strict: Annotated[
        bool, typer.Option("--strict", help="Gate WARN decisions as failures.")
    ] = False,
) -> None:
    """Scan a repository for cryptographic primitives and policy violations."""
    if output is not None and output_format is OutputFormat.TERMINAL:
        raise typer.BadParameter(
            "--output requires --format cbom or sarif", param_hint="--output"
        )
    if (strict or fail_on is not FailOn.POLICY) and policy is None:
        raise typer.BadParameter(
            "--strict and --fail-on need a policy to gate against", param_hint="--policy"
        )

    loaded = _load_policy_arg(policy) if policy is not None else None
    result = run_scan(target, loaded)

    if output_format is OutputFormat.CBOM:
        doc = build_cbom(result)
        violations = validate_cyclonedx_16(doc)
        if violations:
            for violation in violations:
                typer.echo(f"cbom self-validation: {violation}", err=True)
            raise typer.Exit(code=70)
        _emit_json(doc, output)
    elif output_format is OutputFormat.SARIF:
        _emit_json(build_sarif(result), output)
    else:
        _terminal_report(result)

    if loaded is not None:
        worst = gate(result.policy_decisions, fail_on=fail_on.value, strict=strict)
        if worst is not None:
            typer.echo(f"gate: --fail-on {fail_on.value} tripped at {worst.value}", err=True)
            raise typer.Exit(code=1)


@policy_app.command("show")
def policy_show(
    name: Annotated[str, typer.Argument(help="Bundled policy name or path to a policy YAML.")],
) -> None:
    """Print the resolved policy as JSON."""
    loaded = _load_policy_arg(name)
    typer.echo(loaded.model_dump_json(indent=2, by_alias=True))


@policy_app.command("validate")
def policy_validate(
    path: Annotated[Path, typer.Argument(help="Policy YAML to validate.", exists=True)],
) -> None:
    """Validate a policy file against the pqcheck policy schema."""
    try:
        loaded = load_policy(path)
    except PolicyError as exc:
        typer.echo(f"invalid: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"valid: {loaded.metadata.name} {loaded.metadata.version}")


if __name__ == "__main__":  # pragma: no cover
    app()
