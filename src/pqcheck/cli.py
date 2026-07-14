"""Typer CLI entry point.

`scan` runs the end-to-end pipeline (walk → detect → parse → evaluate)
and emits a terminal report, a CycloneDX 1.6 CBOM, or SARIF 2.1.0.
Exit codes: 0 clean, 1 policy gate tripped, 2 usage/policy error,
70 internal error (emitted CBOM/SARIF failed self-validation),
73 refused to write output through a symlink.
"""

from __future__ import annotations

import contextlib
import json
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from pqcheck import __version__
from pqcheck.cbom.builder import build_cbom
from pqcheck.cbom.validator import validate_cyclonedx_16
from pqcheck.models import ScanResult
from pqcheck.output.sarif import build_sarif, sanitize_text
from pqcheck.output.sarif_validator import validate_sarif_210
from pqcheck.policy.engine import gate, unevaluated_constructs
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

_RELEASE_REPO = "Rafael-Ryu/pqcheck"
_GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"


def _configure_output_streams() -> None:
    """Degrade unencodable report characters instead of crashing the scan.

    Windows consoles default to legacy codepages (cp1252) that cannot
    encode the report marks (✗ ⚠ ✓) or em dashes — first hit by the
    Windows CI cell's self-audit step. errors="replace" keeps UTF-8
    terminals pristine and turns the marks into "?" on legacy ones.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(errors="replace")


_configure_output_streams()


@app.command()
def version() -> None:
    """Print the installed pqcheck version."""
    typer.echo(__version__)


def _load_policy_arg(value: str) -> CryptoPolicy:
    path = Path(value)
    try:
        if value.endswith((".yaml", ".yml")) or path.exists():
            loaded = load_policy(path)
        else:
            loaded = load_default_policy(value)
    except PolicyError as exc:
        raise typer.BadParameter(str(exc), param_hint="--policy") from exc
    _warn_unevaluated(loaded)
    return loaded


def _warn_unevaluated(policy: CryptoPolicy) -> None:
    constructs = unevaluated_constructs(policy)
    if constructs:
        typer.echo(
            "warning: policy declares constraints pqcheck v0.1 does not evaluate "
            f"(rules match on family/algorithm/parameter-sets/curves/modes/paddings "
            f"only): {', '.join(constructs)}",
            err=True,
        )


def _emit_json(doc: dict[str, object], output: Path | None) -> None:
    text = json.dumps(doc, indent=2) + "\n"
    if output is None:
        typer.echo(text, nl=False)
        return
    # write_text follows symlinks: a scanned repo could pre-plant the default
    # output name (self-cbom.json) as a symlink and redirect the write over
    # any file the user can touch. Refuse instead of silently replacing.
    if output.is_symlink():
        typer.echo(f"refusing to write through a symlink: {output}", err=True)
        raise typer.Exit(code=73)
    output.write_text(text, encoding="utf-8")


def _relative(path: Path, target: Path) -> str:
    try:
        return path.relative_to(target).as_posix()
    except ValueError:
        return path.as_posix()


def _safe_line(text: str) -> str:
    # sanitize_text keeps \n and \t (fine inside SARIF strings); a terminal
    # report is line-oriented, so either one would let a hostile filename
    # forge extra report lines or misalign columns. Collapse them to spaces.
    return sanitize_text(text).replace("\n", " ").replace("\t", " ")


def _terminal_report(result: ScanResult) -> None:
    # Paths, reasons, and error strings originate in the scanned (untrusted)
    # tree; sanitize_text strips the ANSI/bidi control characters that would
    # otherwise reach the terminal verbatim.
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
            typer.echo(_safe_line(line))
    else:
        for finding in result.findings:
            loc = finding.location
            typer.echo(
                _safe_line(
                    f"• {_relative(loc.path, target)}:{loc.line} — {finding.algorithm}"
                    f" ({finding.family.value})"
                )
            )
    if result.dependencies:
        typer.echo(f"dependencies: {len(result.dependencies)} parsed")
    for error in result.errors:
        typer.echo(_safe_line(f"warning: {error}"), err=True)
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
        bool,
        typer.Option(
            "--strict",
            help="Fail on WARN, treat unknown quantum risk as vulnerable, "
            "refuse policies without severity-rules.",
        ),
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
    if strict and loaded is not None and not loaded.spec.severity_rules:
        raise typer.BadParameter(
            "--strict refuses policies without a severity-rules section", param_hint="--policy"
        )
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
        doc = build_sarif(result)
        violations = validate_sarif_210(doc)
        if violations:
            for violation in violations:
                typer.echo(f"sarif self-validation: {violation}", err=True)
            raise typer.Exit(code=70)
        _emit_json(doc, output)
    else:
        _terminal_report(result)

    if loaded is not None:
        worst = gate(result.policy_decisions, fail_on=fail_on.value, strict=strict)
        if worst is not None:
            typer.echo(f"gate: --fail-on {fail_on.value} tripped at {worst.value}", err=True)
            raise typer.Exit(code=1)


@app.command("self-audit")
def self_audit(
    target: Annotated[
        Path,
        typer.Argument(
            help="Project root to audit.", exists=True, file_okay=False, resolve_path=True
        ),
    ] = Path(),
    output: Annotated[
        Path, typer.Option("--output", "-o", help="Where to write the CBOM.")
    ] = Path("self-cbom.json"),
) -> None:
    """Audit a project against pqcheck's own binding policy (cryptoct-default).

    The release-gate form of `scan`: fixed policy, CBOM always written (and
    self-validated), exit 1 on any FAIL decision. pqcheck runs this against
    its own repository in CI — a release cannot ship crypto its own policy
    bans.
    """
    policy = load_default_policy("cryptoct-default")
    _warn_unevaluated(policy)
    result = run_scan(target, policy)
    doc = build_cbom(result)
    violations = validate_cyclonedx_16(doc)
    if violations:
        for violation in violations:
            typer.echo(f"cbom self-validation: {violation}", err=True)
        raise typer.Exit(code=70)
    _emit_json(doc, output)
    _terminal_report(result)
    worst = gate(result.policy_decisions, fail_on="policy")
    if worst is not None:
        typer.echo(f"self-audit: policy gate tripped at {worst.value}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"self-audit clean — CBOM at {output}")


@app.command("verify-release")
def verify_release(
    artifact: Annotated[
        Path,
        typer.Argument(
            help="Release artifact (wheel or sdist).",
            exists=True,
            dir_okay=False,
            resolve_path=True,
        ),
    ],
    bundle: Annotated[
        Path | None,
        typer.Option("--bundle", help="Sigstore bundle (default: <artifact>.sigstore.json)."),
    ] = None,
    identity: Annotated[
        str | None,
        typer.Option(
            "--identity",
            help="Exact certificate identity to require. Default accepts any signature "
            "from the pqcheck release repository's GitHub Actions workflows.",
        ),
    ] = None,
    issuer: Annotated[
        str, typer.Option("--issuer", help="OIDC issuer to require.")
    ] = _GITHUB_OIDC_ISSUER,
) -> None:
    """Verify a release artifact against its Sigstore keyless bundle.

    Exit codes: 0 verified, 1 verification failed, 2 usage error
    (missing sigstore extra, missing or malformed bundle).
    """
    # deferred import: sigstore is an optional extra; every other command works without it
    try:
        from sigstore.errors import Error as SigstoreError, VerificationError  # noqa: PLC0415, I001
        from sigstore.models import Bundle  # noqa: PLC0415
        from sigstore.verify import Verifier, policy as sigstore_policy  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - extra always present in test env
        typer.echo(
            "sigstore is not installed — install the extra: pip install 'pqcheck[sigstore]'",
            err=True,
        )
        raise typer.Exit(code=2) from exc

    bundle_path = bundle or artifact.with_name(artifact.name + ".sigstore.json")
    if not bundle_path.is_file():
        typer.echo(f"bundle not found: {bundle_path}", err=True)
        raise typer.Exit(code=2)

    verification_policy: sigstore_policy.VerificationPolicy
    if identity is not None:
        verification_policy = sigstore_policy.Identity(identity=identity, issuer=issuer)
    else:
        verification_policy = sigstore_policy.AllOf(
            [
                sigstore_policy.OIDCIssuer(issuer),
                sigstore_policy.GitHubWorkflowRepository(_RELEASE_REPO),
            ]
        )

    try:
        parsed = Bundle.from_json(bundle_path.read_bytes())
    except (SigstoreError, ValueError) as exc:
        typer.echo(f"invalid bundle: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    try:
        Verifier.production().verify_artifact(artifact.read_bytes(), parsed, verification_policy)
    except VerificationError as exc:
        typer.echo(f"verification FAILED: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"OK: {artifact.name} verified against {bundle_path.name}")


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
    _warn_unevaluated(loaded)
    typer.echo(f"valid: {loaded.metadata.name} {loaded.metadata.version}")


if __name__ == "__main__":  # pragma: no cover
    app()
