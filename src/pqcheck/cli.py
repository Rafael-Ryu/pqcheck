"""Typer CLI entry point.

Pre-alpha skeleton — subcommands `scan`, `self-audit`, `verify-release`,
`policy show`, `policy validate` land progressively during Phase 1.
"""

from __future__ import annotations

import typer

from pqcheck import __version__

app = typer.Typer(
    name="pqcheck",
    help="Post-quantum cryptography risk scanner.",
    no_args_is_help=True,
    add_completion=False,
)


@app.command()
def version() -> None:
    """Print the installed pqcheck version."""
    typer.echo(__version__)


@app.command()
def scan(target: str = typer.Argument(..., help="Path to scan.")) -> None:
    """Scan a repository for cryptographic primitives. (Phase 1 — not implemented yet.)"""
    raise typer.Exit(code=64)  # EX_USAGE: subcommand stubbed pre-alpha


if __name__ == "__main__":  # pragma: no cover
    app()
