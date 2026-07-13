"""Validate a SARIF document against the vendored SARIF 2.1.0 schema.

The official OASIS schema (errata01, fetched 2026-07-12 from
oasis-tcs/sarif-spec) is self-contained and vendored under
`pqcheck.schemas` — validation never touches the network.

Runnable as a module for the CI gate:
    python -m pqcheck.output.sarif_validator path/to/file.sarif
"""

from __future__ import annotations

import json
import sys
from functools import cache
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft4Validator

_SARIF_SCHEMA = "sarif-2.1.0.schema.json"


@cache
def _validator() -> Draft4Validator:
    contents = json.loads(
        files("pqcheck.schemas").joinpath(_SARIF_SCHEMA).read_text(encoding="utf-8")
    )
    return Draft4Validator(contents)


def validate_sarif_210(doc: object) -> list[str]:
    """Return human-readable schema violations; empty list means valid."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: e.json_path)
    return [f"{error.json_path}: {error.message}" for error in errors]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m pqcheck.output.sarif_validator <file.sarif>", file=sys.stderr)
        return 2
    try:
        doc = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot load {args[0]}: {exc}", file=sys.stderr)
        return 2
    violations = validate_sarif_210(doc)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        return 1
    print(f"{args[0]}: valid SARIF 2.1.0")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
