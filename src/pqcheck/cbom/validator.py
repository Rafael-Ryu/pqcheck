"""Validate a CBOM document against the vendored CycloneDX 1.6 schema.

The official schema references its SPDX and JSF companions by URL; all
three are vendored under `pqcheck.schemas` (fetched 2026-06-11 from
CycloneDX/specification) and resolved offline through a `referencing`
registry — validation never touches the network.

Runnable as a module for the CI gate:
    python -m pqcheck.cbom.validator path/to/cbom.json
"""

from __future__ import annotations

import json
import sys
from functools import cache
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

_SCHEMA_BASE = "http://cyclonedx.org/schema/"
_BOM_SCHEMA = "bom-1.6.schema.json"
_COMPANION_SCHEMAS = ("spdx.schema.json", "jsf-0.82.schema.json")


@cache
def _validator() -> Draft7Validator:
    package = files("pqcheck.schemas")
    bom_contents = json.loads(package.joinpath(_BOM_SCHEMA).read_text(encoding="utf-8"))
    resources = [
        (_SCHEMA_BASE + _BOM_SCHEMA, Resource.from_contents(bom_contents, DRAFT7))
    ]
    for name in _COMPANION_SCHEMAS:
        contents = json.loads(package.joinpath(name).read_text(encoding="utf-8"))
        resources.append((_SCHEMA_BASE + name, Resource.from_contents(contents, DRAFT7)))
    registry = Registry().with_resources(resources)
    return Draft7Validator(bom_contents, registry=registry)


def validate_cyclonedx_16(doc: object) -> list[str]:
    """Return human-readable schema violations; empty list means valid."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: e.json_path)
    return [f"{error.json_path}: {error.message}" for error in errors]


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m pqcheck.cbom.validator <cbom.json>", file=sys.stderr)
        return 2
    try:
        doc = json.loads(Path(args[0]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"error: cannot load {args[0]}: {exc}", file=sys.stderr)
        return 2
    violations = validate_cyclonedx_16(doc)
    for violation in violations:
        print(violation, file=sys.stderr)
    if violations:
        return 1
    print(f"{args[0]}: valid CycloneDX 1.6")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
