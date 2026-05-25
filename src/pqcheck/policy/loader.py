"""Load and validate pqcheck crypto policies from YAML.

Parsing uses a SafeLoader subclass that refuses YAML anchors/aliases. Plain
``yaml.safe_load`` still expands aliases, so it does not stop a YAML alias bomb
(billion laughs); policies never need anchors, so forbidding them closes that hole.
"""

from __future__ import annotations

import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from pqcheck.policy.schema import CryptoPolicy


class PolicyError(Exception):
    """Raised when a policy cannot be read, parsed, or validated."""


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader that rejects anchors and aliases (alias-bomb defense)."""


def _refuse_alias(self: yaml.SafeLoader, node: Any) -> None:
    raise yaml.constructor.ConstructorError(
        None, None, "YAML anchors/aliases are not allowed in policies", None
    )


# ``None`` registers the catch-all constructor for any unknown/anchored tag; the
# typeshed stub only types the tag as ``str``, so ignore the arg-type mismatch.
_NoAliasSafeLoader.add_constructor(None, _refuse_alias)  # type: ignore[arg-type]


def _compose_node(self: Any, parent: Any, index: Any) -> Any:
    if self.check_event(yaml.events.AliasEvent):
        event = self.get_event()
        raise yaml.constructor.ConstructorError(
            None, None, "YAML aliases are not allowed in policies", event.start_mark
        )
    return yaml.composer.Composer.compose_node(self, parent, index)


_NoAliasSafeLoader.compose_node = _compose_node  # type: ignore[method-assign]


def _parse_and_validate(text: str, origin: str) -> CryptoPolicy:
    try:
        data = yaml.load(text, Loader=_NoAliasSafeLoader)  # noqa: S506 - custom no-alias safe loader
    except yaml.YAMLError as exc:
        raise PolicyError(f"invalid YAML in {origin}: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy {origin} must be a mapping, got {type(data).__name__}")
    try:
        return CryptoPolicy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"policy {origin} failed validation:\n{exc}") from exc


def load_policy(path: Path) -> CryptoPolicy:
    """Read, parse, and validate a policy file. Raises PolicyError on any failure."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    return _parse_and_validate(text, str(path))


def load_default_policy(name: str) -> CryptoPolicy:
    """Load a bundled default policy by name (e.g. 'cryptoct-default')."""
    resource = files("pqcheck.policy").joinpath("defaults", f"{name}.yaml")
    if not resource.is_file():
        raise PolicyError(f"no bundled policy named {name!r}")
    return _parse_and_validate(resource.read_text(encoding="utf-8"), f"<bundled:{name}>")


def main(argv: list[str] | None = None) -> int:
    """Entry point for ``python -m pqcheck.policy.loader <file>``."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m pqcheck.policy.loader <policy.yaml>", file=sys.stderr)
        return 2
    try:
        policy = load_policy(Path(args[0]))
    except PolicyError as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    print(f"OK: {policy.metadata.name} {policy.metadata.version}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
