"""Parser for pyproject.toml — PEP 621 [project] + PEP 735 [dependency-groups].

Emits CryptoDependency per distinct package name across:
  - [project.dependencies]
  - [project.optional-dependencies.<group>]
  - [dependency-groups.<group>]
  - [build-system].requires       (PEP 518)

Versions are NOT pinned in pyproject.toml — every emitted dependency
has version=None. For exact versions, the scanner orchestrator combines
the pyproject result with the matching uv.lock result.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pqcheck.deps.base import extract_pep508_name, pypi_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        data: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []

    seen: set[str] = set()  # keyed on PEP 503 lowercased name for dedup
    deps: list[CryptoDependency] = []
    for raw_name in _iter_requirement_strings(data):
        name = extract_pep508_name(raw_name)
        if name is None:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        deps.append(
            CryptoDependency(
                purl=pypi_purl(name, None),
                name=name,
                version=None,
                ecosystem="pypi",
                declared_in=path,
                introduces_algorithms=lookup_introduces("pypi", name),
            )
        )
    return deps


def _iter_requirement_strings(data: dict[str, Any]) -> Iterable[str]:
    project = data.get("project")
    if isinstance(project, dict):
        yield from _string_items(project.get("dependencies"))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group_value in optional.values():
                yield from _string_items(group_value)

    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group_value in groups.values():
            yield from _string_items(group_value)

    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        yield from _string_items(build_system.get("requires"))


def _string_items(value: Any) -> Iterable[str]:
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, str):
            yield item
