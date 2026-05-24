"""Parser for pyproject.toml — PEP 621 [project] + PEP 735 [dependency-groups].

Emits CryptoDependency per distinct package name across:
  - [project.dependencies]
  - [project.optional-dependencies.<group>]
  - [dependency-groups.<group>]
  - [build-system].requires       (PEP 518)

This parser records only distribution names; any version specifier in a
PEP 508 string is discarded, so every emitted dependency has version=None.
Exact versions come from the matching uv.lock result, which the scanner
orchestrator combines with the pyproject result.
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
        yield from _expand_dependency_groups(groups)

    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        yield from _string_items(build_system.get("requires"))


def _expand_dependency_groups(groups: dict[str, Any]) -> Iterable[str]:
    """Yield every PEP 508 requirement reachable from any group in
    `groups`, following PEP 735 `{include-group = "X"}` references. Each
    group contributes its strings at most once, so cycles cannot loop.
    """
    expanded: set[str] = set()
    for group_name in groups:
        yield from _expand_one_group(group_name, groups, expanded)


def _expand_one_group(
    group_name: str,
    groups: dict[str, Any],
    expanded: set[str],
) -> Iterable[str]:
    if group_name in expanded:
        return
    expanded.add(group_name)
    items = groups.get(group_name)
    if not isinstance(items, list):
        return
    for item in items:
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            included = item.get("include-group")
            if isinstance(included, str):
                yield from _expand_one_group(included, groups, expanded)


def _string_items(value: Any) -> Iterable[str]:
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, str):
            yield item
