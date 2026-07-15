"""Parser for npm package-lock.json (lockfileVersion 1, 2, and 3).

lockfileVersion 1 uses a top-level "dependencies" map where entries may
nest — we flatten the tree iteratively to capture all resolved packages
(recursion made the reachable depth stack-dependent).

lockfileVersion 2 and 3 use a top-level "packages" map keyed by install
path (e.g. "node_modules/foo", "node_modules/foo/node_modules/bar"). The
package name is the segment after the last "node_modules/" in the key.
v2 also carries a legacy "dependencies" map; we prefer "packages" when
present to avoid double-counting.

JSON has no XXE or billion-laughs attack surface. Hardening is via
safe_read_bytes (size cap, no symlink follow) and a non-dict-root guard.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pqcheck.deps.base import ManifestError, npm_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

_NODE_MODULES = "node_modules/"


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    # Deeply nested JSON can exhaust the C/Python stack in json.loads; bounding
    # input size does not bound nesting depth. Surfaced as ManifestError so the
    # scan reports an incomplete inventory.
    try:
        data: Any = json.loads(raw.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError, MemoryError) as exc:
        raise ManifestError(f"malformed package-lock.json: {exc}") from exc
    if not isinstance(data, dict):
        raise ManifestError("malformed package-lock.json: root is not an object")

    seen: set[tuple[str, str | None]] = set()
    deps: list[CryptoDependency] = []

    packages = data.get("packages")
    if isinstance(packages, dict):
        _collect_from_packages(packages, path, seen, deps)
    else:
        dependencies = data.get("dependencies")
        if isinstance(dependencies, dict):
            _collect_from_dependencies(dependencies, path, seen, deps)

    return deps


def _add(
    name: str,
    version: str | None,
    path: Path,
    seen: set[tuple[str, str | None]],
    deps: list[CryptoDependency],
) -> None:
    key = (name, version)
    if key in seen:
        return
    seen.add(key)
    purl = npm_purl(name, version)
    if purl is None:
        return
    deps.append(
        CryptoDependency(
            purl=purl,
            name=name,
            version=version,
            ecosystem="npm",
            declared_in=path,
            introduces_algorithms=lookup_introduces("npm", name),
        )
    )


def _collect_from_packages(
    packages: dict[str, Any],
    path: Path,
    seen: set[tuple[str, str | None]],
    deps: list[CryptoDependency],
) -> None:
    for key, entry in packages.items():
        # Empty string key is the root project — skip it.
        if not key:
            continue
        if not isinstance(entry, dict):
            continue
        # Derive the package name from the last "node_modules/<name>" segment.
        idx = key.rfind(_NODE_MODULES)
        if idx == -1:
            continue
        name = key[idx + len(_NODE_MODULES):]
        if not name:
            continue
        version_raw = entry.get("version")
        version = version_raw if isinstance(version_raw, str) else None
        _add(name, version, path, seen, deps)


def _collect_from_dependencies(
    dependencies: dict[str, Any],
    path: Path,
    seen: set[tuple[str, str | None]],
    deps: list[CryptoDependency],
) -> None:
    # Iterative flatten of the v1 nesting: recursion made the reachable depth
    # depend on the caller's stack, silently truncating a deep-but-valid lock
    # npm accepts to a stack-dependent partial inventory (round 10).
    stack = [dependencies]
    while stack:
        current = stack.pop()
        for name, entry in current.items():
            if not isinstance(entry, dict):
                continue
            version_raw = entry.get("version")
            version = version_raw if isinstance(version_raw, str) else None
            _add(name, version, path, seen, deps)
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                stack.append(nested)
