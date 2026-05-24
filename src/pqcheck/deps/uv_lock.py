"""Parser for uv.lock v1.

Emits one CryptoDependency per (name, version) pair declared in the
[[package]] array. uv.lock pins exact versions for every resolved
package — version is None only for workspace members that don't carry
their own version key.

Lookups in packages.py use the lowercased name (PEP 503 normalization).
The model preserves the originally-declared casing in `name` for
display purposes; PURLs and catalog lookups use the normalized form.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pqcheck.deps.base import pypi_purl, safe_read_bytes
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

    packages = data.get("package")
    if not isinstance(packages, list):
        return []

    seen: set[tuple[str, str | None]] = set()
    deps: list[CryptoDependency] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        version_raw = entry.get("version")
        # Empty/blank version normalizes to None (matches the pom parser) so an
        # empty version qualifier never reaches the PURL.
        version = version_raw if isinstance(version_raw, str) and version_raw else None
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(
            CryptoDependency(
                purl=pypi_purl(name, version),
                name=name,
                version=version,
                ecosystem="pypi",
                declared_in=path,
                introduces_algorithms=lookup_introduces("pypi", name),
            )
        )
    return deps
