"""Parser for pip requirements.txt.

Scope is the common PEP 508 requirement lines: name, optional extras,
optional specifier set, optional environment marker, with full-line and
inline comments, backslash continuations, and per-requirement options
(`--hash=...`). A version is recorded only for an exact, wildcard-free
`==`/`===` pin — ranges resolve at install time and would be a guess.

Deliberately ignored, never followed: `-r`/`-c` includes (path-traversal
vector into files outside the scanned tree), editable installs, URLs and
local paths, and pip options. Variant filenames (requirements-dev.txt
etc.) are out of scope in v0.1 — the walker only routes the canonical
name here.
"""

from __future__ import annotations

import re
from pathlib import Path

from pqcheck.deps.base import ManifestError, pypi_purl, safe_read_bytes, strict_pep508_name
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

_EXACT_PIN_RE = re.compile(r"={2,3}\s*([A-Za-z0-9!+.*_-]+)")
_INLINE_COMMENT_RE = re.compile(r"\s+#.*$")

# PEP 508 named direct reference: `name [extras] @ URL [; marker]`. This is a
# NAMED requirement — dropping it with the unnamed-URL lines silently removed
# a real dependency from the inventory (round 10). The URL pins the version,
# which our exact-pin model records as None.
_DIRECT_REF_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*@\s*[^;\s]+\s*(;.*)?$"
)


def _logical_lines(text: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in text.split("\n"):
        if raw.endswith("\\"):
            pending += raw[:-1] + " "
            continue
        lines.append(pending + raw)
        pending = ""
    if pending:
        lines.append(pending)
    return lines


def _requirement_part(line: str) -> str | None:
    line = _INLINE_COMMENT_RE.sub("", line).strip()
    if not line or line.startswith(("#", "-")):
        return None  # comment, include (-r/-c), editable (-e), or pip option
    named_ref = _DIRECT_REF_RE.match(line)
    if named_ref is not None:
        return named_ref.group(1)  # `name @ URL`: keep the name, URL pins it
    if "://" in line or line.startswith((".", "/", "~")):
        return None  # unnamed URL or filesystem path, not a named requirement
    line = line.split(";", 1)[0]  # drop environment marker
    line = line.split(" --", 1)[0]  # drop per-requirement options (--hash=...)
    return line.strip() or None


def _exact_version(requirement: str) -> str | None:
    match = _EXACT_PIN_RE.search(requirement)
    if match is None:
        return None
    version = match.group(1)
    return None if "*" in version else version


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"malformed requirements.txt: {exc}") from exc

    seen: set[tuple[str, str | None]] = set()
    deps: list[CryptoDependency] = []
    for lineno, line in enumerate(_logical_lines(text), start=1):
        requirement = _requirement_part(line)
        if requirement is None:
            continue
        try:
            name = strict_pep508_name(requirement)
        except ValueError as exc:
            # pip/uv refuse the whole file on an invalid requirement — a
            # silent skip would pass off a partial inventory as complete.
            raise ManifestError(
                f"malformed requirements.txt: line {lineno}: {exc}"
            ) from exc
        version = _exact_version(requirement)
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        purl = pypi_purl(name, version)
        if purl is None:
            continue
        deps.append(
            CryptoDependency(
                purl=purl,
                name=name,
                version=version,
                ecosystem="pypi",
                declared_in=path,
                introduces_algorithms=lookup_introduces("pypi", name),
            )
        )
    return deps
