"""Shared helpers for dependency-manifest parsers.

File-size cap, safe byte-level reader, PURL builders, and a minimal
PEP 508 requirement-name extractor. Parser bodies in this package stay
small by composing these primitives.
"""

from __future__ import annotations

import re
from pathlib import Path

from packageurl import PackageURL

MAX_FILE_BYTES = 5 * 1024 * 1024


def safe_read_bytes(path: Path) -> bytes | None:
    """Read a file as bytes, returning None on any error or oversize.

    Failure modes (return None): path missing, path is a directory,
    OS read error, file larger than MAX_FILE_BYTES. Callers treat None
    as "skip this file" — never raise. Matches the scanner's per-file
    exception-swallowing contract.
    """
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        return path.read_bytes()
    except OSError:  # pragma: no cover - TOCTOU: stat succeeded but read failed
        return None


def pypi_purl(name: str, version: str | None) -> str:
    return PackageURL(type="pypi", name=name.lower(), version=version).to_string()


def maven_purl(group_id: str, artifact_id: str, version: str | None) -> str:
    return PackageURL(
        type="maven", namespace=group_id, name=artifact_id, version=version
    ).to_string()


# PEP 508 distribution-name grammar: a letter or digit followed by any of
# letters, digits, dot, hyphen, underscore. We do not validate the full
# grammar — we only extract the leading name token.
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def extract_pep508_name(requirement: str) -> str | None:
    """Extract the distribution name from a PEP 508 requirement string.

    Examples:
      "cryptography"                                    -> "cryptography"
      "cryptography>=43.0.0"                            -> "cryptography"
      "cryptography[ssh] >= 43.0.0 ; python_version..." -> "cryptography"
      ">=1.0"                                           -> None
      ""                                                -> None
    """
    match = _NAME_RE.match(requirement)
    if match is None:
        return None
    return match.group(1)
