"""Shared helpers for dependency-manifest parsers.

File-size cap, safe byte-level reader, PURL builders, and a minimal
PEP 508 requirement-name extractor. Parser bodies in this package stay
small by composing these primitives.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path

from packageurl import PackageURL

MAX_FILE_BYTES = 5 * 1024 * 1024
_READ_CHUNK = 64 * 1024


def safe_read_bytes(path: Path) -> bytes | None:
    """Read a file as bytes, returning None on any error or oversize.

    Failure modes (return None): missing path, symlink, non-regular file
    (FIFO/device/socket/directory), file larger than MAX_FILE_BYTES, or
    a file that grows between fstat and read past the cap. Callers treat
    None as "skip this file" — never raise. Matches the scanner's
    per-file exception-swallowing contract.

    Open uses O_NOFOLLOW (reject symlinks) and O_NONBLOCK (FIFO opens
    return immediately) so a malicious repo cannot block the scanner
    via a symlink to /dev/zero or an unopened FIFO. fstat + read run
    against the same fd to close the TOCTOU between size check and
    read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > MAX_FILE_BYTES:
            return None
        chunks: list[bytes] = []
        budget = MAX_FILE_BYTES + 1
        while budget > 0:
            chunk = os.read(fd, min(budget, _READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
        if budget == 0:
            return None
    except OSError:  # pragma: no cover - fstat/read on an open fd is well-defined
        return None
    finally:
        os.close(fd)
    return b"".join(chunks)


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
