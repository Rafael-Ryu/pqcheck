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


class ManifestError(Exception):
    """A manifest was read but could not be parsed (syntax/decode failure).

    Distinct from the read failures `safe_read_bytes` swallows (missing,
    symlink, oversized — deliberate skips). A manifest the scanner *saw* and
    could not parse means the dependency inventory is incomplete, so the
    scanner records it in `ScanResult.errors` instead of reporting a clean
    scan over a silently dropped file.
    """


def safe_read_bytes(path: Path) -> bytes | None:
    """Read a file as bytes; None on unreadable, ManifestError on oversize.

    Silent failure modes (return None): missing path, symlink, non-regular
    file (FIFO/device/socket/directory) — deliberate skips. A file larger
    than MAX_FILE_BYTES (or one that grows past the cap between fstat and
    read) raises ManifestError instead: a manifest the scanner saw but did
    not read means the dependency inventory is incomplete, and padding a
    manifest past the cap must not buy a clean scan.

    Open uses O_NOFOLLOW (reject symlinks) and O_NONBLOCK (FIFO opens
    return immediately) so a malicious repo cannot block the scanner
    via a symlink to /dev/zero or an unopened FIFO. fstat + read run
    against the same fd to close the TOCTOU between size check and
    read.

    Windows has neither flag (first hit by the wheel smoke test): there
    the lstat pre-check below is the symlink gate — best-effort rather
    than race-free, acceptable since Windows symlink creation needs
    elevated rights. O_BINARY keeps the CRT's text-mode translation off.
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    try:
        if path.is_symlink():
            return None
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > MAX_FILE_BYTES:
            raise ManifestError(
                f"file exceeds {MAX_FILE_BYTES} bytes; skipped (inventory incomplete)"
            )
        chunks: list[bytes] = []
        budget = MAX_FILE_BYTES + 1
        while budget > 0:
            chunk = os.read(fd, min(budget, _READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
        if budget == 0:
            raise ManifestError(
                f"file exceeds {MAX_FILE_BYTES} bytes; skipped (inventory incomplete)"
            )
    except OSError:  # pragma: no cover - fstat/read on an open fd is well-defined
        return None
    finally:
        os.close(fd)
    return b"".join(chunks)


# A name token that passes a parser's shape check can still be rejected by
# PackageURL (e.g. an empty or whitespace-only name segment), which raises
# ValueError/TypeError. The builders catch that and return None so the caller
# skips the one bad entry instead of letting the exception escape parse() and
# discard every dependency in the file. CryptoDependency.purl is min_length=1,
# so None could never be a valid PURL anyway.
def pypi_purl(name: str, version: str | None) -> str | None:
    try:
        return PackageURL(type="pypi", name=name.lower(), version=version).to_string()
    except (ValueError, TypeError):
        return None


def maven_purl(group_id: str, artifact_id: str, version: str | None) -> str | None:
    try:
        return PackageURL(
            type="maven", namespace=group_id, name=artifact_id, version=version
        ).to_string()
    except (ValueError, TypeError):
        return None


def golang_purl(module_path: str, version: str | None) -> str | None:
    """Build a pkg:golang PURL from a Go module path.

    Go module paths are slash-separated: everything up to (but not including)
    the last segment is the namespace; the last segment is the name.  A bare
    path with no slash produces no namespace. Returns None on a path PackageURL
    rejects (e.g. one ending in "/", which yields an empty name segment).

    Examples:
      "github.com/foo/bar"      -> namespace="github.com/foo", name="bar"
      "golang.org/x/crypto"     -> namespace="golang.org/x",   name="crypto"
      "stdlib"                  -> namespace=None,              name="stdlib"
    """
    if "/" in module_path:
        namespace, _, name = module_path.rpartition("/")
    else:
        namespace, name = None, module_path
    try:
        return PackageURL(
            type="golang", namespace=namespace, name=name, version=version
        ).to_string()
    except (ValueError, TypeError):
        return None


def npm_purl(name: str, version: str | None) -> str | None:
    """Build a PURL for an npm package.

    Scoped packages (@scope/pkg) map namespace=@scope, name=pkg so the
    PURL round-trips correctly through packageurl-python's percent-encoding.
    Unscoped packages carry name only, no namespace. Returns None on a name
    PackageURL rejects (e.g. whitespace-only).
    """
    try:
        if name.startswith("@") and "/" in name:
            namespace, pkg_name = name.split("/", 1)
            return PackageURL(
                type="npm", namespace=namespace, name=pkg_name, version=version
            ).to_string()
        return PackageURL(type="npm", name=name, version=version).to_string()
    except (ValueError, TypeError):
        return None


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
