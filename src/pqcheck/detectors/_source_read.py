"""Hardened, size-capped byte reader shared by source-code detectors.

Source files are capped at 2 MiB — generated or vendored blobs above that
are skipped rather than parsed. Dependency-manifest reading lives separately
in pqcheck.deps.base (5 MiB cap); the two are intentionally not merged.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

MAX_SOURCE_BYTES = 2 * 1024 * 1024
_READ_CHUNK = 64 * 1024


def read_source_bytes(path: Path) -> bytes | None:
    """Read a source file as bytes, returning None on any error or oversize.

    Returns None for: missing path, symlink, non-regular file (FIFO/device/
    socket/directory), file larger than MAX_SOURCE_BYTES, or a file that grows
    past the cap between fstat and read. Never raises — callers treat None as
    "skip this file".

    Open uses O_NOFOLLOW (reject symlinks) and O_NONBLOCK (a FIFO opens
    immediately, then the S_ISREG guard rejects it). fstat and read run on the
    same fd, closing the TOCTOU between the size check and the read.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, ValueError):  # ValueError: embedded NUL in path
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > MAX_SOURCE_BYTES:
            return None
        chunks: list[bytes] = []
        budget = MAX_SOURCE_BYTES + 1
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
