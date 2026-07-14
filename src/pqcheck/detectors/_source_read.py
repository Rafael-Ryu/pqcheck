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


class ResourceLimitError(Exception):
    """A resource guard skipped a file the scan would otherwise analyze.

    Distinct from the silent skips (missing/symlink/non-regular file): those
    are policy, while a file dropped by a size/line/node cap is real input the
    scan did NOT cover. Returning the same empty findings as a clean file
    would let harmless filler suppress real crypto (fail-open), so detectors
    raise this instead and the scanner records it in `ScanResult.errors` as an
    incomplete-scan diagnostic. Never partial findings — a truncated parse
    cannot prove syntax boundaries.
    """


def read_source_bytes(path: Path, *, max_bytes: int = MAX_SOURCE_BYTES) -> bytes | None:
    """Read a source file as bytes; None on unreadable, raises on oversize.

    Returns None for: missing path, symlink, non-regular file (FIFO/device/
    socket/directory) — deliberate silent skips. A file larger than
    `max_bytes` (or one that grows past the cap between fstat and read)
    raises ResourceLimitError: it is analyzable input the scan is dropping,
    which must surface as an incomplete-scan diagnostic, not a clean result.
    `max_bytes` defaults to MAX_SOURCE_BYTES; the key-material detector
    passes a smaller cap (see key_material.py).

    Open uses O_NOFOLLOW (reject symlinks) and O_NONBLOCK (a FIFO opens
    immediately, then the S_ISREG guard rejects it). fstat and read run on the
    same fd, closing the TOCTOU between the size check and the read.

    Windows has neither flag (first hit by the wheel smoke test): there the
    lstat pre-check below is the symlink gate — best-effort rather than
    race-free, acceptable since Windows symlink creation needs elevated
    rights. O_BINARY keeps the CRT's text-mode translation off.
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
    except (OSError, ValueError):  # ValueError: embedded NUL in path
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > max_bytes:
            raise ResourceLimitError(
                f"file exceeds {max_bytes} bytes; skipped (scan incomplete)"
            )
        chunks: list[bytes] = []
        budget = max_bytes + 1
        while budget > 0:
            chunk = os.read(fd, min(budget, _READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
        if budget == 0:
            raise ResourceLimitError(
                f"file exceeds {max_bytes} bytes; skipped (scan incomplete)"
            )
    except OSError:  # pragma: no cover - fstat/read on an open fd is well-defined
        return None
    finally:
        os.close(fd)
    return b"".join(chunks)
