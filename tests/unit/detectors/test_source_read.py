import os
from pathlib import Path

import pytest

from pqcheck.detectors._source_read import MAX_SOURCE_BYTES, read_source_bytes


def test_reads_regular_file(tmp_path: Path) -> None:
    f = tmp_path / "a.go"
    f.write_bytes(b"package main\n")
    assert read_source_bytes(f) == b"package main\n"


def test_missing_file_returns_none(tmp_path: Path) -> None:
    assert read_source_bytes(tmp_path / "nope.go") is None


def test_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real.go"
    target.write_bytes(b"package main\n")
    link = tmp_path / "link.go"
    link.symlink_to(target)
    assert read_source_bytes(link) is None


def test_rejects_directory(tmp_path: Path) -> None:
    assert read_source_bytes(tmp_path) is None


def test_rejects_oversize_file(tmp_path: Path) -> None:
    f = tmp_path / "big.go"
    f.write_bytes(b"a" * (MAX_SOURCE_BYTES + 1))
    assert read_source_bytes(f) is None


def test_accepts_file_at_exact_cap(tmp_path: Path) -> None:
    f = tmp_path / "edge.go"
    f.write_bytes(b"a" * MAX_SOURCE_BYTES)
    assert read_source_bytes(f) == b"a" * MAX_SOURCE_BYTES


def test_nul_in_path_returns_none() -> None:
    # os.open raises ValueError (not OSError) on an embedded NUL; the reader
    # must still honor its never-raise contract.
    assert read_source_bytes(Path("a\x00b.go")) is None


def test_read_source_works_without_posix_open_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows has no O_NOFOLLOW/O_NONBLOCK; the lstat pre-check is the
    # symlink gate there.
    # raising=False: on Windows the flags are already absent — the test then
    # exercises the real platform path instead of erroring on the delattr.
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    f = tmp_path / "a.go"
    f.write_bytes(b"package main\n")
    assert read_source_bytes(f) == b"package main\n"
    link = tmp_path / "lnk.go"
    try:
        link.symlink_to(f)
    except OSError:
        pytest.skip("symlink creation unavailable (Windows without privilege)")
    assert read_source_bytes(link) is None
