from pathlib import Path

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
