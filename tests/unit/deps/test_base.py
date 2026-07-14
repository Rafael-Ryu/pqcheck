import os
from pathlib import Path

import pytest

from pqcheck.deps.base import (
    MAX_FILE_BYTES,
    ManifestError,
    extract_pep508_name,
    golang_purl,
    maven_purl,
    npm_purl,
    pypi_purl,
    safe_read_bytes,
)


def test_pypi_purl_lowercases_name() -> None:
    assert pypi_purl("Cryptography", "43.0.0") == "pkg:pypi/cryptography@43.0.0"


def test_pypi_purl_without_version() -> None:
    assert pypi_purl("cryptography", None) == "pkg:pypi/cryptography"


def test_maven_purl_preserves_group_id_case() -> None:
    result = maven_purl("org.bouncycastle", "bcprov-jdk18on", "1.78")
    assert result == "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"


def test_maven_purl_without_version() -> None:
    result = maven_purl("org.bouncycastle", "bcprov-jdk18on", None)
    assert result == "pkg:maven/org.bouncycastle/bcprov-jdk18on"


# A name token can survive the parsers' shape checks (non-empty, slash-shaped)
# yet still be rejected by PackageURL — e.g. a module path ending in "/" yields
# an empty name segment. The builders must fail closed to None so one malformed
# entry is skipped rather than crashing parse() and discarding the whole file.
def test_golang_purl_returns_none_for_empty_trailing_segment() -> None:
    assert golang_purl("github.com/foo/", "v1.2.3") is None


def test_golang_purl_returns_none_for_bare_slash() -> None:
    assert golang_purl("/", "v1") is None


def test_npm_purl_returns_none_for_blank_name() -> None:
    assert npm_purl(" ", "1.0.0") is None


def test_pypi_purl_returns_none_for_blank_name() -> None:
    assert pypi_purl("   ", None) is None


def test_maven_purl_returns_none_for_empty_artifact() -> None:
    assert maven_purl("org.example", "", "1.0") is None


def test_extract_pep508_name_simple() -> None:
    assert extract_pep508_name("cryptography") == "cryptography"


def test_extract_pep508_name_with_version_spec() -> None:
    assert extract_pep508_name("cryptography>=43.0.0") == "cryptography"
    assert extract_pep508_name("cryptography==43.0.0") == "cryptography"
    assert extract_pep508_name("cryptography<2") == "cryptography"
    assert extract_pep508_name("cryptography ~= 43.0") == "cryptography"


def test_extract_pep508_name_with_extras() -> None:
    assert extract_pep508_name("cryptography[ssh]>=43.0.0") == "cryptography"
    assert extract_pep508_name("cryptography[ssh,extra]") == "cryptography"


def test_extract_pep508_name_with_marker() -> None:
    expr = 'cryptography>=43.0.0 ; python_version >= "3.12"'
    assert extract_pep508_name(expr) == "cryptography"


def test_extract_pep508_name_with_underscores_and_dashes() -> None:
    assert extract_pep508_name("typing_extensions") == "typing_extensions"
    assert extract_pep508_name("python-dateutil") == "python-dateutil"
    assert extract_pep508_name("backports.functools_lru_cache") == "backports.functools_lru_cache"


def test_extract_pep508_name_returns_none_for_empty_or_invalid() -> None:
    assert extract_pep508_name("") is None
    assert extract_pep508_name("   ") is None
    assert extract_pep508_name(">=1.0") is None


def test_safe_read_bytes_returns_content_for_small_file(tmp_path: Path) -> None:
    f = tmp_path / "small.txt"
    f.write_bytes(b"hello")
    assert safe_read_bytes(f) == b"hello"


def test_safe_read_bytes_raises_for_oversized_file(tmp_path: Path) -> None:
    # A manifest padded past the cap must surface as an incomplete inventory,
    # not vanish into a clean scan.
    f = tmp_path / "huge.txt"
    f.write_bytes(b"\x00" * (MAX_FILE_BYTES + 1))
    with pytest.raises(ManifestError):
        safe_read_bytes(f)


def test_safe_read_bytes_returns_none_for_missing_file(tmp_path: Path) -> None:
    assert safe_read_bytes(tmp_path / "does-not-exist") is None


def test_safe_read_bytes_returns_none_for_directory(tmp_path: Path) -> None:
    assert safe_read_bytes(tmp_path) is None


def test_safe_read_bytes_rejects_symlink_to_regular_file(tmp_path: Path) -> None:
    # Symlink to a real file outside the scan target must be rejected — the
    # emitted declared_in would otherwise point at the link, hiding the
    # actual source.
    target = tmp_path / "real.toml"
    target.write_bytes(b"[project]\nname = 'x'\n")
    link = tmp_path / "link.toml"
    link.symlink_to(target)
    assert safe_read_bytes(link) is None


def test_safe_read_bytes_rejects_symlink_to_dev_zero(tmp_path: Path) -> None:
    # Regression: symlink whose target is /dev/zero must not block the
    # read. O_NOFOLLOW makes os.open raise ELOOP/EMLINK; the S_ISREG
    # check is the second line of defense.
    if not Path("/dev/zero").exists():
        pytest.skip("/dev/zero unavailable on this platform")
    link = tmp_path / "zero.toml"
    link.symlink_to("/dev/zero")
    assert safe_read_bytes(link) is None


@pytest.mark.skipif(os.name == "nt", reason="Windows has no FIFOs")
def test_safe_read_bytes_rejects_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.toml"
    os.mkfifo(fifo)
    assert safe_read_bytes(fifo) is None


def test_safe_read_bytes_caps_growth_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # If a file grows between fstat and read past the cap, the loop must
    # bail with None rather than OOM.
    f = tmp_path / "small.toml"
    f.write_bytes(b"# small\n")
    big = b"a" * 65536

    def fake_read(fd: int, n: int) -> bytes:
        return big[:n]

    monkeypatch.setattr("pqcheck.deps.base.os.read", fake_read)
    with pytest.raises(ManifestError):
        safe_read_bytes(f)


def test_safe_read_works_without_posix_open_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Windows has no O_NOFOLLOW/O_NONBLOCK (first hit by the wheel smoke
    # test). The reader must still work, and the lstat pre-check must keep
    # rejecting symlinks when the race-free flag is unavailable.
    # raising=False: on Windows the flags are already absent — the test then
    # exercises the real platform path instead of erroring on the delattr.
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    f = tmp_path / "m.toml"
    f.write_bytes(b"data")
    assert safe_read_bytes(f) == b"data"
    link = tmp_path / "lnk.toml"
    try:
        link.symlink_to(f)
    except OSError:
        pytest.skip("symlink creation unavailable (Windows without privilege)")
    assert safe_read_bytes(link) is None
