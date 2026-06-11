from pathlib import Path

from pqcheck.deps.requirements_txt import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "requirements.txt"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_names_and_exact_versions(tmp_path: Path) -> None:
    f = _write(tmp_path, """
cryptography==43.0.0
requests>=2.31
pycryptodome
""")
    deps = {d.name: d.version for d in parse(f)}
    # only `==` pins an exact version; ranges and bare names carry None
    assert deps == {"cryptography": "43.0.0", "requests": None, "pycryptodome": None}


def test_parse_strips_extras_markers_and_inline_comments(tmp_path: Path) -> None:
    f = _write(tmp_path, """
# full-line comment
cryptography[ssh]==43.0.0  # inline comment
bar==2.0 ; python_version < "3.9"
""")
    deps = {d.name: d.version for d in parse(f)}
    assert deps == {"cryptography": "43.0.0", "bar": "2.0"}


def test_parse_joins_backslash_continuations_and_ignores_hashes(tmp_path: Path) -> None:
    f = _write(tmp_path, """
foo==1.0 \\
    --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \\
    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
""")
    [dep] = parse(f)
    assert (dep.name, dep.version) == ("foo", "1.0")


def test_parse_never_follows_includes(tmp_path: Path) -> None:
    # -r/-c includes are a traversal vector (../../etc) — the parser must
    # ignore them entirely, not resolve them.
    (tmp_path / "evil.txt").write_text("md5lib==1.0\n", encoding="utf-8")
    f = _write(tmp_path, """
-r evil.txt
-c ../constraints.txt
safe==1.0
""")
    assert [(d.name, d.version) for d in parse(f)] == [("safe", "1.0")]


def test_parse_skips_urls_paths_and_options(tmp_path: Path) -> None:
    f = _write(tmp_path, """
--index-url https://pypi.org/simple
-e .
./vendored/pkg
git+https://github.com/x/y.git#egg=y
https://example.com/pkg-1.0.tar.gz
ok==1.0
""")
    assert [d.name for d in parse(f)] == ["ok"]


def test_parse_wildcard_equality_is_not_an_exact_version(tmp_path: Path) -> None:
    f = _write(tmp_path, "foo==1.0.*\n")
    [dep] = parse(f)
    assert dep.version is None


def test_parse_populates_purl_ecosystem_and_catalog(tmp_path: Path) -> None:
    f = _write(tmp_path, "pycryptodome==3.20.0\n")
    [dep] = parse(f)
    assert dep.purl == "pkg:pypi/pycryptodome@3.20.0"
    assert dep.ecosystem == "pypi"
    assert dep.declared_in == f
    assert "RSA" in dep.introduces_algorithms


def test_parse_dedupes_repeated_pins(tmp_path: Path) -> None:
    f = _write(tmp_path, "foo==1.0\nFoo==1.0\nfoo==2.0\n")
    assert [(d.name, d.version) for d in parse(f)] == [("foo", "1.0"), ("foo", "2.0")]


def test_parse_never_raises_on_garbage(tmp_path: Path) -> None:
    f = tmp_path / "requirements.txt"
    f.write_bytes(b"\xff\xfe garbage \x00==1.0\n")
    assert parse(f) == []


def test_parse_missing_file_returns_empty(tmp_path: Path) -> None:
    assert parse(tmp_path / "requirements.txt") == []
