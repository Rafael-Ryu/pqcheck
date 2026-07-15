import sys
import time
from pathlib import Path

import pytest

from pqcheck.deps.base import MAX_FILE_BYTES, ManifestError
from pqcheck.deps.go_mod import lex_go_mod_line, parse

_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "deps"


def test_parse_basic_single_line_require(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\ngo 1.22\n\nrequire github.com/golang-jwt/jwt/v5 v5.2.1\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert len(deps) == 1
    d = deps[0]
    assert d.name == "github.com/golang-jwt/jwt/v5"
    assert d.version == "v5.2.1"
    assert d.ecosystem == "golang"
    assert d.declared_in == f


def test_parse_basic_block_require(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    pkcs8_ver = "v0.0.0-20240424034433-3c2c7870ae76"
    f.write_text(
        "module example.com/app\n\ngo 1.22\n\nrequire (\n"
        "\tgolang.org/x/crypto v0.21.0\n"
        f"\tgithub.com/youmark/pkcs8 {pkcs8_ver}\n)\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert len(deps) == 2
    by_name = {d.name: d for d in deps}
    assert by_name["golang.org/x/crypto"].version == "v0.21.0"
    assert by_name["github.com/youmark/pkcs8"].version == pkcs8_ver


def test_parse_skips_malformed_module_path_keeps_valid(tmp_path: Path) -> None:
    # A module path ending in "/" has an empty name segment, which PackageURL
    # rejects. The parser must skip that one line and still emit the valid
    # sibling — a single bad entry must never crash parse() or discard the
    # whole file (never-raise contract).
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\ngo 1.22\n\nrequire (\n"
        "\tgithub.com/foo/ v1.2.3\n"
        "\tgolang.org/x/crypto v0.21.0\n)\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert {d.name for d in deps} == {"golang.org/x/crypto"}


def test_parse_block_with_trailing_comment_on_open_paren(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire ( // pinned deps\n\tgolang.org/x/crypto v0.21.0\n)\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].name == "golang.org/x/crypto"
    assert deps[0].version == "v0.21.0"


def test_parse_indirect_comment_stripped(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire (\n\tgolang.org/x/crypto v0.21.0 // indirect\n)\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].version == "v0.21.0"
    assert deps[0].name == "golang.org/x/crypto"


def test_parse_block_skips_compact_comment_line(tmp_path: Path) -> None:
    # A full-line comment inside a require block with no space after `//`
    # (`//evil v1.0.0`) shape-matches the module-line regex. Without a comment
    # guard the parser forges a dependency named `//evil`. go.mod's lexer treats
    # the whole line as a comment, so it must yield no dependency.
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire (\n"
        "\t//evil v1.0.0\n"
        "\tgolang.org/x/crypto v0.21.0\n)\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert {d.name for d in deps} == {"golang.org/x/crypto"}


def test_parse_integrity_unknown_when_no_go_sum(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    # No go.sum to cross-reference: no integrity claim in either direction.
    assert all(d.integrity_verified is None for d in deps)


def test_parse_integrity_unverified_when_go_sum_lacks_entry(tmp_path: Path) -> None:
    # go.sum is the cryptographic checksum companion to go.mod. A require whose
    # (module, version) is absent from a present go.sum is not checksum-pinned —
    # the tamper signal the spec asks us to surface.
    (tmp_path / "go.mod").write_text(
        "module example.com/app\n\nrequire (\n"
        "\tgolang.org/x/crypto v0.21.0\n"
        "\tgithub.com/foo/bar v1.0.0\n)\n",
        encoding="utf-8",
    )
    (tmp_path / "go.sum").write_text(
        "golang.org/x/crypto v0.21.0/go.mod h1:abc=\n"
        "golang.org/x/crypto v0.21.0 h1:def=\n",
        encoding="utf-8",
    )
    by_name = {d.name: d for d in parse(tmp_path / "go.mod")}
    assert by_name["golang.org/x/crypto"].integrity_verified is True
    assert by_name["github.com/foo/bar"].integrity_verified is False


def test_parse_purl_three_part_path(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire github.com/golang-jwt/jwt/v5 v5.2.1\n",
        encoding="utf-8",
    )
    deps = parse(f)
    # github.com/golang-jwt/jwt/v5: namespace=github.com/golang-jwt/jwt, name=v5
    # (the PURL path round-trips to the full module path either way)
    assert deps[0].purl == "pkg:golang/github.com/golang-jwt/jwt/v5@v5.2.1"


def test_parse_purl_two_part_path(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    # golang.org/x/crypto: namespace=golang.org/x, name=crypto
    assert deps[0].purl == "pkg:golang/golang.org/x/crypto@v0.21.0"


def test_parse_purl_bare_name(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire stdlib v1.0.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert deps[0].purl == "pkg:golang/stdlib@v1.0.0"


def test_parse_deduplicates(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\n"
        "require golang.org/x/crypto v0.21.0\n"
        "require golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert len(deps) == 1


def test_parse_ignores_non_require_directives(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\ngo 1.22\n\ntoolchain go1.22.3\n\n"
        "require golang.org/x/crypto v0.21.0\n\n"
        "replace golang.org/x/crypto => ./local\n\n"
        "exclude golang.org/x/crypto v0.20.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].name == "golang.org/x/crypto"


def test_parse_ecosystem_is_golang(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert all(d.ecosystem == "golang" for d in deps)


def test_parse_introduces_algorithms_empty_for_unknown(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/app\n\nrequire github.com/unknown/pkg v1.0.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert deps[0].introduces_algorithms == ()


def test_parse_invalid_raises_manifest_error(tmp_path: Path) -> None:
    f = _FIXTURES / "gomod_invalid.mod"
    with pytest.raises(ManifestError):
        parse(f)


def test_parse_unclosed_require_block_raises_manifest_error(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text("module example.com/broken\nrequire (\n  golang.org/x/crypto v0.40.0\n")
    with pytest.raises(ManifestError, match="unclosed require block"):
        parse(f)


def test_parse_missing_file_returns_empty(tmp_path: Path) -> None:
    assert parse(tmp_path / "go.mod") == []


def test_parse_no_require_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text("module example.com/app\n\ngo 1.22\n", encoding="utf-8")
    assert parse(f) == []


def test_parse_unterminated_require_block_terminates_promptly(tmp_path: Path) -> None:
    # A go.mod with many `require (` openers and no closing `)` used to trigger
    # catastrophic regex backtracking: the lazy DOTALL block pattern rescanned
    # to EOF from every opener (~O(n^2)). A hostile repo can ship such a file
    # under the read cap, so the parser must stay linear and finish promptly.
    f = tmp_path / "go.mod"
    f.write_text("module example.com/app\n\n" + "require (\n" * 8000, encoding="utf-8")
    start = time.perf_counter()
    with pytest.raises(ManifestError):
        parse(f)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0


def test_parse_fixture_basic(tmp_path: Path) -> None:
    f = _FIXTURES / "gomod_basic.mod"
    deps = parse(f)
    by_name = {d.name: d for d in deps}
    assert "github.com/golang-jwt/jwt/v5" in by_name
    assert "golang.org/x/crypto" in by_name
    assert "github.com/youmark/pkcs8" in by_name
    assert by_name["github.com/golang-jwt/jwt/v5"].version == "v5.2.1"
    assert by_name["golang.org/x/crypto"].version == "v0.21.0"


def test_parse_ignores_non_go_line_terminators(tmp_path: Path) -> None:
    # go.mod's lexer terminates a line only on \n. A form-feed (\x0c) is not a
    # line break to Go, so a `require` smuggled after one on the same physical
    # line must not be parsed as a second dependency. str.splitlines() would
    # split here and forge evil.example/pkg.
    f = tmp_path / "go.mod"
    f.write_bytes(
        b"module example.com/m\n\n"
        b"require golang.org/x/crypto v0.21.0\x0crequire evil.example/pkg v9.9.9\n"
    )
    # The physical line now carries extra tokens the require grammar rejects,
    # so the file is malformed (as it is to go itself) — never a parse that
    # quietly includes or excludes the smuggled entry.
    with pytest.raises(ManifestError):
        parse(f)


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/dep",  # missing version (Codex 2.4 reproducer)
        "require",  # bare directive
        "require example.com/dep 1.2.3",  # version without the v prefix
        "require example.com/dep v1.2.3 extra",  # trailing junk
        "require ( example.com/dep v1.0.0 )",  # one-line paren block
    ],
)
def test_malformed_require_outside_block_raises(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="invalid require"):
        parse(f)


@pytest.mark.parametrize(
    "entry",
    [
        "example.com/dep",  # missing version inside the block
        "example.com/dep 1.2.3",  # bad version shape
        "example.com/dep v1.0.0 junk",  # trailing junk
    ],
)
def test_malformed_require_block_entry_raises(tmp_path: Path, entry: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(
        f"module example.com/m\nrequire (\n\t{entry}\n)\n", encoding="utf-8"
    )
    with pytest.raises(ManifestError, match="invalid require entry"):
        parse(f)


def test_require_block_without_space_before_paren_parses(tmp_path: Path) -> None:
    # go.mod's lexer treats `(` as its own token, so `require(` opens a block.
    # A whitespace-split parser silently ignored the whole block — the entire
    # dependency inventory vanished from the scan.
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/m\nrequire(\n\tgolang.org/x/crypto v0.21.0\n)\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert [d.name for d in deps] == ["golang.org/x/crypto"]


def test_other_directives_stay_ignored(tmp_path: Path) -> None:
    # Unknown or out-of-scope directives (even odd ones) do not feed the
    # require inventory and must not fail the parse.
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/m\ngo 1.24\nweirddirective foo\n"
        "replace a => ../b\nrequire golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    deps = parse(f)
    assert [d.name for d in deps] == ["golang.org/x/crypto"]


@pytest.mark.parametrize(
    "line",
    [
        "module",  # missing path
        "module example.com/m extra",  # trailing junk
        "go",  # missing version
        "go nope",  # not a go version
        "go nope extra",  # junk + extra token
        "go 1.22 extra",  # trailing junk
        "toolchain",  # missing name
        "toolchain go1.22 extra",  # trailing junk
        "replace example.com/x =>",  # missing replacement
        "replace example.com/x",  # no arrow
        "replace => ../x",  # missing original
        "replace ../x => example.com/y v1.0.0",  # dir-shaped original
        "exclude example.com/x",  # missing version
        "exclude example.com/x 1.2.3",  # version without v prefix
        "retract",  # missing version
        "retract [v1.0.0,] junk",  # half-open interval + junk
        "retract v1.0.0 v1.1.0",  # two bare versions
    ],
)
def test_malformed_known_directive_single_line_raises(tmp_path: Path, line: str) -> None:
    # Item 6 (Codex round 4): every known directive is validated against
    # go.mod's grammar, not just require — a malformed known directive means
    # `go` itself refuses the file, so a silent accept passes off a partial
    # inventory as complete.
    f = tmp_path / "go.mod"
    f.write_text(f"{line}\nrequire golang.org/x/crypto v0.21.0\n", encoding="utf-8")
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


@pytest.mark.parametrize(
    "block",
    [
        "module (\na b\n)",  # two tokens in a module block entry
        "exclude (\nexample.com/x\n)",  # missing version
        "replace (\nexample.com/x =>\n)",  # missing replacement
        "retract (\n[v1.0.0,] junk\n)",  # half-open interval + junk
        "go (\n1.22\n)",  # go has no block form
        "toolchain (\ngo1.22\n)",  # toolchain has no block form
    ],
)
def test_malformed_known_directive_block_form_raises(tmp_path: Path, block: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"{block}\nrequire golang.org/x/crypto v0.21.0\n", encoding="utf-8")
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


@pytest.mark.parametrize(
    "snippet",
    [
        "module example.com/m",
        'module "example.com/m"',  # quoted path is valid go.mod
        "module (\nexample.com/m\n)",  # block form is in the grammar
        "go 1.22",
        "go 1.21rc1",
        "go 1.22.3",
        "toolchain go1.22.3",
        "toolchain default",
        "exclude example.com/x v1.0.0",
        "exclude (\nexample.com/x v1.0.0 // broken\n)",
        "replace example.com/x => ../local",
        "replace example.com/x v1.0.0 => example.com/y/v2 v2.0.0",
        'replace "example.com/x" => "./local dir"',  # quoted path with a space
        "replace (\nexample.com/x => ./l\n)",
        "retract v1.0.0",
        "retract [v1.0.0, v1.1.0]",
        "retract [v1.0.0,v1.1.0]",
        "retract (\nv1.0.0 // broken\n[v1.0.0, v1.1.0]\n)",
        "tool example.com/tool",  # valid unknown/future directives stay ignored
        "godebug x=y",
        "weirddirective foo bar",
    ],
)
def test_valid_directives_accepted(tmp_path: Path, snippet: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"{snippet}\nrequire golang.org/x/crypto v0.21.0\n", encoding="utf-8")
    assert [d.name for d in parse(f)] == ["golang.org/x/crypto"]


@pytest.mark.skipif(sys.platform == "win32", reason="backslash paths are dir-shaped on Windows")
def test_backslash_replacement_rejected_on_posix(tmp_path: Path) -> None:
    # `..\outside\pkg` is not a go directory path on POSIX (dir_shaped is
    # platform-aware, matching the boundary check in go_module_detector);
    # on Windows go itself accepts backslash paths, so this only raises here.
    f = tmp_path / "go.mod"
    f.write_text(
        "module example.com/m\nreplace example.com/x => ..\\outside\\pkg\n", encoding="utf-8"
    )
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


def test_unlexable_line_raises(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text('module example.com/m\nrequire "untermin\n', encoding="utf-8")
    with pytest.raises(ManifestError, match="cannot be lexed"):
        parse(f)


def test_unclosed_replace_block_raises(tmp_path: Path) -> None:
    f = tmp_path / "go.mod"
    f.write_text("module example.com/m\nreplace (\nexample.com/x => ./l\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="unclosed replace block"):
        parse(f)


def test_quoted_require_path_is_unquoted(tmp_path: Path) -> None:
    # go.mod's lexer strips the quotes; the dependency name must not keep them.
    f = tmp_path / "go.mod"
    f.write_text(
        'module example.com/m\nrequire "golang.org/x/crypto" v0.21.0\n', encoding="utf-8"
    )
    deps = parse(f)
    assert [d.name for d in deps] == ["golang.org/x/crypto"]


def test_oversized_go_sum_reports_skip_and_keeps_inventory(tmp_path: Path) -> None:
    # Item 2 (Codex round 4): a go.sum skipped by the size cap must not read
    # as "no checksum companion exists" — the inventory survives with no
    # integrity claim, and the skip lands in the caller's error sink.
    (tmp_path / "go.mod").write_text(
        "module example.com/m\nrequire golang.org/x/crypto v0.21.0\n", encoding="utf-8"
    )
    (tmp_path / "go.sum").write_bytes(
        b"golang.org/x/crypto v0.21.0 h1:AAAA\n" + b"#" * (MAX_FILE_BYTES + 1)
    )
    errors: list[str] = []
    deps = parse(tmp_path / "go.mod", errors=errors)
    assert [d.name for d in deps] == ["golang.org/x/crypto"]
    assert deps[0].integrity_verified is None
    assert len(errors) == 1
    assert str(tmp_path / "go.sum") in errors[0]
    assert "ManifestError" in errors[0]


def test_non_utf8_go_sum_reports_skip_and_keeps_inventory(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/m\nrequire golang.org/x/crypto v0.21.0\n", encoding="utf-8"
    )
    (tmp_path / "go.sum").write_bytes(b"\xff\xfe not utf-8")
    errors: list[str] = []
    deps = parse(tmp_path / "go.mod", errors=errors)
    assert deps[0].integrity_verified is None
    assert len(errors) == 1
    assert "malformed go.sum" in errors[0]


def test_go_sum_skip_without_error_sink_still_parses(tmp_path: Path) -> None:
    # Callers that pass no sink (direct API use) keep the old behavior:
    # inventory preserved, no integrity claim, no crash.
    (tmp_path / "go.mod").write_text(
        "module example.com/m\nrequire golang.org/x/crypto v0.21.0\n", encoding="utf-8"
    )
    (tmp_path / "go.sum").write_bytes(b"#" * (MAX_FILE_BYTES + 1))
    deps = parse(tmp_path / "go.mod")
    assert deps[0].integrity_verified is None


# --- Round 5: version grammar per x/mod, full interpreted-string escapes ---


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/a vbanana",  # not a semver (round-5 reproducer)
        "require example.com/a v01.2.3",  # leading zero in a numeric part
        "require example.com/a v1.2.3-01",  # leading zero in numeric prerelease
        "exclude example.com/a vbanana",
        "replace example.com/a vbanana => example.com/b v1.0.0",
        "replace example.com/a => example.com/b vbanana",
        "go 01.24",  # leading zero (round-5 reproducer)
        "go 1",  # modfile's GoVersionRE requires a minor
        "go 1.024",
        "toolchain gopher",  # round-5 reproducer
        "toolchain go",  # bare prefix is not a toolchain name
        "toolchain go2.0",  # modfile's ToolchainRE only admits go1 releases
    ],
)
def test_invalid_version_tokens_raise(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/a v1.2",  # x/mod semver is lax: minor/patch optional
        "require example.com/a v1",
        "require example.com/a v1.2.3-pre.1",
        "require example.com/a v2.0.0+incompatible",
        "require example.com/a v0.0.0-20240424034433-3c2c7870ae76",  # pseudo-version
        "require example.com/a v1.2.3-0.20240101000000-abcdef123456",
        "go 1.10",
        "go 1.21rc1",
        "toolchain go1",
        "toolchain go1.22.3-custom",
        "retract [v1.0.0, v1.1.0-pre]",
    ],
)
def test_valid_version_tokens_accepted(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    parse(f)


@pytest.mark.parametrize(
    ("snippet", "decoded"),
    [
        ('replace example.com/a => "./vendor\\x20dir"', "./vendor dir"),  # round-5 reproducer
        ('replace example.com/a => "./v\\tdir"', "./v\tdir"),
        ('replace example.com/a => "./caf\\u00e9"', "./café"),
        ('replace example.com/a => "./\\U0001F512lock"', "./\U0001f512lock"),
        ('replace example.com/a => "./\\101bc"', "./Abc"),  # 3-digit octal
        ('replace example.com/a => "./a\\\\b\\"c"', './a\\b"c'),
    ],
)
def test_go_escapes_in_interpreted_strings_accepted(
    tmp_path: Path, snippet: str, decoded: str
) -> None:
    # Go's own lexer applies strconv.Unquote to interpreted strings; a lexer
    # modelling only \\ and \" rejected go.mod files Go accepts (round 5).
    tokens = lex_go_mod_line(snippet.split(" ", 1)[1])
    assert tokens is not None and tokens[-1] == decoded
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{snippet}\n", encoding="utf-8")
    parse(f)  # must not raise


@pytest.mark.parametrize(
    "string",
    [
        '"\\q"',  # unknown escape
        '"\\x2"',  # truncated hex
        '"\\12"',  # octal needs exactly three digits
        '"\\ud800xyz"',  # surrogate code point
        '"\\U00110000aa"',  # beyond U+10FFFF
        '"\\xff"',  # non-ASCII byte: raw byte to Go, unmappable to str
        '"\\x80"',
        '"\\200"',  # octal spelling of the same non-ASCII byte
        '"\\',  # backslash at end of line
    ],
)
def test_invalid_escapes_fail_closed(tmp_path: Path, string: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module {string}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="cannot be lexed"):
        parse(f)


# --- Round 6: path-major, canonicalization, raw strings, singletons ---


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/short v7-rc.1",  # suffix after short form (round-6 reproducer)
        "require example.com/nosuffix v9.1.2",  # major 9 without /v9 (round-6 reproducer)
        "require example.com/x/v2 v3.0.0",  # /v2 suffix disagreeing with major
        "require gopkg.in/yaml.v2 v3.0.1",  # gopkg.in suffix disagreeing with major
        "require gopkg.in/nodot v1.0.0",  # gopkg.in path without its .vN suffix
        "exclude example.com/nosuffix v9.1.2",  # same check applies to exclude
        "replace example.com/a v9.0.0 => ./local",  # LHS major without suffix
        "require `example.com/raw` v1.2.3",  # raw string arg: go refuses (round-6)
        "module `example.com/m`",
    ],
)
def test_round6_invalid_forms_raise(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    body = f"{line}\n" if line.startswith("module") else f"module example.com/m\n{line}\n"
    f.write_text(body, encoding="utf-8")
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/x/v2 v2.1.0",  # suffix agreeing with major
        "require gopkg.in/yaml.v2 v2.4.0",
        "require gopkg.in/yaml.v0 v0.1.0",
        "require example.com/x v2.0.0+incompatible",  # exempt without a suffix
        "require example.com/x v1.4.5+incompatible",
    ],
)
def test_round6_valid_forms_accepted(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    parse(f)


def test_versions_canonicalized_for_purl_and_go_sum(tmp_path: Path) -> None:
    # modfile's CanonicalVersion: `v0` and `v0.0.0` are one version, and
    # ordinary build metadata is dropped — the inventory, PURL, and go.sum
    # matching must all see the canonical value (round-6 reproducer).
    (tmp_path / "go.mod").write_text(
        "module example.com/m\nrequire (\n"
        "\texample.com/shortzero v0\n"
        "\texample.com/meta v1.4.5+Build.007\n)\n",
        encoding="utf-8",
    )
    (tmp_path / "go.sum").write_text(
        "example.com/shortzero v0.0.0 h1:fresh\nexample.com/meta v1.4.5 h1:fresh\n",
        encoding="utf-8",
    )
    by_name = {d.name: d for d in parse(tmp_path / "go.mod")}
    assert by_name["example.com/shortzero"].version == "v0.0.0"
    assert by_name["example.com/shortzero"].purl == "pkg:golang/example.com/shortzero@v0.0.0"
    assert by_name["example.com/shortzero"].integrity_verified is True
    assert by_name["example.com/meta"].version == "v1.4.5"
    assert by_name["example.com/meta"].integrity_verified is True


def test_canonicalization_preserves_incompatible_and_dedups(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text(
        "module example.com/m\n"
        "require example.com/x v2.0.0+incompatible\n"
        "require example.com/y v1.2\n"
        "require example.com/y v1.2.0\n",  # same version once canonicalized
        encoding="utf-8",
    )
    deps = parse(tmp_path / "go.mod")
    by_name = {d.name: d for d in deps}
    assert by_name["example.com/x"].version == "v2.0.0+incompatible"
    assert sum(1 for d in deps if d.name == "example.com/y") == 1
    assert by_name["example.com/y"].version == "v1.2.0"


@pytest.mark.parametrize(
    "body",
    [
        "module example.com/m\nmodule example.com/again\n",
        "module example.com/m\ngo 1.24\ngo 1.25\n",
        "module example.com/m\ntoolchain default\ntoolchain go1.25.4\n",  # round-6 reproducer
        "module example.com/m\nmodule (\nexample.com/again\n)\n",  # block form counts too
        "module (\nexample.com/m\nexample.com/again\n)\n",  # two entries in one block
    ],
)
def test_repeated_singleton_directives_raise(tmp_path: Path, body: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(body, encoding="utf-8")
    with pytest.raises(ManifestError, match="repeated"):
        parse(f)


# --- Round 7: SplitPathVersion/CheckPathMajor parity ---


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/engine/v12 v12.0.1-0.20260714010203-deadbeefcafe",  # major >= 10
        "require example.com/big/v20 v20.0.0",
        "require gopkg.in/acme/codec.v4-unstable v4.2.1",  # -unstable suffix
        "require gopkg.in/verify.v1 v0.0.0-20190101010101-abcdefabcdef",  # legacy pseudo-version
        "require example.com/lib/v2 v2.4.0+incompatible",  # matching suffix accepts any build
        "require gopkg.in/lib.v2 v2.4.0+incompatible",
        "replace example.com/a/v3 v3.0.0 => example.com/b/v7 v6.9.0",  # RHS not major-checked
    ],
)
def test_round7_valid_forms_accepted(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    parse(f)


@pytest.mark.parametrize(
    "line",
    [
        "require example.com/widget/v1 v1.9.3",  # /v1 suffix: invalid module path
        "require example.com/widget/v0 v0.9.3",
        "require example.com/widget/v02 v2.0.0+incompatible",  # zero-padded suffix
        "require example.com/widget/v1.2 v1.2.0",  # dotted suffix
        "require gopkg.in/lib.v01 v1.0.0",  # gopkg.in zero-padded
        "require gopkg.in/codec.v4-unstable v5.0.0",  # -unstable major mismatch
        "require example.com/engine/v12 v11.0.0",  # major >= 10 mismatch
        "replace example.com/old/v8 v7.2.0 => example.com/new/v5 v5.0.0",  # LHS mismatch
        "replace example.com/bad/v1 => ./local",  # invalid LHS path suffix
    ],
)
def test_round7_invalid_forms_raise(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


@pytest.mark.parametrize(
    "line",
    [
        "replace example.com/a => example.com/b/v1 v1.0.0",  # round-8: RHS /v1 accepted by go
        "replace example.com/a => example.com/b/v0 v0.3.0",
        "replace example.com/a => example.com/b/v01 v1.0.0",  # zero-padded RHS suffix
        "replace example.com/a => example.com/b/v1.2 v1.2.0",  # dotted RHS suffix
        "replace example.com/a => gopkg.in/nodot v1.0.0",  # gopkg.in RHS without .vN
    ],
)
def test_round8_replace_rhs_not_suffix_checked(tmp_path: Path, line: str) -> None:
    # modfile's parseReplace never suffix-checks the replacement side; the
    # require inventory must survive these manifests (round-8 differential:
    # go mod edit -json accepts every one of them).
    f = tmp_path / "go.mod"
    f.write_text(
        f"module example.com/m\n{line}\nrequire golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    assert [d.name for d in parse(f)] == ["golang.org/x/crypto"]


# --- Round 9: retract values are unvalidated (dontFixRetract) ---


@pytest.mark.parametrize(
    "line",
    [
        "retract v1.9-rc.3",  # round-9 reproducer: short form + prerelease
        "retract v2-rc.11",
        "retract v2.3+orbit.14",
        "retract v02",
        "retract v2.3.04",
        "retract v2.",
        "retract vquasar",
        'retract "version with gap"',  # quoted value, spaces and all
        'retract ""',  # even the empty quoted token is accepted by go
        "retract [vnebula,vquasar]",
        "retract [v0.0.1, v2.3+]",
    ],
)
def test_round9_retract_values_unvalidated(tmp_path: Path, line: str) -> None:
    # modfile parses retract with dontFixRetract: the interval/singleton
    # STRUCTURE is enforced but the values are not semver-checked at parse
    # time — the require inventory must survive all of these (round-9
    # differential: go mod edit -json accepts every one).
    f = tmp_path / "go.mod"
    f.write_text(
        f"module example.com/m\n{line}\nrequire golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    assert [d.name for d in parse(f)] == ["golang.org/x/crypto"]


@pytest.mark.parametrize(
    "line",
    [
        "retract",  # no version at all
        "retract v1.0.0 v1.1.0",  # two bare tokens: go errors after the first
        "retract [v1.0.0,]",  # empty interval side
        "retract [v1.0.0,] junk",
        "retract [v1.0.0]",  # interval without a comma
    ],
)
def test_round9_retract_structure_still_enforced(tmp_path: Path, line: str) -> None:
    f = tmp_path / "go.mod"
    f.write_text(f"module example.com/m\n{line}\n", encoding="utf-8")
    with pytest.raises(ManifestError, match=r"malformed go\.mod"):
        parse(f)


# --- Round 10: quote provenance in retract, empty module token ---


def test_retract_quoted_singleton_resembling_interval_accepted(tmp_path: Path) -> None:
    # `retract "[not,an,interval]"` is a quoted STRING token to go's lexer —
    # a singleton version, not interval punctuation (round-10 reproducer).
    f = tmp_path / "go.mod"
    f.write_text(
        'module example.com/m\nretract "[not,an,interval]"\n'
        "require golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    assert [d.name for d in parse(f)] == ["golang.org/x/crypto"]


def test_empty_quoted_module_token_accepted(tmp_path: Path) -> None:
    # `module ""` is structurally valid to modfile.Parse (round-10) — the
    # require inventory must survive it.
    f = tmp_path / "go.mod"
    f.write_text('module ""\nrequire golang.org/x/crypto v0.21.0\n', encoding="utf-8")
    assert [d.name for d in parse(f)] == ["golang.org/x/crypto"]


def test_quoted_directive_verb_is_not_a_directive(tmp_path: Path) -> None:
    # A quoted verb is a string token, not a directive keyword — it must not
    # open a require block or feed the inventory (treated as unknown line).
    f = tmp_path / "go.mod"
    f.write_text(
        'module example.com/m\n"require" evil.example/pkg v9.9.9\n'
        "require golang.org/x/crypto v0.21.0\n",
        encoding="utf-8",
    )
    assert [d.name for d in parse(f)] == ["golang.org/x/crypto"]
