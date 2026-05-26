import time
from pathlib import Path

from pqcheck.deps.go_mod import parse

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


def test_parse_invalid_returns_empty(tmp_path: Path) -> None:
    f = _FIXTURES / "gomod_invalid.mod"
    assert parse(f) == []


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
    deps = parse(f)
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    assert deps == []


def test_parse_fixture_basic(tmp_path: Path) -> None:
    f = _FIXTURES / "gomod_basic.mod"
    deps = parse(f)
    by_name = {d.name: d for d in deps}
    assert "github.com/golang-jwt/jwt/v5" in by_name
    assert "golang.org/x/crypto" in by_name
    assert "github.com/youmark/pkcs8" in by_name
    assert by_name["github.com/golang-jwt/jwt/v5"].version == "v5.2.1"
    assert by_name["golang.org/x/crypto"].version == "v0.21.0"
