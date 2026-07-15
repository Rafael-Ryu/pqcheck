from pathlib import Path

import pytest

from pqcheck.deps.base import ManifestError
from pqcheck.deps.package_lock_json import _collect_from_dependencies, parse

_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "deps"


def _fixture(name: str) -> Path:
    return _FIXTURES / name


def test_parse_v1_flat_deps() -> None:
    deps = parse(_fixture("package_lock_v1.json"))
    by_name = {d.name: d for d in deps}
    assert "node-forge" in by_name
    assert by_name["node-forge"].version == "1.3.1"
    assert by_name["node-forge"].purl == "pkg:npm/node-forge@1.3.1"


def test_parse_utf8_bom_still_parses(tmp_path: Path) -> None:
    # A BOM'd lockfile made json.loads raise (JSON forbids a leading BOM),
    # which parse() swallowed into zero deps. utf-8-sig strips the BOM.
    f = tmp_path / "package-lock.json"
    f.write_bytes(
        b"\xef\xbb\xbf"
        + b'{"lockfileVersion":3,"packages":{'
        + b'"node_modules/node-forge":{"version":"1.3.1"}}}'
    )
    deps = parse(f)
    assert {d.name for d in deps} == {"node-forge"}


def test_parse_skips_blank_package_name_keeps_valid(tmp_path: Path) -> None:
    # A "node_modules/ " key yields a whitespace-only name that survives the
    # empty-name guard but breaks PackageURL. The parser must skip it and still
    # emit the valid sibling — never crash parse() (never-raise contract).
    f = tmp_path / "package-lock.json"
    f.write_text(
        '{"lockfileVersion":3,"packages":{'
        '"node_modules/ ":{"version":"1.0.0"},'
        '"node_modules/node-forge":{"version":"1.3.1"}}}',
        encoding="utf-8",
    )
    deps = parse(f)
    assert {d.name for d in deps} == {"node-forge"}


def test_parse_v1_nested_deps_flattened() -> None:
    deps = parse(_fixture("package_lock_v1.json"))
    by_name = {d.name: d for d in deps}
    # jws is a nested dependency inside jsonwebtoken
    assert "jws" in by_name
    assert by_name["jws"].version == "3.2.2"


def test_parse_v3_packages() -> None:
    deps = parse(_fixture("package_lock_v3.json"))
    by_name = {d.name: d for d in deps}
    assert "node-forge" in by_name
    assert by_name["node-forge"].version == "1.3.1"
    assert by_name["node-forge"].purl == "pkg:npm/node-forge@1.3.1"


def test_parse_v3_scoped_package_purl() -> None:
    deps = parse(_fixture("package_lock_v3.json"))
    by_name = {d.name: d for d in deps}
    # The full scoped name is preserved so different scopes can't collide.
    assert "@scope/thing" in by_name
    assert by_name["@scope/thing"].version == "2.0.0"
    assert by_name["@scope/thing"].purl == "pkg:npm/%40scope/thing@2.0.0"


def test_parse_v3_nested_path_derived_name() -> None:
    deps = parse(_fixture("package_lock_v3.json"))
    by_name = {d.name: d for d in deps}
    # path: node_modules/jsonwebtoken/node_modules/jws -> name is "jws"
    assert "jws" in by_name
    assert by_name["jws"].version == "3.2.2"


def test_parse_v3_root_key_skipped() -> None:
    deps = parse(_fixture("package_lock_v3.json"))
    # Root key "" represents the project itself; should not appear in deps
    names = [d.name for d in deps]
    assert "my-app" not in names


def test_parse_v3_no_double_counting_with_v2(tmp_path: Path) -> None:
    """v2 carries both 'packages' and 'dependencies'; prefer 'packages'."""
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
  "lockfileVersion": 2,
  "packages": {
    "": {},
    "node_modules/node-forge": {"version": "1.3.1"}
  },
  "dependencies": {
    "node-forge": {"version": "1.3.1"}
  }
}""",
        encoding="utf-8",
    )
    deps = parse(lock)
    forge_deps = [d for d in deps if d.name == "node-forge"]
    assert len(forge_deps) == 1


def test_parse_ecosystem_is_npm(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}}',
        encoding="utf-8",
    )
    deps = parse(lock)
    assert all(d.ecosystem == "npm" for d in deps)


def test_parse_declared_in_is_path(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}}',
        encoding="utf-8",
    )
    deps = parse(lock)
    assert all(d.declared_in == lock for d in deps)


def test_parse_deduplicates_name_version_pairs(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        """{
  "lockfileVersion": 1,
  "dependencies": {
    "x": {"version": "1.0.0"},
    "also-x": {"version": "1.0.0", "dependencies": {"x": {"version": "1.0.0"}}}
  }
}""",
        encoding="utf-8",
    )
    deps = parse(lock)
    x_deps = [d for d in deps if d.name == "x"]
    assert len(x_deps) == 1


def test_parse_invalid_json_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        parse(_fixture("package_lock_invalid.json"))


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "does-not-exist.json") == []


def test_parse_non_dict_root_raises_manifest_error(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ManifestError):
        parse(lock)


def test_parse_no_packages_or_dependencies_returns_empty_list(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"lockfileVersion": 3}', encoding="utf-8")
    assert parse(lock) == []


def test_parse_deeply_nested_dependencies_raise_manifest_error(tmp_path: Path) -> None:
    # A hostile v1 lockfile can nest "dependencies" far past the recursion
    # limit; the RecursionError must surface as a ManifestError the scan
    # records, never as a crash.
    inner = '{"version": "1.0.0"}'
    for _ in range(5000):
        inner = '{"version": "1.0.0", "dependencies": {"a": ' + inner + "}}"
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"dependencies": {"a": ' + inner + "}}", encoding="utf-8")
    with pytest.raises(ManifestError):
        parse(lock)


def test_v1_tree_flatten_is_iterative() -> None:
    # The recursive v1 walk truncated deep-but-valid locks npm accepts at a
    # stack-dependent depth with no diagnostic (round-10). Exercise the walk
    # directly on a tree far deeper than any recursion limit — building it
    # via json.loads would hit the JSON decoder's own (platform-dependent)
    # stack first, which is the separate, intended ManifestError path.
    depth = 5000
    tree: dict = {"leaf": {"version": "9.9.9"}}
    for i in range(depth):
        tree = {f"pkg{i}": {"version": "1.0.0", "dependencies": tree}}
    seen: set = set()
    deps: list = []
    _collect_from_dependencies(tree, Path("package-lock.json"), seen, deps)
    assert len(deps) == depth + 1
    assert any(d.name == "leaf" for d in deps)


def test_parse_moderately_deep_v1_tree_end_to_end(tmp_path: Path) -> None:
    depth = 200
    start = '{"name":"deep","lockfileVersion":1,"dependencies":{'
    chain = "".join(
        f'"pkg{i}":{{"version":"1.0.{i % 10}","dependencies":{{' for i in range(depth)
    )
    text = start + chain + '"leaf":{"version":"9.9.9"}' + "}}" * depth + "}}"
    f = tmp_path / "package-lock.json"
    f.write_text(text, encoding="utf-8")
    deps = parse(f)
    assert len(deps) == depth + 1
    assert any(d.name == "leaf" for d in deps)
