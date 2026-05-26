from pathlib import Path

from pqcheck.deps.package_lock_json import parse

_FIXTURES = Path(__file__).parent.parent.parent / "fixtures" / "deps"


def _fixture(name: str) -> Path:
    return _FIXTURES / name


def test_parse_v1_flat_deps() -> None:
    deps = parse(_fixture("package_lock_v1.json"))
    by_name = {d.name: d for d in deps}
    assert "node-forge" in by_name
    assert by_name["node-forge"].version == "1.3.1"
    assert by_name["node-forge"].purl == "pkg:npm/node-forge@1.3.1"


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
    assert "thing" in by_name
    assert by_name["thing"].version == "2.0.0"
    # scoped: namespace=@scope, name=thing
    assert by_name["thing"].purl == "pkg:npm/%40scope/thing@2.0.0"


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


def test_parse_invalid_json_returns_empty_list() -> None:
    assert parse(_fixture("package_lock_invalid.json")) == []


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "does-not-exist.json") == []


def test_parse_non_dict_root_returns_empty_list(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text("[1, 2, 3]", encoding="utf-8")
    assert parse(lock) == []


def test_parse_no_packages_or_dependencies_returns_empty_list(tmp_path: Path) -> None:
    lock = tmp_path / "package-lock.json"
    lock.write_text('{"lockfileVersion": 3}', encoding="utf-8")
    assert parse(lock) == []
