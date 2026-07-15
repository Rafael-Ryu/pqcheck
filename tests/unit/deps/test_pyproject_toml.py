from pathlib import Path

import pytest

from pqcheck.deps.base import ManifestError
from pqcheck.deps.pyproject_toml import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "pyproject.toml"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_pep621_dependencies(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
version = "0.1.0"
dependencies = [
    "cryptography>=43.0.0",
    "pycryptodome==3.20.0",
    "requests",
]
""")
    deps = parse(f)
    names = sorted(d.name for d in deps)
    assert names == ["cryptography", "pycryptodome", "requests"]
    assert all(d.ecosystem == "pypi" for d in deps)
    assert all(d.version is None for d in deps)
    assert all(d.declared_in == f for d in deps)


def test_parse_utf8_bom_still_parses(tmp_path: Path) -> None:
    # A BOM'd manifest (routine Windows tooling output) made tomllib raise,
    # which parse() swallowed into zero deps. utf-8-sig strips the BOM.
    f = tmp_path / "pyproject.toml"
    f.write_bytes(b"\xef\xbb\xbf" + b'[project]\ndependencies = ["pycryptodome"]\n')
    deps = parse(f)
    assert [d.name for d in deps] == ["pycryptodome"]


def test_parse_populates_introduces_algorithms_from_catalog(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography>=43.0.0", "pycryptodome"]
""")
    deps = {d.name: d for d in parse(f)}
    assert "RSA" in deps["cryptography"].introduces_algorithms
    assert "DES" in deps["pycryptodome"].introduces_algorithms


def test_parse_unknown_package_has_empty_algorithms_tuple(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["requests"]
""")
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].name == "requests"
    assert deps[0].introduces_algorithms == ()


def test_parse_purl_is_well_formed(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["Cryptography>=43.0.0"]
""")
    deps = parse(f)
    assert deps[0].purl == "pkg:pypi/cryptography"


def test_parse_optional_dependencies(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography"]
[project.optional-dependencies]
test = ["pytest", "rsa"]
crypto-extras = ["pynacl"]
""")
    deps = sorted(d.name for d in parse(f))
    assert deps == ["cryptography", "pynacl", "pytest", "rsa"]


def test_parse_pep735_dependency_groups(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography"]
[dependency-groups]
dev = ["ruff", "mypy"]
test = ["pytest", "ecdsa"]
""")
    deps = sorted(d.name for d in parse(f))
    assert deps == ["cryptography", "ecdsa", "mypy", "pytest", "ruff"]


def test_parse_pep735_include_group_resolves_transitively(tmp_path: Path) -> None:
    # `dev` reaches `test` only via {include-group}; before the fix the
    # dict entry was silently dropped and pytest never surfaced when
    # `dev` was the entry point.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = []
[dependency-groups]
dev = ["ruff", {include-group = "test"}]
test = ["pytest"]
""")
    deps = sorted(d.name for d in parse(f))
    assert deps == ["pytest", "ruff"]


def test_parse_pep735_include_group_only_path_to_dep(tmp_path: Path) -> None:
    # The dep `cryptography` is reachable ONLY via include-group resolution.
    # Direct walk of dev = [{include-group = "build"}] would have missed it.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = []
[dependency-groups]
dev = [{include-group = "build"}]
build = ["cryptography>=43.0.0"]
""")
    deps = sorted(d.name for d in parse(f))
    assert deps == ["cryptography"]


def test_parse_pep735_include_group_handles_cycle(tmp_path: Path) -> None:
    # a -> b -> a; each group still contributes its strings once and
    # the parser does not hang.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = []
[dependency-groups]
a = ["ruff", {include-group = "b"}]
b = ["pytest", {include-group = "a"}]
""")
    deps = sorted(d.name for d in parse(f))
    assert deps == ["pytest", "ruff"]


def test_parse_pep735_include_group_unknown_key_ignored(tmp_path: Path) -> None:
    # PEP 735 reserves keys beyond `include-group` for future use; unknown
    # keys must not crash the parser.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = []
[dependency-groups]
dev = ["ruff", {foo = "bar"}]
""")
    deps = sorted(d.name for d in parse(f))
    assert deps == ["ruff"]


def test_parse_deduplicates_across_sections(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography"]
[project.optional-dependencies]
test = ["cryptography", "pytest"]
""")
    deps = parse(f)
    names = sorted(d.name for d in deps)
    assert names == ["cryptography", "pytest"]


def test_parse_pyproject_without_project_table(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[tool.ruff]
line-length = 100
""")
    assert parse(f) == []


def test_parse_invalid_toml_raises_manifest_error(tmp_path: Path) -> None:
    # A manifest we saw but could not parse means an incomplete inventory; the
    # scanner records it in ScanResult.errors instead of reporting a clean scan.
    f = _write(tmp_path, "this is not [valid TOML\n")
    with pytest.raises(ManifestError):
        parse(f)


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "no-such-file.toml") == []


def test_parse_invalid_requirement_string_raises(tmp_path: Path) -> None:
    # uv refuses the project on an invalid requirement string (round 10) —
    # a silent skip passed off a partial inventory as complete.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography", ">=1.0", ""]
""")
    with pytest.raises(ManifestError, match=r"malformed pyproject\.toml"):
        parse(f)


def test_parse_skips_non_string_entries_in_lists(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography", 42, true]
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["cryptography"]


def test_parse_build_system_requires_emits_deps(tmp_path: Path) -> None:
    # PEP 518: [build-system].requires lists build-time deps. They ship
    # cryptography code into every wheel built from source, so they
    # must surface in the CBOM.
    f = _write(tmp_path, """
[build-system]
requires = ["setuptools", "cryptography>=43"]
build-backend = "setuptools.build_meta"
""")
    deps = parse(f)
    names = sorted(d.name for d in deps)
    assert names == ["cryptography", "setuptools"]


def test_parse_build_system_requires_deduped_with_runtime(tmp_path: Path) -> None:
    # The same package can appear in both [project.dependencies] and
    # [build-system].requires (e.g. cryptography); PEP 503 dedup keeps
    # only one finding.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography>=43"]

[build-system]
requires = ["cryptography>=43"]
build-backend = "setuptools.build_meta"
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["cryptography"]


def test_parse_deduplicates_case_insensitively(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["Cryptography"]
[project.optional-dependencies]
test = ["cryptography", "CRYPTOGRAPHY"]
""")
    deps = parse(f)
    # All three spellings normalize to the same PyPI package.
    assert len(deps) == 1
    # First-seen casing wins — "Cryptography" appeared in [project.dependencies].
    assert deps[0].name == "Cryptography"
    assert deps[0].purl == "pkg:pypi/cryptography"


def test_parse_deeply_nested_toml_raises_manifest_error(tmp_path: Path) -> None:
    # Nested arrays parse recursively; a hostile pyproject can blow the stack.
    # The RecursionError must surface as a ManifestError the scan records, not
    # as an empty-but-clean parse or a crash.
    f = _write(tmp_path, "a = " + "[" * 3000 + "]" * 3000 + "\n")
    with pytest.raises(ManifestError):
        parse(f)


def test_parse_invalid_specifier_operator_raises(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography=>43.0"]
""")
    with pytest.raises(ManifestError, match=r"malformed pyproject\.toml"):
        parse(f)


def test_parse_missing_include_group_raises(tmp_path: Path) -> None:
    # uv rejects the project on a missing include-group (round-10) — silently
    # ignoring it dropped every dependency the include would contribute.
    f = _write(tmp_path, """
[project]
name = "demo"
version = "0.0.0"
[dependency-groups]
audit = [{ include-group = "does-not-exist" }, "pyopenssl==25.1.0"]
""")
    with pytest.raises(ManifestError, match="dependency group"):
        parse(f)
