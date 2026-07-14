"""End-to-end fixture-driven tests for the deps parsers.

Run independently with `uv run pytest tests/integration -v -m integration`.
The default `uv run pytest` includes them too via the `-ra` config.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pqcheck.deps import go_mod, package_lock_json, pom_xml, pyproject_toml, uv_lock
from pqcheck.deps.base import ManifestError

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parent.parent / "fixtures" / "deps"


def test_pyproject_pep621_fixture_emits_expected_deps() -> None:
    deps = pyproject_toml.parse(FIXTURES / "pyproject_pep621.toml")
    names = sorted(d.name for d in deps)
    assert names == [
        "cryptography",
        "ecdsa",
        "hypothesis",
        "pycryptodome",
        "pynacl",
        "pytest",
        "requests",
        "rsa",
    ]
    by_name = {d.name: d for d in deps}
    assert "RSA" in by_name["cryptography"].introduces_algorithms
    assert by_name["rsa"].introduces_algorithms == ("RSA",)


def test_pyproject_with_groups_fixture_includes_dependency_groups() -> None:
    deps = pyproject_toml.parse(FIXTURES / "pyproject_with_groups.toml")
    names = sorted(d.name for d in deps)
    assert names == ["cryptography", "ecdsa", "mypy", "pytest", "ruff"]


def test_pyproject_no_project_fixture_returns_empty() -> None:
    assert pyproject_toml.parse(FIXTURES / "pyproject_no_project.toml") == []


def test_pyproject_invalid_fixture_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        pyproject_toml.parse(FIXTURES / "pyproject_invalid.toml")


def test_uv_basic_fixture_emits_pinned_versions() -> None:
    deps = uv_lock.parse(FIXTURES / "uv_basic.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["cryptography"].version == "43.0.0"
    assert by_name["pyopenssl"].version == "24.2.1"
    assert "RSA" in by_name["cryptography"].introduces_algorithms


def test_uv_workspace_fixture_emits_workspace_member_without_version() -> None:
    deps = uv_lock.parse(FIXTURES / "uv_workspace.lock")
    by_name = {d.name: d for d in deps}
    assert by_name["my-workspace-member"].version is None
    assert by_name["my-workspace-member"].purl == "pkg:pypi/my-workspace-member"
    assert by_name["ecdsa"].version == "0.19.0"


def test_uv_invalid_fixture_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        uv_lock.parse(FIXTURES / "uv_invalid.lock")


def test_pom_basic_fixture_emits_expected_deps() -> None:
    deps = pom_xml.parse(FIXTURES / "pom_basic.xml")
    by_name = {d.name: d for d in deps}
    assert by_name["bcprov-jdk18on"].version == "1.78"
    assert by_name["tink"].version == "1.14.0"
    assert by_name["spring-core"].version == "6.1.10"
    assert "RSA" in by_name["bcprov-jdk18on"].introduces_algorithms
    assert by_name["spring-core"].introduces_algorithms == ()  # not in catalog


def test_pom_with_props_fixture_interpolates_versions() -> None:
    deps = pom_xml.parse(FIXTURES / "pom_with_props.xml")
    by_name = {d.name: d for d in deps}
    assert by_name["bcprov-jdk18on"].version == "1.78"
    assert by_name["tink"].version == "1.14.0"
    # Unresolved property -> version=None.
    assert by_name["bcpkix-jdk18on"].version is None


def test_pom_xxe_fixture_does_not_leak_file_contents() -> None:
    # Sanity: the fixture must actually carry the entity declaration, else
    # the test silently goes vacuous if the corpus is edited.
    fixture = FIXTURES / "pom_xxe.xml"
    assert "<!ENTITY xxe SYSTEM" in fixture.read_text()
    deps = pom_xml.parse(fixture)
    # The legitimate dep declared after the poisoned root must survive parsing.
    # The poisoned root <groupId>&xxe;</groupId> is in the project root, not
    # inside <dependencies>, and so is not emitted by the parser regardless.
    by_name = {d.name: d for d in deps}
    assert "bcprov-jdk18on" in by_name
    # No emitted dep may carry the expanded payload marker. /etc/passwd on
    # Linux always starts with "root:".
    for d in deps:
        assert "root:" not in d.purl
        assert "root:" not in d.name
        assert "root:" not in (d.version or "")


def test_pom_billion_laughs_fixture_terminates_safely() -> None:
    # Sanity: fixture must declare the nested entities, else the test is
    # vacuous if the corpus is edited.
    fixture = FIXTURES / "pom_billion_laughs.xml"
    assert "<!ENTITY lol5" in fixture.read_text()
    # The fixture has no <dependencies> block, so the parser emits nothing.
    # Wall-clock cap is generous (5s) to avoid CI flakes; the real invariant
    # is "no expansion ran" — checked via deps == [] and no bloomed text.
    start = time.perf_counter()
    deps = pom_xml.parse(fixture)
    elapsed = time.perf_counter() - start
    assert elapsed < 5.0
    assert deps == []


def test_pom_invalid_fixture_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        pom_xml.parse(FIXTURES / "pom_invalid.xml")


def test_gomod_basic_fixture_emits_single_line_and_block_requires() -> None:
    deps = go_mod.parse(FIXTURES / "gomod_basic.mod")
    by_name = {d.name: d for d in deps}
    assert set(by_name) == {
        "golang.org/x/crypto",
        "github.com/youmark/pkcs8",
        "github.com/golang-jwt/jwt/v5",
    }
    assert by_name["golang.org/x/crypto"].version == "v0.21.0"
    assert by_name["github.com/youmark/pkcs8"].version.startswith("v0.0.0-")
    # Single-line require outside the block, with a multi-segment module path.
    assert by_name["github.com/golang-jwt/jwt/v5"].purl == (
        "pkg:golang/github.com/golang-jwt/jwt/v5@v5.2.1"
    )


def test_gomod_invalid_fixture_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        go_mod.parse(FIXTURES / "gomod_invalid.mod")


def test_package_lock_v1_fixture_flattens_nested_dependencies() -> None:
    deps = package_lock_json.parse(FIXTURES / "package_lock_v1.json")
    by_name = {d.name: d for d in deps}
    assert by_name["node-forge"].version == "1.3.1"
    assert by_name["jsonwebtoken"].version == "9.0.2"
    # jws is nested under jsonwebtoken.dependencies; the v1 tree must flatten it.
    assert by_name["jws"].version == "3.2.2"


def test_package_lock_v3_fixture_preserves_scoped_name() -> None:
    deps = package_lock_json.parse(FIXTURES / "package_lock_v3.json")
    by_name = {d.name: d for d in deps}
    assert by_name["node-forge"].version == "1.3.1"
    assert by_name["jws"].version == "3.2.2"
    # Scoped package keeps its full @scope/name and PURL-encodes the @ as %40.
    assert by_name["@scope/thing"].version == "2.0.0"
    assert by_name["@scope/thing"].purl == "pkg:npm/%40scope/thing@2.0.0"


def test_package_lock_invalid_fixture_raises_manifest_error() -> None:
    with pytest.raises(ManifestError):
        package_lock_json.parse(FIXTURES / "package_lock_invalid.json")
