"""End-to-end fixture-driven tests for the three v0.1 deps parsers.

Run independently with `uv run pytest tests/integration -v -m integration`.
The default `uv run pytest` includes them too via the `-ra` config.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from pqcheck.deps import pom_xml, pyproject_toml, uv_lock

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


def test_pyproject_invalid_fixture_returns_empty() -> None:
    assert pyproject_toml.parse(FIXTURES / "pyproject_invalid.toml") == []


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


def test_uv_invalid_fixture_returns_empty() -> None:
    assert uv_lock.parse(FIXTURES / "uv_invalid.lock") == []


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
    deps = pom_xml.parse(FIXTURES / "pom_xxe.xml")
    for d in deps:
        assert "root:" not in d.purl
        assert "/etc/passwd" not in d.purl


def test_pom_billion_laughs_fixture_terminates_quickly() -> None:
    start = time.perf_counter()
    deps = pom_xml.parse(FIXTURES / "pom_billion_laughs.xml")
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0
    for d in deps:
        assert len(d.name) < 100


def test_pom_invalid_fixture_returns_empty() -> None:
    assert pom_xml.parse(FIXTURES / "pom_invalid.xml") == []
