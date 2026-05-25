# Lockfile Parsers (pyproject / uv.lock / pom.xml) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship three dependency-manifest parsers in `pqcheck.deps` that emit `CryptoDependency` objects from `pyproject.toml` (PEP 621 + PEP 735), `uv.lock` (v1), and `pom.xml` (XML, lossy). Each parser is a stdlib-only or lxml-only function `parse(path: Path) -> list[CryptoDependency]`. Every dep gets a valid PURL, an `introduces_algorithms` tuple populated from a static catalog, and survives malformed input without crashing the scanner. Whole project keeps coverage ≥ 85% (the gate already configured in `pyproject.toml`).

**Architecture:** Three independent file-format parsers behind a shared protocol in `deps/base.py`. Each parser handles file-size cap, error swallowing, and PURL construction via the same helpers. A static `deps/packages.py` catalog maps `(ecosystem, name)` → tuple of canonical algorithms introduced by that package (initial seed: 10-15 entries covering the BR-fintech relevant packages — `cryptography`, `pycryptodome`, `rsa`, `ecdsa`, BouncyCastle, Tink). pyproject and uv.lock use `tomllib` (stdlib 3.11+); pom.xml uses `lxml.etree` with a hardened parser config (`resolve_entities=False`, `no_network=True`, `huge_tree=False`, no DTDs) to block XXE and billion-laughs DoS.

**Tech Stack:**
- Python 3.12+ stdlib for TOML: `tomllib`, `pathlib`, `re` (PEP 508 name extraction).
- `lxml>=5.3,<7` — already pinned in `pyproject.toml`; the project-blessed XML parser. We do NOT add `defusedxml`; the hardened `lxml.etree.XMLParser` config gives equivalent guarantees with zero new supply-chain surface.
- `packageurl-python>=0.16,<1` — already pinned; used for PURL construction (`PackageURL(...).to_string()`).
- `pydantic>=2.11,<3` — already pinned; `CryptoDependency` is a frozen Pydantic model.
- pytest + hypothesis (already in dev extras) for tests.
- No new third-party deps.

**Prerequisites:**
- `feat/python-ast-detector` merged to `develop`. Provides the baseline `src/pqcheck/models.py` with `AlgorithmFamily`, `QuantumRisk`, `SourceLocation`, `CryptoFinding`. This plan extends that file with `CryptoDependency`.
- Branch off `develop` as `feat/lockfile-parsers-pyproject-uv-pom` (per CLAUDE.md workflow memory).

**Scope guard — what this plan does NOT build:**
- `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `requirements.txt`, `go.mod`, `go.sum` parsers — separate tasks per `.context/plans/03-phase1-pqcheck-cli.md` Task 8.
- Maven effective-pom (transitive resolution via parent POM traversal or `mvn` subprocess) — Phase 3 per spec line 422. v0.1 does in-file properties substitution only.
- Policy engine integration — `CryptoDependency` instances are consumed by the scanner orchestrator (Task 9 in spec 03) and then by the policy engine. Out of scope here.
- `ScanResult` glue — separate task. This plan only ships parser functions returning lists.
- Coalescing duplicates across multiple manifests in one repo (same `cryptography==43.0.0` declared in pyproject.toml AND uv.lock). The scanner orchestrator handles dedup; parsers emit independently.
- Catalog expansion beyond the seed 10-15 entries. Customer-signal driven per the trigger-based-provisioning principle in CLAUDE.md.

---

## File structure

| Action | Path | Responsibility |
|---|---|---|
| Modify | `src/pqcheck/models.py` | Append `CryptoDependency` Pydantic model (purl, name, version, ecosystem, declared_in, introduces_algorithms) — Task 1 |
| Modify | `tests/unit/test_models.py` | Append `CryptoDependency` tests — Task 1 |
| Create | `src/pqcheck/deps/__init__.py` | Empty package marker — Task 2 |
| Create | `src/pqcheck/deps/packages.py` | Static catalog: `(ecosystem, name)` → tuple[canonical_algorithm, ...] — Task 2 |
| Create | `tests/unit/deps/__init__.py` | Empty package marker — Task 2 |
| Create | `tests/unit/deps/test_packages.py` | Tests for catalog lookup — Task 2 |
| Create | `src/pqcheck/deps/base.py` | Shared helpers: file-size cap, safe-read, PURL builders, PEP 508 name extractor — Task 3 |
| Create | `tests/unit/deps/test_base.py` | Tests for helpers — Task 3 |
| Create | `src/pqcheck/deps/pyproject_toml.py` | `parse(path) -> list[CryptoDependency]` for PEP 621 + PEP 735 — Task 4 |
| Create | `tests/unit/deps/test_pyproject_toml.py` | Tests for pyproject parser — Task 4 |
| Create | `src/pqcheck/deps/uv_lock.py` | `parse(path) -> list[CryptoDependency]` for uv.lock v1 — Task 5 |
| Create | `tests/unit/deps/test_uv_lock.py` | Tests for uv.lock parser — Task 5 |
| Create | `src/pqcheck/deps/pom_xml.py` | `parse(path) -> list[CryptoDependency]` for pom.xml (hardened lxml) — Task 6 |
| Create | `tests/unit/deps/test_pom_xml.py` | Tests for pom.xml parser including XXE / billion-laughs — Task 6 |
| Create | `tests/fixtures/deps/pyproject_pep621.toml` | Realistic pyproject with PEP 621 deps — Task 7 |
| Create | `tests/fixtures/deps/pyproject_with_groups.toml` | PEP 735 dependency-groups + optional-deps — Task 7 |
| Create | `tests/fixtures/deps/pyproject_no_project.toml` | Tool-only pyproject (no `[project]`) — Task 7 |
| Create | `tests/fixtures/deps/pyproject_invalid.toml` | Syntactically broken TOML — Task 7 |
| Create | `tests/fixtures/deps/uv_basic.lock` | Realistic uv.lock with cryptography + pyca/pyOpenSSL — Task 7 |
| Create | `tests/fixtures/deps/uv_workspace.lock` | uv.lock with workspace members + optional — Task 7 |
| Create | `tests/fixtures/deps/uv_invalid.lock` | Syntactically broken uv.lock — Task 7 |
| Create | `tests/fixtures/deps/pom_basic.xml` | Realistic pom.xml with bouncycastle + tink — Task 7 |
| Create | `tests/fixtures/deps/pom_with_props.xml` | pom.xml using `<properties>` interpolation — Task 7 |
| Create | `tests/fixtures/deps/pom_xxe.xml` | pom.xml with XXE external-entity payload — Task 7 |
| Create | `tests/fixtures/deps/pom_billion_laughs.xml` | pom.xml with nested-entity DoS payload — Task 7 |
| Create | `tests/fixtures/deps/pom_invalid.xml` | Malformed XML — Task 7 |
| Create | `tests/integration/test_deps_integration.py` | End-to-end: run each parser against its fixtures, assert deps + algorithms — Task 7 |

**Why one parser file per format (not split per format-variant):** Each format has its own grammar, its own quirks, and its own failure modes. A `pyproject_toml.py` reader does not share state with a `uv_lock.py` reader. The shared logic — file-size cap, safe-read, PURL building, PEP 508 name extraction — lives in `base.py` so DRY holds at the helper layer. This matches the spec's `src/pqcheck/deps/` layout (03:84-92).

**Why one catalog (`packages.py`) not per-language:** A package's introduced-algorithms list is keyed by `(ecosystem, name)`, not by language. The Python parser emits ecosystem="pypi", the Maven parser emits ecosystem="maven". One catalog file with one lookup function keeps the policy authors' source-of-truth in one place. Detector-side `algorithms.py` keys on `qualified_dotted_name` (a different shape entirely) — keep them separate.

---

## Task 0: Branch off develop

**Context:** Per CLAUDE.md branching memory, feature branches start from `develop` with a conventional name. Confirm prerequisite is in place before any code.

**Files:** none (git only)

- [ ] **Step 1: Verify prerequisite is merged**

Run: `git log --oneline develop | head -5`
Expected: the most recent commit on `develop` includes the Python AST detector work — look for a `feat: …python ast detector…` line or equivalent. If absent, STOP and either (a) wait for the prerequisite PR to merge or (b) branch off `feat/python-ast-detector` instead and rebase later.

- [ ] **Step 2: Confirm the baseline coverage gate passes on develop**

Run: `uv run pytest --cov=pqcheck 2>&1 | tail -5`
Expected: `passed` with total coverage ≥ 85%. If failing, fix that first — this plan must not start on a red baseline.

- [ ] **Step 3: Create the feature branch**

```bash
git checkout develop
git pull --ff-only
git checkout -b feat/lockfile-parsers-pyproject-uv-pom
```

Expected: `Switched to a new branch 'feat/lockfile-parsers-pyproject-uv-pom'`.

- [ ] **Step 4: Confirm clean working tree**

Run: `git status`
Expected: `nothing to commit, working tree clean`.

(No commit on Task 0 — it's branch setup only.)

---

## Task 1: Extend models.py with CryptoDependency

**Context:** The deps parsers emit `CryptoDependency` instances. The python-ast-detector PR shipped a minimal `models.py` containing `SourceLocation`, `AlgorithmFamily`, `QuantumRisk`, `CryptoFinding` — but explicitly deferred `CryptoDependency` (see the docstring in `src/pqcheck/models.py`). This task appends the model and its tests. We are NOT adding `ScanResult` yet — that belongs to the scanner orchestrator task per spec 03:424.

**Files:**
- Modify: `src/pqcheck/models.py`
- Modify: `tests/unit/test_models.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_models.py`:

```python
from pqcheck.models import CryptoDependency


def test_crypto_dependency_minimal_construction() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/cryptography@43.0.0",
        name="cryptography",
        version="43.0.0",
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
    )
    assert dep.name == "cryptography"
    assert dep.version == "43.0.0"
    assert dep.ecosystem == "pypi"
    assert dep.introduces_algorithms == ()


def test_crypto_dependency_with_algorithms_tuple() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/pycryptodome@3.20.0",
        name="pycryptodome",
        version="3.20.0",
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
        introduces_algorithms=("RSA", "AES", "DES", "MD5"),
    )
    assert dep.introduces_algorithms == ("RSA", "AES", "DES", "MD5")


def test_crypto_dependency_is_frozen() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/rsa@4.9",
        name="rsa",
        version="4.9",
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
    )
    with pytest.raises(ValidationError):
        dep.version = "5.0"  # type: ignore[misc]


def test_crypto_dependency_accepts_missing_version() -> None:
    dep = CryptoDependency(
        purl="pkg:pypi/cryptography",
        name="cryptography",
        version=None,
        ecosystem="pypi",
        declared_in=Path("pyproject.toml"),
    )
    assert dep.version is None
```

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: FAIL with `ImportError: cannot import name 'CryptoDependency' from 'pqcheck.models'`.

- [ ] **Step 2: Implement the model**

Append to `src/pqcheck/models.py` (after the existing `CryptoFinding` class):

```python
class CryptoDependency(BaseModel):
    """A dependency declared in a manifest or lockfile.

    Emitted by parsers in pqcheck.deps. The `introduces_algorithms` tuple
    is populated by the parser from the static catalog in
    pqcheck.deps.packages — it lists canonical algorithm names the package
    is known to introduce (e.g., pycryptodome introduces RSA, AES, DES,
    MD5). Empty tuple means "unknown / no entry in catalog", not "no
    crypto" — downstream policy treats unknown packages as INFO findings.
    """

    model_config = ConfigDict(frozen=True)

    purl: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str | None = None
    ecosystem: str = Field(min_length=1)
    declared_in: Path
    introduces_algorithms: tuple[str, ...] = ()
```

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: all 4 new tests PASS plus the existing model tests still PASS.

- [ ] **Step 3: Update the module docstring**

In `src/pqcheck/models.py`, replace the existing docstring opening sentence:

```python
"""Domain types emitted by language detectors.

Only the slice consumed by the Python AST detector lives here today.
```

with:

```python
"""Domain types emitted by language detectors and dependency parsers.

Slice consumed by the Python AST detector and the v0.1 deps parsers
(pyproject.toml, uv.lock, pom.xml) lives here today.
```

And remove `CryptoDependency` from the "added when" sentence at the end of the docstring (it's no longer deferred).

- [ ] **Step 4: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add src/pqcheck/models.py tests/unit/test_models.py
git commit -m "feat(models): add CryptoDependency for deps parsers"
```

---

## Task 2: Package introduces-algorithms catalog

**Context:** Each parser must populate `CryptoDependency.introduces_algorithms` from a static lookup. The catalog is keyed by `(ecosystem, lowercased_name)` because case folding matters for PyPI (`Cryptography` and `cryptography` are the same package per PEP 503) and we want a single canonical lookup. Maven artifact IDs are case-sensitive, but we still lowercase the lookup key by convention — Maven artifact IDs in the wild are conventionally lowercase. The seed is intentionally small (BR-fintech relevant only); expansion is customer-signal driven.

**Files:**
- Create: `src/pqcheck/deps/__init__.py`
- Create: `src/pqcheck/deps/packages.py`
- Create: `tests/unit/deps/__init__.py`
- Create: `tests/unit/deps/test_packages.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/deps/__init__.py` as an empty file.

Create `tests/unit/deps/test_packages.py`:

```python
from pqcheck.deps.packages import lookup_introduces


def test_lookup_pypi_cryptography_returns_known_algorithms() -> None:
    result = lookup_introduces("pypi", "cryptography")
    assert "RSA" in result
    assert "AES" in result
    assert "SHA-256" in result


def test_lookup_is_case_insensitive_for_name() -> None:
    lower = lookup_introduces("pypi", "cryptography")
    upper = lookup_introduces("pypi", "Cryptography")
    mixed = lookup_introduces("pypi", "CrYpToGrApHy")
    assert lower == upper == mixed


def test_lookup_pypi_pycryptodome_includes_broken_algorithms() -> None:
    result = lookup_introduces("pypi", "pycryptodome")
    assert "MD5" in result
    assert "DES" in result
    assert "RC4" in result


def test_lookup_maven_bouncycastle_returns_algorithms() -> None:
    result = lookup_introduces("maven", "bcprov-jdk18on")
    assert "RSA" in result
    assert "AES" in result


def test_lookup_unknown_package_returns_empty_tuple() -> None:
    result = lookup_introduces("pypi", "nonexistent-package-xyz")
    assert result == ()


def test_lookup_unknown_ecosystem_returns_empty_tuple() -> None:
    result = lookup_introduces("conda", "cryptography")
    assert result == ()


def test_lookup_returns_a_tuple_not_a_list() -> None:
    result = lookup_introduces("pypi", "cryptography")
    assert isinstance(result, tuple)
```

Run: `uv run pytest tests/unit/deps/test_packages.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pqcheck.deps'`.

- [ ] **Step 2: Implement the package + catalog**

Create `src/pqcheck/deps/__init__.py` as an empty file.

Create `src/pqcheck/deps/packages.py`:

```python
"""Static catalog: (ecosystem, package_name) -> tuple of canonical algorithms.

Seeded with the 10-15 packages most relevant to the v0.1 BR-fintech
vertical. Expansion is customer-signal driven (trigger-based
provisioning principle). Canonical algorithm names match those in
pqcheck.detectors.algorithms — when adding a new entry, use the same
spelling so downstream policy rules apply uniformly.

A package's presence in this catalog does NOT mean it always uses every
listed algorithm at runtime — it means the package SURFACES the
algorithm in its public API. The policy engine treats the dep list as a
"potentially uses" set, combined with detector findings (which prove
actual call sites) to score severity.
"""

from __future__ import annotations

# (ecosystem, lowercased_name) -> tuple of canonical algorithm names.
_CATALOG: dict[tuple[str, str], tuple[str, ...]] = {
    # ---- PyPI ----
    ("pypi", "cryptography"): (
        "RSA", "DSA", "ECDSA", "DH", "ED25519", "ED448", "X25519", "X448",
        "AES", "CHACHA20", "3DES", "RC4",
        "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B", "BLAKE2S",
    ),
    ("pypi", "pycryptodome"): (
        "RSA", "DSA", "ECDSA",
        "AES", "DES", "3DES", "RC4", "CHACHA20",
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B", "BLAKE2S",
    ),
    ("pypi", "pycryptodomex"): (
        "RSA", "DSA", "ECDSA",
        "AES", "DES", "3DES", "RC4", "CHACHA20",
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "SHA3-256", "SHA3-384", "SHA3-512", "BLAKE2B", "BLAKE2S",
    ),
    ("pypi", "rsa"): ("RSA",),
    ("pypi", "ecdsa"): ("ECDSA",),
    ("pypi", "pynacl"): ("ED25519", "X25519", "CHACHA20"),
    ("pypi", "pyopenssl"): ("RSA", "ECDSA", "AES", "SHA-256"),
    ("pypi", "bcrypt"): (),  # BCRYPT is a KDF; not in QuantumRisk map; flagged via family
    ("pypi", "passlib"): ("MD5", "SHA-1", "SHA-256", "SHA-512"),
    # ---- Maven ----
    ("maven", "bcprov-jdk18on"): (
        "RSA", "DSA", "ECDSA", "DH", "ED25519", "ED448", "X25519", "X448",
        "AES", "DES", "3DES", "RC4", "CHACHA20",
        "MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512",
        "BLAKE2B", "BLAKE2S",
    ),
    ("maven", "bcpkix-jdk18on"): ("RSA", "ECDSA", "AES", "SHA-256"),
    ("maven", "bctls-jdk18on"): ("RSA", "ECDSA", "AES", "CHACHA20", "SHA-256"),
    ("maven", "tink"): ("AES", "ECDSA", "ED25519", "X25519", "SHA-256"),
    ("maven", "tink-android"): ("AES", "ECDSA", "ED25519", "X25519", "SHA-256"),
}


def lookup_introduces(ecosystem: str, name: str) -> tuple[str, ...]:
    """Return the algorithms a package is known to introduce, or () if unknown."""
    return _CATALOG.get((ecosystem, name.lower()), ())
```

Run: `uv run pytest tests/unit/deps/test_packages.py -v`
Expected: all 7 tests PASS.

- [ ] **Step 3: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean.

- [ ] **Step 4: Commit**

```bash
git add src/pqcheck/deps/__init__.py src/pqcheck/deps/packages.py tests/unit/deps/__init__.py tests/unit/deps/test_packages.py
git commit -m "feat(deps): seed introduces-algorithms catalog"
```

---

## Task 3: Shared parser helpers (base.py)

**Context:** All three parsers share four concerns: (1) reject files larger than `_MAX_FILE_BYTES` (5 MB — a real-world pom.xml is ~10-200 KB; a real uv.lock for a large project is 500 KB - 2 MB; 5 MB is generous), (2) safely read the file as bytes with one round of decoding, (3) build a PURL given an ecosystem + name + (optional) namespace + (optional) version, (4) extract a package name from a PEP 508 requirement string like `"cryptography[ssh] >= 43.0.0 ; python_version >= '3.12'"`. Centralize so parser bodies stay tiny.

**Files:**
- Create: `src/pqcheck/deps/base.py`
- Create: `tests/unit/deps/test_base.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/deps/test_base.py`:

```python
from pathlib import Path

import pytest

from pqcheck.deps.base import (
    MAX_FILE_BYTES,
    extract_pep508_name,
    maven_purl,
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


def test_safe_read_bytes_returns_none_for_oversized_file(tmp_path: Path) -> None:
    f = tmp_path / "huge.txt"
    f.write_bytes(b"\x00" * (MAX_FILE_BYTES + 1))
    assert safe_read_bytes(f) is None


def test_safe_read_bytes_returns_none_for_missing_file(tmp_path: Path) -> None:
    assert safe_read_bytes(tmp_path / "does-not-exist") is None


def test_safe_read_bytes_returns_none_for_directory(tmp_path: Path) -> None:
    assert safe_read_bytes(tmp_path) is None
```

Run: `uv run pytest tests/unit/deps/test_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pqcheck.deps.base'`.

- [ ] **Step 2: Implement the helpers**

Create `src/pqcheck/deps/base.py`:

```python
"""Shared helpers for dependency-manifest parsers.

File-size cap, safe byte-level reader, PURL builders, and a minimal
PEP 508 requirement-name extractor. Parser bodies in this package stay
small by composing these primitives.
"""

from __future__ import annotations

import re
from pathlib import Path

from packageurl import PackageURL

MAX_FILE_BYTES = 5 * 1024 * 1024


def safe_read_bytes(path: Path) -> bytes | None:
    """Read a file as bytes, returning None on any error or oversize.

    Failure modes (return None): path missing, path is a directory,
    OS read error, file larger than MAX_FILE_BYTES. Callers treat None
    as "skip this file" — never raise. Matches the scanner's per-file
    exception-swallowing contract.
    """
    try:
        stat = path.stat()
    except OSError:
        return None
    if not stat.st_size or not path.is_file():
        if not path.is_file():
            return None
    if stat.st_size > MAX_FILE_BYTES:
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def pypi_purl(name: str, version: str | None) -> str:
    return PackageURL(type="pypi", name=name.lower(), version=version).to_string()


def maven_purl(group_id: str, artifact_id: str, version: str | None) -> str:
    return PackageURL(
        type="maven", namespace=group_id, name=artifact_id, version=version
    ).to_string()


# PEP 508 distribution-name grammar: a letter or digit followed by any of
# letters, digits, dot, hyphen, underscore. We do not validate the full
# grammar — we only extract the leading name token.
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def extract_pep508_name(requirement: str) -> str | None:
    """Extract the distribution name from a PEP 508 requirement string.

    Examples:
      "cryptography"                                    -> "cryptography"
      "cryptography>=43.0.0"                            -> "cryptography"
      "cryptography[ssh] >= 43.0.0 ; python_version..." -> "cryptography"
      ">=1.0"                                           -> None
      ""                                                -> None
    """
    match = _NAME_RE.match(requirement)
    if match is None:
        return None
    return match.group(1)
```

Run: `uv run pytest tests/unit/deps/test_base.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Tighten `safe_read_bytes` redundant check**

The implementation in Step 2 has a small bug (`if not stat.st_size or not path.is_file():` is incoherent). Replace the body of `safe_read_bytes` in `src/pqcheck/deps/base.py` with this corrected version:

```python
def safe_read_bytes(path: Path) -> bytes | None:
    try:
        if not path.is_file():
            return None
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_FILE_BYTES:
        return None
    try:
        return path.read_bytes()
    except OSError:  # pragma: no cover - TOCTOU: stat succeeded but read failed
        return None
```

Re-run: `uv run pytest tests/unit/deps/test_base.py -v`
Expected: all tests still PASS.

- [ ] **Step 4: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean.

- [ ] **Step 5: Commit**

```bash
git add src/pqcheck/deps/base.py tests/unit/deps/test_base.py
git commit -m "feat(deps): add shared parser helpers (purl, safe-read, pep508)"
```

---

## Task 4: pyproject.toml parser

**Context:** PEP 621 puts runtime deps in `[project.dependencies]` (list of PEP 508 strings) and optional deps in `[project.optional-dependencies]` (table of group → list). PEP 735 adds `[dependency-groups]` (table of group → list of strings OR tables with `{include-group = "name"}`). Each PEP 508 string yields one `CryptoDependency` with `version=None` (pyproject.toml does NOT pin exact versions — that's the lockfile's job). De-duplicate by `(name)` across all sections — if `cryptography` appears in both `dependencies` and `optional-dependencies.test`, emit it once with the first-seen declaration.

**Files:**
- Create: `src/pqcheck/deps/pyproject_toml.py`
- Create: `tests/unit/deps/test_pyproject_toml.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/deps/test_pyproject_toml.py`:

```python
from pathlib import Path

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


def test_parse_pep735_include_group_is_ignored_safely(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = []
[dependency-groups]
dev = ["ruff", {include-group = "test"}]
test = ["pytest"]
""")
    deps = sorted(d.name for d in parse(f))
    # include-group entries are tables, not PEP 508 strings — we skip them
    # (the included names already appear in their own group).
    assert deps == ["pytest", "ruff"]


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


def test_parse_invalid_toml_returns_empty_list(tmp_path: Path) -> None:
    f = _write(tmp_path, "this is not [valid TOML\n")
    assert parse(f) == []


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "no-such-file.toml") == []


def test_parse_skips_non_pep508_entries(tmp_path: Path) -> None:
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography", ">=1.0", ""]
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["cryptography"]


def test_parse_skips_non_string_entries_in_lists(tmp_path: Path) -> None:
    # PEP 735 tables ({include-group = ...}) are valid TOML; PEP 621 lists
    # of dicts are not part of the spec but we must not crash on them.
    f = _write(tmp_path, """
[project]
name = "demo"
dependencies = ["cryptography", 42, true]
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["cryptography"]
```

Run: `uv run pytest tests/unit/deps/test_pyproject_toml.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 2: Implement the parser**

Create `src/pqcheck/deps/pyproject_toml.py`:

```python
"""Parser for pyproject.toml — PEP 621 [project] + PEP 735 [dependency-groups].

Emits CryptoDependency per distinct package name across:
  - [project.dependencies]
  - [project.optional-dependencies.<group>]
  - [dependency-groups.<group>]

Versions are NOT pinned in pyproject.toml — every emitted dependency
has version=None. For exact versions, the scanner orchestrator combines
the pyproject result with the matching uv.lock result.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from pqcheck.deps.base import extract_pep508_name, pypi_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        data: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []

    seen: set[str] = set()
    deps: list[CryptoDependency] = []
    for raw_name in _iter_requirement_strings(data):
        name = extract_pep508_name(raw_name)
        if name is None or name in seen:
            continue
        seen.add(name)
        deps.append(
            CryptoDependency(
                purl=pypi_purl(name, None),
                name=name,
                version=None,
                ecosystem="pypi",
                declared_in=path,
                introduces_algorithms=lookup_introduces("pypi", name),
            )
        )
    return deps


def _iter_requirement_strings(data: dict[str, Any]) -> Iterable[str]:
    project = data.get("project")
    if isinstance(project, dict):
        yield from _string_items(project.get("dependencies"))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group_value in optional.values():
                yield from _string_items(group_value)

    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group_value in groups.values():
            yield from _string_items(group_value)


def _string_items(value: Any) -> Iterable[str]:
    if not isinstance(value, list):
        return
    for item in value:
        if isinstance(item, str):
            yield item
```

Run: `uv run pytest tests/unit/deps/test_pyproject_toml.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean. (If ruff flags `RUF013` on `Any` usage, adjust per-file ignore or use `object` — Pydantic's `model_validate` is the trust boundary.)

- [ ] **Step 4: Commit**

```bash
git add src/pqcheck/deps/pyproject_toml.py tests/unit/deps/test_pyproject_toml.py
git commit -m "feat(deps): add pyproject.toml parser (PEP 621 + PEP 735)"
```

---

## Task 5: uv.lock parser

**Context:** `uv.lock` is TOML at the top level with `[[package]]` array-of-tables entries. Each entry has `name`, `version` (always pinned), and an optional `source` table. The top-level `version` key is the lockfile-schema version (currently `1`). We only consume `name` + `version`. Workspace members and packages with `source.editable = true` are still emitted (a workspace member can still introduce algorithms if it depends on `cryptography` directly — though those transitive deps appear as their own `[[package]]` entries anyway). De-duplicate by `(name, version)` — a uv.lock can pin two versions of the same package (rare but legal under `--resolution=lowest-direct` plus a conflicting fork).

**Files:**
- Create: `src/pqcheck/deps/uv_lock.py`
- Create: `tests/unit/deps/test_uv_lock.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/deps/test_uv_lock.py`:

```python
from pathlib import Path

from pqcheck.deps.uv_lock import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "uv.lock"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_basic_uv_lock(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1

[[package]]
name = "cryptography"
version = "43.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pyopenssl"
version = "24.2.1"
source = { registry = "https://pypi.org/simple" }
""")
    deps = parse(f)
    by_name = {d.name: d for d in deps}
    assert by_name["cryptography"].version == "43.0.0"
    assert by_name["cryptography"].purl == "pkg:pypi/cryptography@43.0.0"
    assert by_name["pyopenssl"].version == "24.2.1"
    assert all(d.ecosystem == "pypi" for d in deps)
    assert all(d.declared_in == f for d in deps)


def test_parse_populates_introduces_algorithms(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "pycryptodome"
version = "3.20.0"
""")
    deps = parse(f)
    assert "RSA" in deps[0].introduces_algorithms
    assert "DES" in deps[0].introduces_algorithms


def test_parse_skips_package_without_name(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
version = "1.0.0"
[[package]]
name = "cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["cryptography"]


def test_parse_accepts_package_without_version(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "my-workspace-member"
source = { workspace = true }
""")
    deps = parse(f)
    assert len(deps) == 1
    assert deps[0].name == "my-workspace-member"
    assert deps[0].version is None
    assert deps[0].purl == "pkg:pypi/my-workspace-member"


def test_parse_deduplicates_name_version_pairs(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "cryptography"
version = "43.0.0"
[[package]]
name = "cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert len(deps) == 1


def test_parse_keeps_distinct_versions_of_same_package(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "cryptography"
version = "43.0.0"
[[package]]
name = "cryptography"
version = "44.0.0"
""")
    deps = sorted(parse(f), key=lambda d: d.version or "")
    assert [d.version for d in deps] == ["43.0.0", "44.0.0"]


def test_parse_invalid_toml_returns_empty_list(tmp_path: Path) -> None:
    f = _write(tmp_path, "this is not [valid TOML\n")
    assert parse(f) == []


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "missing.lock") == []


def test_parse_without_package_array(tmp_path: Path) -> None:
    f = _write(tmp_path, "version = 1\n")
    assert parse(f) == []


def test_parse_lowercases_purl_name(tmp_path: Path) -> None:
    f = _write(tmp_path, """
version = 1
[[package]]
name = "Cryptography"
version = "43.0.0"
""")
    deps = parse(f)
    assert deps[0].purl == "pkg:pypi/cryptography@43.0.0"
    # We preserve the originally-declared name on the model but normalize
    # the PURL — matches PyPI's PEP 503 normalization.
    assert deps[0].name == "Cryptography"
```

Run: `uv run pytest tests/unit/deps/test_uv_lock.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 2: Implement the parser**

Create `src/pqcheck/deps/uv_lock.py`:

```python
"""Parser for uv.lock v1.

Emits one CryptoDependency per (name, version) pair declared in the
[[package]] array. uv.lock pins exact versions for every resolved
package — version is None only for workspace members that don't carry
their own version key.

Lookups in packages.py use the lowercased name (PEP 503 normalization).
The model preserves the originally-declared casing in `name` for
display purposes; PURLs and catalog lookups use the normalized form.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from pqcheck.deps.base import pypi_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        data: dict[str, Any] = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []

    packages = data.get("package")
    if not isinstance(packages, list):
        return []

    seen: set[tuple[str, str | None]] = set()
    deps: list[CryptoDependency] = []
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str) or not name:
            continue
        version_raw = entry.get("version")
        version = version_raw if isinstance(version_raw, str) else None
        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(
            CryptoDependency(
                purl=pypi_purl(name, version),
                name=name,
                version=version,
                ecosystem="pypi",
                declared_in=path,
                introduces_algorithms=lookup_introduces("pypi", name),
            )
        )
    return deps
```

Run: `uv run pytest tests/unit/deps/test_uv_lock.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean.

- [ ] **Step 4: Commit**

```bash
git add src/pqcheck/deps/uv_lock.py tests/unit/deps/test_uv_lock.py
git commit -m "feat(deps): add uv.lock parser"
```

---

## Task 6: pom.xml parser (hardened against XXE + billion-laughs)

**Context:** Maven POM files declare deps under `<project><dependencies><dependency>` with `<groupId>`, `<artifactId>`, `<version>`. Versions often use property interpolation: `<version>${spring.version}</version>` where `spring.version` is defined in `<project><properties>`. For v0.1 we do **in-file** substitution only (no parent-POM walk, no `mvn` subprocess — those are Phase 3 per spec 03:422). If a property reference cannot be resolved in-file, we emit the dependency with `version=None` — the scanner orchestrator can then flag it or rerun under effective-pom in a later phase.

The XML parser MUST be hardened. pom.xml is the only XML format pqcheck reads in v0.1, and a malicious pom.xml in a customer's repo could attempt XXE (external entity) or billion-laughs (entity expansion DoS) attacks during a scan. We use `lxml.etree.XMLParser` with: `resolve_entities=False`, `no_network=True`, `huge_tree=False`, `dtd_validation=False`, `load_dtd=False`, `recover=False`. This is equivalent in effect to `defusedxml` but uses only the already-pinned `lxml` dep — no new supply-chain surface.

XML namespace handling: Maven 4 POMs declare `xmlns="http://maven.apache.org/POM/4.0.0"`. We use namespace-agnostic local-name matching via `etree.iterparse` + `etree.QName(...).localname` rather than encoding the namespace into XPath queries — this keeps the parser robust to versioned namespaces and to the (legal) absence of any xmlns.

**Files:**
- Create: `src/pqcheck/deps/pom_xml.py`
- Create: `tests/unit/deps/test_pom_xml.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/deps/test_pom_xml.py`:

```python
from pathlib import Path

from pqcheck.deps.pom_xml import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "pom.xml"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_basic_pom(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    by_artifact = {d.name: d for d in deps}
    assert by_artifact["bcprov-jdk18on"].version == "1.78"
    assert by_artifact["bcprov-jdk18on"].purl == (
        "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"
    )
    assert by_artifact["tink"].version == "1.14.0"
    assert all(d.ecosystem == "maven" for d in deps)


def test_parse_populates_introduces_algorithms(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert "RSA" in deps[0].introduces_algorithms
    assert "DES" in deps[0].introduces_algorithms


def test_parse_resolves_in_file_property_interpolation(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <bc.version>1.78</bc.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${bc.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "1.78"
    assert deps[0].purl.endswith("@1.78")


def test_parse_unresolvable_property_emits_none_version(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${missing.property}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version is None
    assert deps[0].purl == "pkg:maven/org.bouncycastle/bcprov-jdk18on"


def test_parse_skips_dependency_with_missing_artifact_id(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["tink"]


def test_parse_skips_dependency_with_missing_group_id(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    assert parse(f) == []


def test_parse_includes_dependency_management_section(tmp_path: Path) -> None:
    # dependencyManagement declares versions for downstream modules but
    # the artifacts are real coordinates and may introduce crypto. We
    # emit them; downstream policy decides whether to demote severity.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["bcprov-jdk18on"]


def test_parse_deduplicates_coordinates(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
""")
    assert len(parse(f)) == 1


def test_parse_pom_without_namespace(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].name == "tink"


def test_parse_invalid_xml_returns_empty_list(tmp_path: Path) -> None:
    f = _write(tmp_path, "<project><dependencies><dependency></project>")
    assert parse(f) == []


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "no-pom.xml") == []


def test_parse_rejects_external_entity_payload(tmp_path: Path) -> None:
    # /etc/passwd is the canonical XXE target. If the parser resolves the
    # entity, &xxe; expands and ends up as the groupId text. We assert
    # the parser does NOT expand it: either the parse fails (returns [])
    # OR the dependency is emitted with the raw &xxe; reference preserved
    # / blanked. We accept either failure mode but FORBID the expanded
    # payload showing up.
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<project>
  <dependencies>
    <dependency>
      <groupId>&xxe;</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
"""
    f = _write(tmp_path, payload)
    deps = parse(f)
    for dep in deps:
        # No file contents leaked into the dep tree.
        assert "root:" not in dep.purl
        assert "root:" not in dep.name
        # group_id either stays empty (entity not resolved) or contains
        # the raw entity ref text. We do not allow /etc/passwd contents.
        assert "/etc/passwd" not in dep.purl


def test_parse_rejects_billion_laughs_payload(tmp_path: Path) -> None:
    # Classic billion-laughs: 10 nested entities each expanding 10x.
    # With resolve_entities=False, the parser never expands lol9, so the
    # whole document either parses cheaply (entity refs untouched) or
    # fails fast. EITHER way it must complete quickly without OOMing.
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>&lol5;</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
"""
    f = _write(tmp_path, payload)
    import time
    start = time.perf_counter()
    deps = parse(f)
    elapsed = time.perf_counter() - start
    # Hard cap: should finish in well under 1 second on any laptop. If
    # expansion ran, this hits multi-seconds and gigabytes of RAM.
    assert elapsed < 1.0
    for dep in deps:
        # No expansion: the artifactId never blooms into 100k "lol"s.
        assert len(dep.name) < 100


def test_parse_oversized_file_returns_empty_list(tmp_path: Path) -> None:
    from pqcheck.deps.base import MAX_FILE_BYTES
    f = tmp_path / "huge.xml"
    # Build a payload that is just over the cap. The body doesn't need to
    # parse — safe_read_bytes rejects before lxml sees it.
    f.write_bytes(b"<project/>" + b" " * MAX_FILE_BYTES)
    assert parse(f) == []
```

Run: `uv run pytest tests/unit/deps/test_pom_xml.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 2: Implement the parser**

Create `src/pqcheck/deps/pom_xml.py`:

```python
"""Parser for Maven pom.xml — hardened against XXE and billion-laughs.

We use lxml.etree with the following parser config:
  - resolve_entities=False  -> entity refs (incl. external) are not expanded
  - no_network=True         -> no network fetches for DTDs / schemas
  - huge_tree=False         -> reject documents with insane depth / breadth
  - dtd_validation=False    -> no DTD validation
  - load_dtd=False          -> no DTD loading at all
  - recover=False           -> fail fast on malformed XML

Property interpolation is in-file only: <properties><foo>1.2</foo></properties>
substitutes ${foo} in <version> text. Parent-POM walking and effective-pom
expansion are Phase 3 per spec 03:422.

Namespace handling: Maven 4 POMs use xmlns="http://maven.apache.org/POM/4.0.0"
but the literal namespace is sometimes absent. We match elements by local
name only via etree.QName(...).localname.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from lxml import etree

from pqcheck.deps.base import maven_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

_PARSER_CONFIG: Final[dict[str, bool]] = {
    "resolve_entities": False,
    "no_network": True,
    "huge_tree": False,
    "dtd_validation": False,
    "load_dtd": False,
    "recover": False,
}

_PROPERTY_REF_RE = re.compile(r"\$\{([^}]+)\}")


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    parser = etree.XMLParser(**_PARSER_CONFIG)  # type: ignore[arg-type]
    try:
        root = etree.fromstring(raw, parser=parser)
    except etree.XMLSyntaxError:
        return []
    if root is None:  # pragma: no cover - lxml raises rather than returning None
        return []

    properties = _collect_properties(root)
    seen: set[tuple[str, str, str | None]] = set()
    deps: list[CryptoDependency] = []
    for dep_el in _iter_dependency_elements(root):
        group_id = _child_text(dep_el, "groupId")
        artifact_id = _child_text(dep_el, "artifactId")
        version_raw = _child_text(dep_el, "version")
        if not group_id or not artifact_id:
            continue
        version = _resolve_version(version_raw, properties)
        key = (group_id, artifact_id, version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(
            CryptoDependency(
                purl=maven_purl(group_id, artifact_id, version),
                name=artifact_id,
                version=version,
                ecosystem="maven",
                declared_in=path,
                introduces_algorithms=lookup_introduces("maven", artifact_id),
            )
        )
    return deps


def _local(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return etree.QName(tag).localname


def _child_text(element: etree._Element, local_name: str) -> str | None:
    for child in element:
        if _local(child.tag) == local_name:
            text = child.text
            if isinstance(text, str):
                stripped = text.strip()
                return stripped or None
    return None


def _collect_properties(root: etree._Element) -> dict[str, str]:
    """Return name -> value for entries in the top-level <properties> block.

    Nested property blocks inside profiles or build configs are ignored
    for v0.1 — covering them requires profile activation logic that
    belongs in the Phase 3 effective-pom resolver.
    """
    properties: dict[str, str] = {}
    for child in root:
        if _local(child.tag) != "properties":
            continue
        for prop in child:
            name = _local(prop.tag)
            text = prop.text
            if name and isinstance(text, str):
                stripped = text.strip()
                if stripped:
                    properties[name] = stripped
    return properties


def _iter_dependency_elements(root: etree._Element) -> list[etree._Element]:
    """Yield every <dependency> element under <dependencies> or
    <dependencyManagement>/<dependencies>, regardless of namespace."""
    deps: list[etree._Element] = []
    for child in root:
        tag = _local(child.tag)
        if tag == "dependencies":
            deps.extend(_direct_dependency_children(child))
        elif tag == "dependencyManagement":
            for grand in child:
                if _local(grand.tag) == "dependencies":
                    deps.extend(_direct_dependency_children(grand))
    return deps


def _direct_dependency_children(parent: etree._Element) -> list[etree._Element]:
    return [child for child in parent if _local(child.tag) == "dependency"]


def _resolve_version(version_raw: str | None, properties: dict[str, str]) -> str | None:
    if version_raw is None:
        return None
    match = _PROPERTY_REF_RE.fullmatch(version_raw)
    if match is None:
        # Either a literal version or a string with embedded refs we don't
        # try to resolve mid-token. Return as-is unless it looks unresolved.
        if _PROPERTY_REF_RE.search(version_raw):
            return None
        return version_raw
    return properties.get(match.group(1))
```

Run: `uv run pytest tests/unit/deps/test_pom_xml.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Verify the XXE test actually exercises the hardening**

The XXE test passes trivially if the parser silently expands `&xxe;` into empty string. We need to be sure the protection is the parser config, not luck. Temporarily flip `resolve_entities` to `True` in `_PARSER_CONFIG` and rerun:

```bash
sed -i 's/"resolve_entities": False/"resolve_entities": True/' src/pqcheck/deps/pom_xml.py
uv run pytest tests/unit/deps/test_pom_xml.py::test_parse_rejects_external_entity_payload -v
```

Expected: the test now MAY FAIL (entity gets expanded or lxml raises a different error). This confirms the hardening config is load-bearing.

Restore the config:

```bash
sed -i 's/"resolve_entities": True/"resolve_entities": False/' src/pqcheck/deps/pom_xml.py
uv run pytest tests/unit/deps/test_pom_xml.py -v
```

Expected: all tests PASS again.

(If the flipped-config test still passes — because lxml's defaults already block file:// scheme — that's fine, but document the discovery as a comment near `_PARSER_CONFIG` and keep the explicit config for defense-in-depth.)

- [ ] **Step 4: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean. (`lxml` stubs are pulled in via `types-lxml` already in the dev extras.)

- [ ] **Step 5: Commit**

```bash
git add src/pqcheck/deps/pom_xml.py tests/unit/deps/test_pom_xml.py
git commit -m "feat(deps): add hardened pom.xml parser (XXE/billion-laughs safe)"
```

---

## Task 7: Fixture-driven integration tests

**Context:** The unit tests use inline strings — useful for sharp assertions but they don't catch shape regressions when a parser change subtly alters output across the whole fixture corpus. Real fixtures + a single integration test give a snapshot-like guarantee against unintended drift.

**Files:**
- Create: `tests/fixtures/deps/pyproject_pep621.toml`
- Create: `tests/fixtures/deps/pyproject_with_groups.toml`
- Create: `tests/fixtures/deps/pyproject_no_project.toml`
- Create: `tests/fixtures/deps/pyproject_invalid.toml`
- Create: `tests/fixtures/deps/uv_basic.lock`
- Create: `tests/fixtures/deps/uv_workspace.lock`
- Create: `tests/fixtures/deps/uv_invalid.lock`
- Create: `tests/fixtures/deps/pom_basic.xml`
- Create: `tests/fixtures/deps/pom_with_props.xml`
- Create: `tests/fixtures/deps/pom_xxe.xml`
- Create: `tests/fixtures/deps/pom_billion_laughs.xml`
- Create: `tests/fixtures/deps/pom_invalid.xml`
- Create: `tests/integration/test_deps_integration.py`

- [ ] **Step 1: Create pyproject fixtures**

Create `tests/fixtures/deps/pyproject_pep621.toml`:

```toml
[project]
name = "fixture-demo"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "cryptography>=43.0.0",
    "pycryptodome==3.20.0",
    "requests>=2.31",
    "rsa==4.9",
]

[project.optional-dependencies]
test = ["pytest>=8.0", "hypothesis"]
crypto-extras = ["pynacl>=1.5", "ecdsa"]
```

Create `tests/fixtures/deps/pyproject_with_groups.toml`:

```toml
[project]
name = "fixture-demo"
dependencies = ["cryptography>=43.0.0"]

[dependency-groups]
dev = [
    "ruff>=0.7",
    "mypy>=1.13",
    {include-group = "test"},
]
test = [
    "pytest>=8.0",
    "ecdsa",
]
```

Create `tests/fixtures/deps/pyproject_no_project.toml`:

```toml
[tool.ruff]
line-length = 100

[tool.mypy]
strict = true
```

Create `tests/fixtures/deps/pyproject_invalid.toml`:

```
[project
name = "broken"
```

- [ ] **Step 2: Create uv.lock fixtures**

Create `tests/fixtures/deps/uv_basic.lock`:

```toml
version = 1
requires-python = ">=3.12"

[[package]]
name = "cryptography"
version = "43.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "cffi" },
]

[[package]]
name = "cffi"
version = "1.17.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "pycparser" },
]

[[package]]
name = "pycparser"
version = "2.22"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pyopenssl"
version = "24.2.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "cryptography" },
]
```

Create `tests/fixtures/deps/uv_workspace.lock`:

```toml
version = 1
requires-python = ">=3.12"

[[package]]
name = "my-workspace-member"
source = { workspace = true }
dependencies = [
    { name = "cryptography" },
]

[[package]]
name = "cryptography"
version = "43.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "ecdsa"
version = "0.19.0"
source = { registry = "https://pypi.org/simple" }
```

Create `tests/fixtures/deps/uv_invalid.lock`:

```
this is not [valid TOML
```

- [ ] **Step 3: Create pom.xml fixtures**

Create `tests/fixtures/deps/pom_basic.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.fixture</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>6.1.10</version>
    </dependency>
  </dependencies>
</project>
```

Create `tests/fixtures/deps/pom_with_props.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.fixture</groupId>
  <artifactId>props-demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <bc.version>1.78</bc.version>
    <tink.version>1.14.0</tink.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${bc.version}</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>${tink.version}</version>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcpkix-jdk18on</artifactId>
      <version>${missing.property}</version>
    </dependency>
  </dependencies>
</project>
```

Create `tests/fixtures/deps/pom_xxe.xml`:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>&xxe;</groupId>
  <artifactId>poisoned</artifactId>
  <version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
```

Create `tests/fixtures/deps/pom_billion_laughs.xml`:

```xml
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>&lol5;</artifactId>
  <version>1.0</version>
</project>
```

Create `tests/fixtures/deps/pom_invalid.xml`:

```xml
<project><dependencies><dependency></project>
```

- [ ] **Step 4: Write the failing integration test**

Create `tests/integration/test_deps_integration.py`:

```python
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
```

Run: `uv run pytest tests/integration/test_deps_integration.py -v`
Expected: all tests PASS.

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest`
Expected: every prior test still PASS, total coverage ≥ 85% (the gate). If any prior test broke, STOP and investigate — Task 1's `models.py` change is the most likely culprit.

- [ ] **Step 6: Type-check and lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`

Expected: both clean.

- [ ] **Step 7: Commit**

```bash
git add tests/fixtures/deps/ tests/integration/test_deps_integration.py
git commit -m "test(deps): add fixture corpus and integration test"
```

---

## Task 8: Verify branch readiness

**Context:** Last gate before opening the PR. Run everything one more time, confirm git history is clean, push the branch.

- [ ] **Step 1: Final full-suite run**

Run: `uv run pytest --cov=pqcheck --cov-report=term-missing 2>&1 | tail -20`
Expected: `passed`, coverage ≥ 85%, no `Missing` lines on the new `src/pqcheck/deps/*.py` files (every branch covered).

- [ ] **Step 2: Final type-check + lint**

Run in parallel:
- `uv run mypy`
- `uv run ruff check .`
- `uv run ruff format --check .`

Expected: all three clean. If ruff format complains, run `uv run ruff format .` then re-stage and amend the most recent commit (or, per the project's commit discipline memory, create a follow-up `style: …` commit — do NOT amend if the commit was already pushed).

- [ ] **Step 3: Confirm build still works**

Run: `uv build && twine check dist/*`
Expected: sdist + wheel succeed; `twine check` PASSED.

(`uv build` will regenerate `dist/` — if the directory already has artifacts from earlier, that's fine; twine inspects whatever is there.)

- [ ] **Step 4: Confirm git history is one logical change per commit**

Run: `git log --oneline develop..HEAD`
Expected:
```
feat(models): add CryptoDependency for deps parsers
feat(deps): seed introduces-algorithms catalog
feat(deps): add shared parser helpers (purl, safe-read, pep508)
feat(deps): add pyproject.toml parser (PEP 621 + PEP 735)
feat(deps): add uv.lock parser
feat(deps): add hardened pom.xml parser (XXE/billion-laughs safe)
test(deps): add fixture corpus and integration test
```

If the history looks different (typos, missing tests, etc.), use `git rebase -i develop` to clean it up BEFORE pushing. Never amend already-pushed commits.

- [ ] **Step 5: Push and open the PR**

```bash
git push -u origin feat/lockfile-parsers-pyproject-uv-pom
```

Then open a PR against `develop` (not `main` — main is reserved for release tags). The PR description should mention:
- Closes the "lockfile parsers pyproject/uv/pom" slice of `.context/plans/05-development-roadmap.md` Sem 0 Founder A work.
- Lists the three parsers, the catalog seed size, the XXE/billion-laughs hardening rationale.
- Notes the explicit scope cut (other lockfile formats deferred).

(No commit at this step — push only.)

---

## Self-review checklist

Run through this list before declaring the plan ready.

**Spec coverage** — every promised parser is built:
- pyproject.toml (PEP 621 + PEP 735): Task 4 ✓
- uv.lock v1: Task 5 ✓
- pom.xml (hardened, in-file properties): Task 6 ✓
- `CryptoDependency` model: Task 1 ✓
- `introduces_algorithms` catalog: Task 2 ✓
- PURL construction: Task 3 ✓
- File-size cap + per-file exception swallowing: Task 3 ✓
- Security hardening (XXE / billion-laughs / oversized): Task 6 + Task 3 ✓
- Integration tests with real fixtures: Task 7 ✓
- 85% coverage gate respected: Task 8 ✓

**Placeholder scan** — every step contains the actual content the engineer needs. No "TBD" / "implement later" / "add error handling" / "similar to Task N". Verified by reading top-to-bottom.

**Type consistency**:
- `parse(path: Path) -> list[CryptoDependency]` — same signature across all three parsers ✓
- `lookup_introduces(ecosystem: str, name: str) -> tuple[str, ...]` — same shape in Task 2 catalog and every parser call ✓
- `safe_read_bytes(path: Path) -> bytes | None` — same shape in `base.py` and every parser caller ✓
- `pypi_purl(name, version)` / `maven_purl(group_id, artifact_id, version)` — consistent across parsers and tests ✓
- `extract_pep508_name(requirement: str) -> str | None` — only used by pyproject_toml.py ✓
- `CryptoDependency.declared_in: Path` — always set to the input `path` in every parser ✓
- `CryptoDependency.ecosystem: str` — `"pypi"` for pyproject + uv, `"maven"` for pom ✓
- `CryptoDependency.introduces_algorithms: tuple[str, ...]` — always populated via `lookup_introduces(...)` ✓
- The `humanize-writing` skill (per user memory) is not applied to this plan because the existing python-ast-detector plan in `.context/plans/impl/` uses the same engineering-reference structure (tables, exact code blocks, scannable headers) — that's the established house style for plans in this repo. Apply humanize-writing to PR description / README / docs / public-facing prose, not to plan documents.
