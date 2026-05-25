# Python AST Detector — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `pqcheck.detectors.python_detector.detect_python_file(path) -> list[CryptoFinding]`, a stdlib-only AST detector that flags every cryptographic primitive use in a Python source file (per policy §2 approved + §3 banned), with confidence 0.7-1.0 and zero new third-party dependencies. Whole project keeps coverage ≥ 85% (the existing `pyproject.toml` gate).

**Architecture:** Two-pass stdlib `ast` walk per file. Pass 1 (`ImportResolver`): build map `local_name → fully_qualified_dotted_name`. Pass 2 (`PythonDetector(ast.NodeVisitor)`): on every `Call` node, resolve callee to a qualified name, look it up in a static `algorithms` catalog, extract optional kwargs (`key_size`, `curve`, `mode`, `padding`), and append a `CryptoFinding`. File-level wrapper handles file-size cap, syntax errors, and encoding errors without crashing the scanner.

**Tech Stack:**
- Python 3.12+ stdlib only for the detector: `ast`, `pathlib`, `dataclasses` / pydantic v2 (already a project dep), `tomllib` not needed here.
- No new third-party deps. (Memory: minimize supply-chain surface.)
- pydantic v2 is already in `pyproject.toml` and used by `CryptoFinding`.
- pytest + hypothesis (already in dev extras) for tests.

**Scope guard — what this plan does NOT build:**
- Full `models.py` per spec (computed `severity`, `ScanResult`, `CryptoDependency`, policy_decisions) — only the slice the detector emits. Downstream computed fields are a separate task.
- Algorithm registry beyond the canonical names the Python detector emits. Go/Java detectors will extend it later.
- Walker, scanner orchestrator, CBOM/SARIF output, policy engine, CLI wiring — separate tasks per `.context/plans/03-phase1-pqcheck-cli.md`.
- Evidence redaction (Phase 3 wire-format concern per 02:§5.7 + 03:338) — the local CLI keeps raw evidence.

---

## File structure

| Action | Path | Responsibility |
|---|---|---|
| Modify | `src/pqcheck/cli.py` | Add `# pragma: no cover` to the `if __name__ == "__main__":` guard (unreachable from pytest) — Task 0 |
| Modify | `src/pqcheck/__main__.py` | Add `# pragma: no cover` to `if __name__ == "__main__":` guard — Task 0 |
| Create | `tests/unit/test_cli_scan_stub.py` | Test the `scan` stub returns exit code 64 — Task 0 |
| (none) | `pyproject.toml` | Coverage gate stays at the existing `--cov-fail-under=85` — no change |
| Create | `src/pqcheck/models.py` | Detector-emitted types: `SourceLocation`, `AlgorithmFamily`, `QuantumRisk`, `CryptoFinding` — Task 1 |
| Create | `tests/unit/test_models.py` | Tests for models — Task 1 |
| Create | `src/pqcheck/detectors/__init__.py` | Empty package marker — Task 2 |
| Create | `src/pqcheck/detectors/algorithms.py` | Static catalog: qualified-name → `AlgorithmHit(canonical, family)` — Task 2 |
| Create | `tests/unit/detectors/__init__.py` | Empty package marker — Task 2 |
| Create | `tests/unit/detectors/test_algorithms.py` | Tests for catalog — Task 2 |
| Create | `src/pqcheck/detectors/python_detector.py` | `ImportResolver`, `PythonDetector`, `detect_python_file()` — Tasks 3-7 |
| Create | `tests/unit/detectors/test_python_detector.py` | Unit tests for detector — Tasks 3-7 |
| Create | `tests/fixtures/python/known_bad.py` | Banned primitives — Task 8 |
| Create | `tests/fixtures/python/known_good.py` | Quantum-safe primitives — Task 8 |
| Create | `tests/fixtures/python/mixed_pycryptodome.py` | pycryptodome banned + good — Task 8 |
| Create | `tests/fixtures/python/edge_syntax_error.py` | Intentional `SyntaxError` — Task 8 |
| Create | `tests/integration/test_python_detector_integration.py` | Detector run against fixtures — Task 8 |

**Why one detector file (not split into `python_imports.py` + `python_args.py`):** The resolver and the visitor share a tightly-coupled state machine — splitting them creates a circular-ish import (detector imports resolver, tests import both). Keeping them in one ~250-line file beats the abstraction tax. Algorithms catalog stays separate because it's pure data with a different change frequency.

---

## Task 0: Fix baseline coverage gate

**Context:** Current `uv run pytest --cov=pqcheck` reports 62% (below the 85% gate already in `pyproject.toml`). `__main__.py:1-4` and `cli.py:30,34` are uncovered. We fix this before adding new code so every later task can run the full `uv run pytest` cleanly without the gate failing for reasons unrelated to the detector. The gate stays at 85% — we are not raising it.

**Files:**
- Modify: `src/pqcheck/cli.py:30,34`
- Modify: `src/pqcheck/__main__.py:3-4`
- Create: `tests/unit/test_cli_scan_stub.py`

- [ ] **Step 1: Confirm current coverage failure**

Run: `uv run pytest --cov=pqcheck --cov-report=term-missing 2>&1 | tail -10`
Expected: `FAIL Required test coverage of 85% not reached. Total coverage: 61.90%`

- [ ] **Step 2: Write the failing test for the `scan` stub**

Create `tests/unit/test_cli_scan_stub.py`:

```python
from typer.testing import CliRunner

from pqcheck.cli import app


def test_scan_stub_exits_with_usage_error() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "."])
    assert result.exit_code == 64
```

Run: `uv run pytest tests/unit/test_cli_scan_stub.py -v`
Expected: PASS (the stub already raises `typer.Exit(code=64)`; we just lacked a test).

- [ ] **Step 3: Add `# pragma: no cover` to the unreachable `__main__` guards**

In `src/pqcheck/cli.py`, replace:
```python
if __name__ == "__main__":
    app()
```
with:
```python
if __name__ == "__main__":  # pragma: no cover
    app()
```

In `src/pqcheck/__main__.py`, replace:
```python
if __name__ == "__main__":
    app()
```
with:
```python
if __name__ == "__main__":  # pragma: no cover
    app()
```

The whole body of `__main__.py` is `from pqcheck.cli import app` + the guard. The `from` import is exercised whenever the module loads. To force coverage to load the module at least once, add a test. The `__main__` import must be at module scope (ruff `PLC0415` forbids in-function imports under the project's selected rules); use an aliased import:

At the top of `tests/unit/test_cli_scan_stub.py` add:

```python
import pqcheck.__main__ as main_module
```

Then append the test body:

```python
def test_main_module_exposes_app() -> None:
    assert main_module.app is app
```

- [ ] **Step 4: Confirm baseline now clears the 85% gate**

Run: `uv run pytest --cov=pqcheck --cov-report=term-missing 2>&1 | tail -15`
Expected: Total coverage ≥ 85% (in practice ≥ 95% on the tiny current surface); no `Missing` lines on `cli.py` or `__main__.py`; no `FAIL Required test coverage` line.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_cli_scan_stub.py src/pqcheck/cli.py src/pqcheck/__main__.py
git commit -m "test: cover cli.scan stub and __main__ entry guard"
```

---

## Task 1: Domain models slice

**Context:** The detector emits `CryptoFinding`. We need the minimum slice of `models.py` to build a `CryptoFinding` instance: `SourceLocation`, `AlgorithmFamily` enum, `QuantumRisk` enum, `CryptoFinding` itself with `quantum_risk` as a computed field. Computed `severity`/`base_severity`/`confidence_band` are downstream (consumed by policy engine) — defer to its own task.

**Files:**
- Create: `src/pqcheck/models.py`
- Create: `tests/unit/test_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_models.py`:

```python
from pathlib import Path

import pytest
from pydantic import ValidationError

from pqcheck.models import (
    AlgorithmFamily,
    CryptoFinding,
    QuantumRisk,
    SourceLocation,
)


def test_source_location_requires_positive_line() -> None:
    with pytest.raises(ValidationError):
        SourceLocation(path=Path("a.py"), line=0, column=0)


def test_source_location_is_frozen() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    with pytest.raises(ValidationError):
        loc.line = 2  # type: ignore[misc]


def test_crypto_finding_minimal_construction() -> None:
    loc = SourceLocation(path=Path("a.py"), line=10, column=4)
    finding = CryptoFinding(
        algorithm="MD5",
        family=AlgorithmFamily.HASH,
        location=loc,
        evidence="hashlib.md5()",
        detector_id="python-ast",
    )
    assert finding.algorithm == "MD5"
    assert finding.family is AlgorithmFamily.HASH
    assert finding.confidence == 1.0


def test_quantum_risk_resolved_from_algorithm_name() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    md5 = CryptoFinding(
        algorithm="MD5", family=AlgorithmFamily.HASH, location=loc,
        evidence="x", detector_id="python-ast",
    )
    rsa = CryptoFinding(
        algorithm="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION, location=loc,
        evidence="x", detector_id="python-ast",
    )
    aes = CryptoFinding(
        algorithm="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER, location=loc,
        evidence="x", detector_id="python-ast",
    )
    unknown = CryptoFinding(
        algorithm="WHIRLPOOL", family=AlgorithmFamily.HASH, location=loc,
        evidence="x", detector_id="python-ast",
    )
    assert md5.quantum_risk is QuantumRisk.BROKEN
    assert rsa.quantum_risk is QuantumRisk.VULNERABLE
    assert aes.quantum_risk is QuantumRisk.SAFE
    assert unknown.quantum_risk is QuantumRisk.UNKNOWN


def test_confidence_bounded_0_to_1() -> None:
    loc = SourceLocation(path=Path("a.py"), line=1, column=0)
    with pytest.raises(ValidationError):
        CryptoFinding(
            algorithm="MD5", family=AlgorithmFamily.HASH, location=loc,
            evidence="x", detector_id="python-ast", confidence=1.5,
        )
```

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pqcheck.models'`.

- [ ] **Step 2: Implement the minimum models slice**

Create `src/pqcheck/models.py`:

```python
"""Domain types emitted by language detectors.

Only the slice consumed by the Python AST detector lives here today.
Downstream computed fields (severity, base_severity, confidence_band,
ScanResult, CryptoDependency, policy_decisions) are added when the
policy engine and scanner orchestrator land.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, computed_field


class AlgorithmFamily(str, Enum):
    SYMMETRIC_CIPHER = "symmetric-cipher"
    ASYMMETRIC_ENCRYPTION = "asymmetric-encryption"
    KEY_AGREEMENT = "key-agreement"
    KEM = "key-encapsulation"
    SIGNATURE = "signature"
    HASH = "hash"
    MAC = "message-authentication"
    KDF = "key-derivation"
    RNG = "random"
    AEAD = "authenticated-encryption"


class QuantumRisk(str, Enum):
    SAFE = "quantum-safe"
    HYBRID = "hybrid"
    VULNERABLE = "quantum-vulnerable"
    BROKEN = "broken"
    UNKNOWN = "unknown"


_QUANTUM_MAP: dict[str, QuantumRisk] = {
    "RSA": QuantumRisk.VULNERABLE,
    "DSA": QuantumRisk.VULNERABLE,
    "ECDSA": QuantumRisk.VULNERABLE,
    "ECDH": QuantumRisk.VULNERABLE,
    "DH": QuantumRisk.VULNERABLE,
    "ED25519": QuantumRisk.VULNERABLE,
    "ED448": QuantumRisk.VULNERABLE,
    "X25519": QuantumRisk.VULNERABLE,
    "X448": QuantumRisk.VULNERABLE,
    "AES": QuantumRisk.SAFE,
    "CHACHA20": QuantumRisk.SAFE,
    "SHA-256": QuantumRisk.SAFE,
    "SHA-384": QuantumRisk.SAFE,
    "SHA-512": QuantumRisk.SAFE,
    "SHA3-256": QuantumRisk.SAFE,
    "SHA3-384": QuantumRisk.SAFE,
    "SHA3-512": QuantumRisk.SAFE,
    "BLAKE2B": QuantumRisk.SAFE,
    "BLAKE2S": QuantumRisk.SAFE,
    "ML-KEM": QuantumRisk.SAFE,
    "ML-DSA": QuantumRisk.SAFE,
    "SLH-DSA": QuantumRisk.SAFE,
    "MD5": QuantumRisk.BROKEN,
    "SHA-1": QuantumRisk.BROKEN,
    "DES": QuantumRisk.BROKEN,
    "3DES": QuantumRisk.BROKEN,
    "RC4": QuantumRisk.BROKEN,
}


class SourceLocation(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: Path
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    end_line: int | None = None
    end_column: int | None = None


class CryptoFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    algorithm: str
    family: AlgorithmFamily
    key_size: int | None = None
    curve: str | None = None
    mode: str | None = None
    padding: str | None = None
    location: SourceLocation
    evidence: str
    detector_id: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def quantum_risk(self) -> QuantumRisk:
        return _QUANTUM_MAP.get(self.algorithm.upper(), QuantumRisk.UNKNOWN)
```

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: 5 tests PASS.

- [ ] **Step 3: Confirm `mypy --strict` is happy**

Run: `uv run mypy src/pqcheck/models.py`
Expected: `Success: no issues found in 1 source file`.

- [ ] **Step 4: Commit**

```bash
git add src/pqcheck/models.py tests/unit/test_models.py
git commit -m "feat(models): add SourceLocation, CryptoFinding, AlgorithmFamily, QuantumRisk

Minimum slice consumed by the Python AST detector. Computed severity
and ScanResult land with the policy engine / scanner orchestrator."
```

---

## Task 2: Algorithm catalog

**Context:** The detector resolves a Call's callee to a fully-qualified dotted name (e.g. `cryptography.hazmat.primitives.hashes.MD5`) and needs to map it to `(canonical_name, family)`. Pure data, no logic. Sourced from policy §2 (approved) + §3 (banned) + Python ecosystem libs (`cryptography`, `hashlib`, `pycryptodome`).

**Files:**
- Create: `src/pqcheck/detectors/__init__.py`
- Create: `src/pqcheck/detectors/algorithms.py`
- Create: `tests/unit/detectors/__init__.py`
- Create: `tests/unit/detectors/test_algorithms.py`

- [ ] **Step 1: Write the failing test**

Create `src/pqcheck/detectors/__init__.py` (empty file):

```python
```

Create `tests/unit/detectors/__init__.py` (empty file):

```python
```

Create `tests/unit/detectors/test_algorithms.py`:

```python
from pqcheck.detectors.algorithms import AlgorithmHit, lookup_python_symbol
from pqcheck.models import AlgorithmFamily


def test_hashlib_md5_resolves() -> None:
    hit = lookup_python_symbol("hashlib.md5")
    assert hit == AlgorithmHit(canonical="MD5", family=AlgorithmFamily.HASH)


def test_hashlib_sha1_resolves() -> None:
    hit = lookup_python_symbol("hashlib.sha1")
    assert hit == AlgorithmHit(canonical="SHA-1", family=AlgorithmFamily.HASH)


def test_cryptography_hashes_md5_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.hashes.MD5"
    )
    assert hit == AlgorithmHit(canonical="MD5", family=AlgorithmFamily.HASH)


def test_cryptography_rsa_generate_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key"
    )
    assert hit == AlgorithmHit(
        canonical="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    )


def test_cryptography_ec_generate_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key"
    )
    assert hit == AlgorithmHit(
        canonical="ECDSA", family=AlgorithmFamily.SIGNATURE
    )


def test_cryptography_cipher_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.ciphers.Cipher"
    )
    assert hit is not None
    assert hit.canonical == "CIPHER-WRAPPER"
    assert hit.family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_cryptography_algorithms_aes_resolves() -> None:
    hit = lookup_python_symbol(
        "cryptography.hazmat.primitives.ciphers.algorithms.AES"
    )
    assert hit == AlgorithmHit(
        canonical="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER
    )


def test_pycryptodome_aes_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Cipher.AES.new")
    assert hit == AlgorithmHit(
        canonical="AES", family=AlgorithmFamily.SYMMETRIC_CIPHER
    )


def test_pycryptodome_rsa_generate_resolves() -> None:
    hit = lookup_python_symbol("Crypto.PublicKey.RSA.generate")
    assert hit == AlgorithmHit(
        canonical="RSA", family=AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    )


def test_pycryptodome_hash_md5_new_resolves() -> None:
    hit = lookup_python_symbol("Crypto.Hash.MD5.new")
    assert hit == AlgorithmHit(canonical="MD5", family=AlgorithmFamily.HASH)


def test_unknown_symbol_returns_none() -> None:
    assert lookup_python_symbol("os.getcwd") is None
    assert lookup_python_symbol("") is None
    assert lookup_python_symbol("nothing.at.all") is None
```

Run: `uv run pytest tests/unit/detectors/test_algorithms.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pqcheck.detectors.algorithms'`.

- [ ] **Step 2: Implement the catalog**

Create `src/pqcheck/detectors/algorithms.py`:

```python
"""Static catalog mapping language-level symbols to canonical algorithms.

Python-specific lookups for v0.1. Go and Java detectors extend the
catalog with their own lookup functions; canonical names are shared
across languages so downstream policy rules apply uniformly.
"""

from __future__ import annotations

from dataclasses import dataclass

from pqcheck.models import AlgorithmFamily


@dataclass(frozen=True, slots=True)
class AlgorithmHit:
    canonical: str
    family: AlgorithmFamily


_HASH = AlgorithmFamily.HASH
_ASYM = AlgorithmFamily.ASYMMETRIC_ENCRYPTION
_SIG = AlgorithmFamily.SIGNATURE
_KA = AlgorithmFamily.KEY_AGREEMENT
_SYM = AlgorithmFamily.SYMMETRIC_CIPHER


# Fully-qualified callee name → AlgorithmHit.
# Canonical names follow policy §2/§3 spelling (uppercase, hyphenated).
_PYTHON_SYMBOLS: dict[str, AlgorithmHit] = {
    # ---- hashlib (stdlib) ----
    "hashlib.md5": AlgorithmHit("MD5", _HASH),
    "hashlib.sha1": AlgorithmHit("SHA-1", _HASH),
    "hashlib.sha224": AlgorithmHit("SHA-224", _HASH),
    "hashlib.sha256": AlgorithmHit("SHA-256", _HASH),
    "hashlib.sha384": AlgorithmHit("SHA-384", _HASH),
    "hashlib.sha512": AlgorithmHit("SHA-512", _HASH),
    "hashlib.sha3_256": AlgorithmHit("SHA3-256", _HASH),
    "hashlib.sha3_384": AlgorithmHit("SHA3-384", _HASH),
    "hashlib.sha3_512": AlgorithmHit("SHA3-512", _HASH),
    "hashlib.blake2b": AlgorithmHit("BLAKE2B", _HASH),
    "hashlib.blake2s": AlgorithmHit("BLAKE2S", _HASH),
    # ---- cryptography.hazmat.primitives.hashes ----
    "cryptography.hazmat.primitives.hashes.MD5": AlgorithmHit("MD5", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA1": AlgorithmHit("SHA-1", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA224": AlgorithmHit("SHA-224", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA256": AlgorithmHit("SHA-256", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA384": AlgorithmHit("SHA-384", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA512": AlgorithmHit("SHA-512", _HASH),
    "cryptography.hazmat.primitives.hashes.SHA3_256": AlgorithmHit("SHA3-256", _HASH),
    # ---- cryptography asymmetric keygens ----
    "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key": AlgorithmHit("RSA", _ASYM),
    "cryptography.hazmat.primitives.asymmetric.dsa.generate_private_key": AlgorithmHit("DSA", _SIG),
    "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key": AlgorithmHit("ECDSA", _SIG),
    "cryptography.hazmat.primitives.asymmetric.dh.generate_parameters": AlgorithmHit("DH", _KA),
    "cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey.generate": AlgorithmHit("ED25519", _SIG),
    "cryptography.hazmat.primitives.asymmetric.ed448.Ed448PrivateKey.generate": AlgorithmHit("ED448", _SIG),
    "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate": AlgorithmHit("X25519", _KA),
    "cryptography.hazmat.primitives.asymmetric.x448.X448PrivateKey.generate": AlgorithmHit("X448", _KA),
    # ---- cryptography ciphers wrapper + algorithms + modes ----
    # The Cipher(...) wrapper is detected as a marker so the visitor can
    # walk its args to extract the concrete algorithm + mode.
    "cryptography.hazmat.primitives.ciphers.Cipher": AlgorithmHit("CIPHER-WRAPPER", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.AES": AlgorithmHit("AES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.AES128": AlgorithmHit("AES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.AES256": AlgorithmHit("AES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.TripleDES": AlgorithmHit("3DES", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.ARC4": AlgorithmHit("RC4", _SYM),
    "cryptography.hazmat.primitives.ciphers.algorithms.ChaCha20": AlgorithmHit("CHACHA20", _SYM),
    # ---- pycryptodome ----
    "Crypto.Hash.MD5.new": AlgorithmHit("MD5", _HASH),
    "Crypto.Hash.SHA1.new": AlgorithmHit("SHA-1", _HASH),
    "Crypto.Hash.SHA256.new": AlgorithmHit("SHA-256", _HASH),
    "Crypto.Hash.SHA384.new": AlgorithmHit("SHA-384", _HASH),
    "Crypto.Hash.SHA512.new": AlgorithmHit("SHA-512", _HASH),
    "Crypto.Cipher.AES.new": AlgorithmHit("AES", _SYM),
    "Crypto.Cipher.DES.new": AlgorithmHit("DES", _SYM),
    "Crypto.Cipher.DES3.new": AlgorithmHit("3DES", _SYM),
    "Crypto.Cipher.ARC4.new": AlgorithmHit("RC4", _SYM),
    "Crypto.Cipher.ChaCha20.new": AlgorithmHit("CHACHA20", _SYM),
    "Crypto.PublicKey.RSA.generate": AlgorithmHit("RSA", _ASYM),
    "Crypto.PublicKey.DSA.generate": AlgorithmHit("DSA", _SIG),
    "Crypto.PublicKey.ECC.generate": AlgorithmHit("ECDSA", _SIG),
}


# Cipher-mode classes: dotted suffix → mode name. Used when the visitor
# walks `Cipher(algorithms.AES(...), modes.GCM(...))` to extract the mode.
_CIPHER_MODES: dict[str, str] = {
    "cryptography.hazmat.primitives.ciphers.modes.GCM": "GCM",
    "cryptography.hazmat.primitives.ciphers.modes.CBC": "CBC",
    "cryptography.hazmat.primitives.ciphers.modes.ECB": "ECB",
    "cryptography.hazmat.primitives.ciphers.modes.CTR": "CTR",
    "cryptography.hazmat.primitives.ciphers.modes.OFB": "OFB",
    "cryptography.hazmat.primitives.ciphers.modes.CFB": "CFB",
    "cryptography.hazmat.primitives.ciphers.modes.XTS": "XTS",
}


# pycryptodome AES.MODE_* attribute → mode name.
_PYCRYPTODOME_MODE_ATTRS: dict[str, str] = {
    "Crypto.Cipher.AES.MODE_GCM": "GCM",
    "Crypto.Cipher.AES.MODE_CBC": "CBC",
    "Crypto.Cipher.AES.MODE_ECB": "ECB",
    "Crypto.Cipher.AES.MODE_CTR": "CTR",
    "Crypto.Cipher.AES.MODE_OFB": "OFB",
    "Crypto.Cipher.AES.MODE_CFB": "CFB",
}


def lookup_python_symbol(qualified_name: str) -> AlgorithmHit | None:
    if not qualified_name:
        return None
    return _PYTHON_SYMBOLS.get(qualified_name)


def lookup_cipher_mode(qualified_name: str) -> str | None:
    return _CIPHER_MODES.get(qualified_name) or _PYCRYPTODOME_MODE_ATTRS.get(qualified_name)
```

Run: `uv run pytest tests/unit/detectors/test_algorithms.py -v`
Expected: 11 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/pqcheck/detectors/__init__.py src/pqcheck/detectors/algorithms.py tests/unit/detectors/__init__.py tests/unit/detectors/test_algorithms.py
git commit -m "feat(detectors): add Python crypto symbol catalog

Static map: fully-qualified callee → (canonical algorithm, family).
Covers hashlib, cryptography.hazmat.primitives, and pycryptodome."
```

---

## Task 3: ImportResolver — qualified-name resolution

**Context:** Pass 1 of the two-pass walk. Build a map `local_name → fully_qualified_dotted_name` by visiting `Import` and `ImportFrom` nodes. The detector then resolves a `Call` node's callee (Attribute or Name chain) to a fully-qualified string. `from X import *` is recorded as a sentinel (we cannot resolve names from a star import without runtime semantics, so we skip detections in files that use it for crypto modules and surface this as a known limitation).

**Files:**
- Create: `src/pqcheck/detectors/python_detector.py`
- Create: `tests/unit/detectors/test_python_detector.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/detectors/test_python_detector.py`:

```python
import ast

from pqcheck.detectors.python_detector import ImportResolver


def _resolver(source: str) -> ImportResolver:
    tree = ast.parse(source)
    r = ImportResolver()
    r.visit(tree)
    return r


def test_plain_import_records_module_name() -> None:
    r = _resolver("import hashlib")
    assert r.resolve_name("hashlib") == "hashlib"


def test_import_with_alias_records_alias() -> None:
    r = _resolver("import hashlib as h")
    assert r.resolve_name("h") == "hashlib"
    assert r.resolve_name("hashlib") is None


def test_dotted_import_records_full_path() -> None:
    r = _resolver("import cryptography.hazmat.primitives.hashes")
    assert r.resolve_name("cryptography") == "cryptography"


def test_from_import_records_qualified_symbol() -> None:
    r = _resolver("from hashlib import md5")
    assert r.resolve_name("md5") == "hashlib.md5"


def test_from_import_with_alias() -> None:
    r = _resolver("from hashlib import md5 as digest")
    assert r.resolve_name("digest") == "hashlib.md5"
    assert r.resolve_name("md5") is None


def test_from_dotted_module_import() -> None:
    r = _resolver(
        "from cryptography.hazmat.primitives import hashes"
    )
    assert r.resolve_name("hashes") == "cryptography.hazmat.primitives.hashes"


def test_star_import_recorded_as_sentinel() -> None:
    r = _resolver("from hashlib import *")
    assert r.has_star_import("hashlib") is True


def test_resolve_attribute_chain_on_name() -> None:
    tree = ast.parse("hashlib.md5()")
    r = ImportResolver()
    r.add_module("hashlib", "hashlib")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) == "hashlib.md5"


def test_resolve_attribute_chain_with_alias() -> None:
    tree = ast.parse("h.md5()")
    r = ImportResolver()
    r.add_module("h", "hashlib")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) == "hashlib.md5"


def test_resolve_attribute_chain_three_segments() -> None:
    tree = ast.parse("hashes.MD5()")
    r = ImportResolver()
    r.add_module("hashes", "cryptography.hazmat.primitives.hashes")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) == (
        "cryptography.hazmat.primitives.hashes.MD5"
    )


def test_unresolved_name_returns_none() -> None:
    tree = ast.parse("foo.bar()")
    r = ImportResolver()
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) is None
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 2: Implement `ImportResolver`**

Create `src/pqcheck/detectors/python_detector.py`:

```python
"""Python AST detector — emits CryptoFinding per detected primitive use.

Two passes over the file's AST:
  1. ImportResolver records local_name → fully_qualified_dotted_name.
  2. PythonDetector visits every Call and resolves its callee against
     the catalog in pqcheck.detectors.algorithms.

Both passes are stdlib-only (ast module). No third-party deps beyond
pydantic, which the project already uses for CryptoFinding.
"""

from __future__ import annotations

import ast


class ImportResolver(ast.NodeVisitor):
    """First pass: build local-name → qualified-name map.

    Star imports are recorded but not expanded — there is no way to know
    which names a `from X import *` binds without importing X. Files
    using star imports for crypto modules are flagged via has_star_import.
    """

    def __init__(self) -> None:
        self._names: dict[str, str] = {}
        self._star_imports: set[str] = set()

    # ---- public API used by PythonDetector and tests ----

    def add_module(self, local: str, qualified: str) -> None:
        self._names[local] = qualified

    def resolve_name(self, local: str) -> str | None:
        return self._names.get(local)

    def has_star_import(self, module: str) -> bool:
        return module in self._star_imports

    def resolve_attribute(self, node: ast.expr) -> str | None:
        """Resolve a Name or Attribute chain to its fully-qualified name.

        Examples (with `hashlib` recorded as itself, `h` as alias):
          ast.parse("hashlib.md5").body[0].value           -> "hashlib.md5"
          ast.parse("h.md5").body[0].value                 -> "hashlib.md5"
          ast.parse("hashes.MD5").body[0].value            -> "<resolved>.MD5"
        """
        parts: list[str] = []
        current: ast.expr | None = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        base = self._names.get(current.id)
        if base is None:
            return None
        parts.reverse()
        return ".".join([base, *parts]) if parts else base

    # ---- ast.NodeVisitor hooks ----

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            qualified = alias.name if alias.asname else alias.name.split(".", 1)[0]
            self._names[local] = qualified

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        # Skip relative imports — we cannot resolve them to a project-
        # independent qualified name, and crypto libs are never relative.
        if node.level and node.level > 0:
            return
        for alias in node.names:
            if alias.name == "*":
                self._star_imports.add(module)
                continue
            local = alias.asname or alias.name
            qualified = f"{module}.{alias.name}" if module else alias.name
            self._names[local] = qualified
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: 11 tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/pqcheck/detectors/python_detector.py tests/unit/detectors/test_python_detector.py
git commit -m "feat(detectors): add ImportResolver for Python AST pass 1

Resolves Name/Attribute chains to fully-qualified dotted names via
recorded imports. Star imports recorded as a sentinel, not expanded."
```

---

## Task 4: PythonDetector — basic Call detection

**Context:** Pass 2. On every `ast.Call`, resolve callee → qualified name → look up in catalog → if hit, emit a `CryptoFinding` with confidence 1.0 (resolved import path is a strong signal). This task covers the flat case: `hashlib.md5(...)`, `rsa.generate_private_key(...)`, `Crypto.Hash.MD5.new(...)`. Cipher wrapper and arg extraction are Tasks 5 and 6.

**Files:**
- Modify: `src/pqcheck/detectors/python_detector.py`
- Modify: `tests/unit/detectors/test_python_detector.py`

- [ ] **Step 1: Add failing tests for PythonDetector basic flow**

Append to `tests/unit/detectors/test_python_detector.py`:

```python
from pathlib import Path

from pqcheck.detectors.python_detector import PythonDetector
from pqcheck.models import AlgorithmFamily, QuantumRisk


def _scan(source: str, path: str = "sample.py") -> list:
    tree = ast.parse(source)
    detector = PythonDetector(source_path=Path(path), source=source)
    detector.visit(tree)
    return detector.findings


def test_detector_finds_hashlib_md5_call() -> None:
    findings = _scan("import hashlib\nhashlib.md5(b'x')\n")
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "MD5"
    assert f.family is AlgorithmFamily.HASH
    assert f.quantum_risk is QuantumRisk.BROKEN
    assert f.location.line == 2
    assert f.detector_id == "python-ast"
    assert f.confidence == 1.0


def test_detector_finds_md5_via_from_import() -> None:
    findings = _scan("from hashlib import md5\nmd5(b'x')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detector_finds_md5_via_alias() -> None:
    findings = _scan("from hashlib import md5 as digest\ndigest(b'x')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detector_finds_rsa_keygen() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA"
    assert findings[0].family is AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    assert findings[0].quantum_risk is QuantumRisk.VULNERABLE


def test_detector_finds_pycryptodome_aes() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'\\x00' * 32, AES.MODE_GCM)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_detector_ignores_unknown_calls() -> None:
    findings = _scan("import os\nos.getcwd()\nprint('hi')\n")
    assert findings == []


def test_detector_records_evidence_snippet() -> None:
    findings = _scan("import hashlib\nhashlib.md5(b'x')\n")
    assert "hashlib.md5" in findings[0].evidence


def test_detector_starts_with_empty_findings() -> None:
    findings = _scan("x = 1\n")
    assert findings == []


def test_detector_demotes_confidence_for_hashlib_new_string() -> None:
    findings = _scan("import hashlib\nhashlib.new('md5')\n")
    # String-based dynamic dispatch — confidence demoted vs direct call.
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
    assert findings[0].confidence == 0.7
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: FAIL (ImportError on PythonDetector).

- [ ] **Step 2: Implement `PythonDetector` core + `hashlib.new(...)` special case**

Append to `src/pqcheck/detectors/python_detector.py`:

```python
from pathlib import Path

from pqcheck.detectors.algorithms import lookup_python_symbol
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation


_DETECTOR_ID = "python-ast"

# Lower-cased argument values accepted by hashlib.new("...") that map
# directly to canonical algorithm names. Confidence is demoted because
# the string argument could be runtime-computed (we only see literals).
_HASHLIB_NEW_NAMES: dict[str, tuple[str, AlgorithmFamily]] = {
    "md5": ("MD5", AlgorithmFamily.HASH),
    "sha1": ("SHA-1", AlgorithmFamily.HASH),
    "sha224": ("SHA-224", AlgorithmFamily.HASH),
    "sha256": ("SHA-256", AlgorithmFamily.HASH),
    "sha384": ("SHA-384", AlgorithmFamily.HASH),
    "sha512": ("SHA-512", AlgorithmFamily.HASH),
    "sha3_256": ("SHA3-256", AlgorithmFamily.HASH),
    "sha3_384": ("SHA3-384", AlgorithmFamily.HASH),
    "sha3_512": ("SHA3-512", AlgorithmFamily.HASH),
    "blake2b": ("BLAKE2B", AlgorithmFamily.HASH),
    "blake2s": ("BLAKE2S", AlgorithmFamily.HASH),
}


class PythonDetector(ast.NodeVisitor):
    """Second pass: emit CryptoFinding per detected primitive use."""

    def __init__(self, source_path: Path, source: str) -> None:
        self._path = source_path
        self._source_lines = source.splitlines()
        self._imports = ImportResolver()
        self.findings: list[CryptoFinding] = []

    def visit(self, node: ast.AST) -> None:
        # Pass 1: collect imports before walking calls.
        if isinstance(node, ast.Module):
            self._imports.visit(node)
        super().visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qualified = self._imports.resolve_attribute(node.func)
        if qualified is not None:
            hit = lookup_python_symbol(qualified)
            if hit is not None and hit.canonical != "CIPHER-WRAPPER":
                self._emit(node, hit.canonical, hit.family, confidence=1.0)
        # hashlib.new("md5") — string-based dispatch, demoted confidence.
        if qualified == "hashlib.new":
            self._emit_hashlib_new(node)
        self.generic_visit(node)

    def _emit_hashlib_new(self, node: ast.Call) -> None:
        if not node.args:
            return
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return
        key = first.value.lower()
        mapping = _HASHLIB_NEW_NAMES.get(key)
        if mapping is None:
            return
        canonical, family = mapping
        self._emit(node, canonical, family, confidence=0.7)

    def _emit(
        self,
        node: ast.Call,
        canonical: str,
        family: AlgorithmFamily,
        *,
        confidence: float,
        key_size: int | None = None,
        curve: str | None = None,
        mode: str | None = None,
        padding: str | None = None,
    ) -> None:
        location = SourceLocation(
            path=self._path,
            line=node.lineno,
            column=node.col_offset,
            end_line=node.end_lineno,
            end_column=node.end_col_offset,
        )
        self.findings.append(
            CryptoFinding(
                algorithm=canonical,
                family=family,
                key_size=key_size,
                curve=curve,
                mode=mode,
                padding=padding,
                location=location,
                evidence=self._evidence(node),
                detector_id=_DETECTOR_ID,
                confidence=confidence,
            )
        )

    def _evidence(self, node: ast.Call) -> str:
        line_idx = node.lineno - 1
        if 0 <= line_idx < len(self._source_lines):
            return self._source_lines[line_idx].strip()
        return ""
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: All tests PASS (Task 3 tests still pass; Task 4 tests now pass).

- [ ] **Step 3: Commit**

```bash
git add src/pqcheck/detectors/python_detector.py tests/unit/detectors/test_python_detector.py
git commit -m "feat(detectors): PythonDetector emits findings on resolved Calls

Confidence 1.0 for fully-resolved imports; 0.7 for hashlib.new(literal)
string-based dispatch. Cipher wrapper and arg extraction land next."
```

---

## Task 5: Cipher wrapper — extract algorithm + mode

**Context:** `cryptography.hazmat.primitives.ciphers.Cipher(algorithms.AES(key), modes.GCM(iv))` is the canonical pattern. We detected it as `CIPHER-WRAPPER` in Task 4 but emitted nothing. Now we inspect args (positional or keyword `algorithm=`, `mode=`), resolve each nested Call's callee, and emit ONE finding with the concrete algorithm + mode.

**Files:**
- Modify: `src/pqcheck/detectors/python_detector.py`
- Modify: `tests/unit/detectors/test_python_detector.py`

- [ ] **Step 1: Add failing tests**

Append to `tests/unit/detectors/test_python_detector.py`:

```python
def test_detector_finds_aes_gcm_cipher() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'\\x00' * 32), modes.GCM(b'\\x00' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "AES"
    assert f.mode == "GCM"
    assert f.family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_detector_finds_aes_ecb_weak_mode() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'\\x00' * 32), modes.ECB())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode == "ECB"


def test_detector_finds_3des_via_cipher_wrapper() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.TripleDES(b'\\x00' * 24), modes.CBC(b'\\x00' * 8))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "3DES"
    assert findings[0].mode == "CBC"


def test_cipher_with_keyword_args() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithm=algorithms.AES(b'k'*32), mode=modes.GCM(b'i'*12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode == "GCM"


def test_cipher_without_resolvable_algorithm_skipped() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher\n"
        "Cipher(some_unknown_thing(), other_thing())\n"
    )
    findings = _scan(src)
    assert findings == []
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v -k cipher`
Expected: 5 new tests FAIL.

- [ ] **Step 2: Implement Cipher-wrapper handling**

In `src/pqcheck/detectors/python_detector.py`, modify `visit_Call` and add a helper. Replace the existing `visit_Call` body with:

```python
    def visit_Call(self, node: ast.Call) -> None:
        qualified = self._imports.resolve_attribute(node.func)
        if qualified is not None:
            hit = lookup_python_symbol(qualified)
            if hit is not None:
                if hit.canonical == "CIPHER-WRAPPER":
                    self._emit_cipher_wrapper(node)
                else:
                    self._emit(node, hit.canonical, hit.family, confidence=1.0)
        if qualified == "hashlib.new":
            self._emit_hashlib_new(node)
        self.generic_visit(node)

    def _emit_cipher_wrapper(self, node: ast.Call) -> None:
        algorithm_arg = self._cipher_arg(node, position=0, keyword="algorithm")
        mode_arg = self._cipher_arg(node, position=1, keyword="mode")
        algo_hit = self._resolve_call_target(algorithm_arg)
        if algo_hit is None or algo_hit.canonical == "CIPHER-WRAPPER":
            return
        mode_name = self._resolve_mode_target(mode_arg)
        self._emit(
            node,
            algo_hit.canonical,
            algo_hit.family,
            confidence=1.0,
            mode=mode_name,
        )

    @staticmethod
    def _cipher_arg(
        node: ast.Call, *, position: int, keyword: str
    ) -> ast.expr | None:
        if position < len(node.args):
            return node.args[position]
        for kw in node.keywords:
            if kw.arg == keyword:
                return kw.value
        return None

    def _resolve_call_target(self, expr: ast.expr | None):  # -> AlgorithmHit | None
        if not isinstance(expr, ast.Call):
            return None
        qualified = self._imports.resolve_attribute(expr.func)
        if qualified is None:
            return None
        return lookup_python_symbol(qualified)

    def _resolve_mode_target(self, expr: ast.expr | None) -> str | None:
        if not isinstance(expr, ast.Call):
            return None
        qualified = self._imports.resolve_attribute(expr.func)
        if qualified is None:
            return None
        from pqcheck.detectors.algorithms import lookup_cipher_mode

        return lookup_cipher_mode(qualified)
```

Add the type-checking import at the top of the file (right after the existing `from pqcheck.detectors.algorithms import lookup_python_symbol` line):

```python
from pqcheck.detectors.algorithms import AlgorithmHit, lookup_cipher_mode, lookup_python_symbol
```

And update the return type hint on `_resolve_call_target`:

```python
    def _resolve_call_target(self, expr: ast.expr | None) -> AlgorithmHit | None:
```

Remove the duplicate `from pqcheck.detectors.algorithms import lookup_cipher_mode` inside `_resolve_mode_target` (it was only there to keep Step 1 self-contained):

```python
    def _resolve_mode_target(self, expr: ast.expr | None) -> str | None:
        if not isinstance(expr, ast.Call):
            return None
        qualified = self._imports.resolve_attribute(expr.func)
        if qualified is None:
            return None
        return lookup_cipher_mode(qualified)
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/pqcheck/detectors/python_detector.py tests/unit/detectors/test_python_detector.py
git commit -m "feat(detectors): emit AES/3DES findings with mode from Cipher wrapper

Resolves nested algorithms.X() and modes.Y() calls inside the
cryptography.hazmat.primitives.ciphers.Cipher constructor."
```

---

## Task 6: Argument extraction — key_size, curve, padding

**Context:** Today the detector emits findings with `key_size=None`, `curve=None`, `padding=None`. Now we extract:
- `key_size` from `rsa.generate_private_key(key_size=2048, ...)` and `dh.generate_parameters(key_size=2048, ...)`
- `curve` from `ec.generate_private_key(curve=ec.SECP256R1())` (resolve the curve class name)
- `padding` from `cipher.encrypt(padding=padding.OAEP(...))` — deferred to a later task (no v0.1 fixtures depend on it)

Only `key_size` and `curve` for now. `padding` is YAGNI for v0.1.

**Files:**
- Modify: `src/pqcheck/detectors/python_detector.py`
- Modify: `tests/unit/detectors/test_python_detector.py`

- [ ] **Step 1: Add failing tests**

Append to `tests/unit/detectors/test_python_detector.py`:

```python
def test_rsa_extracts_key_size() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 2048


def test_rsa_without_key_size_kwarg_emits_none() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=size)\n"
    )
    findings = _scan(src)
    assert findings[0].key_size is None


def test_ec_extracts_curve_name() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(curve=ec.SECP256R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "SECP256R1"


def test_ec_with_positional_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP384R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "SECP384R1"
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v -k "key_size or curve"`
Expected: 4 tests FAIL.

- [ ] **Step 2: Extract `key_size` and `curve`**

In `src/pqcheck/detectors/python_detector.py`, modify `visit_Call` so that the resolved-symbol branch passes args to `_emit`. Replace the relevant else branch:

```python
                else:
                    self._emit(
                        node,
                        hit.canonical,
                        hit.family,
                        confidence=1.0,
                        key_size=self._extract_key_size(node),
                        curve=self._extract_curve(node) if hit.canonical == "ECDSA" else None,
                    )
```

Add two static helpers to the class:

```python
    @staticmethod
    def _extract_key_size(node: ast.Call) -> int | None:
        for kw in node.keywords:
            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                value = kw.value.value
                if isinstance(value, int):
                    return value
        return None

    def _extract_curve(self, node: ast.Call) -> str | None:
        # Positional first arg or keyword `curve=`. Expected: an instance
        # construction like `ec.SECP256R1()` whose callee's last segment
        # is the curve name.
        candidate: ast.expr | None = None
        if node.args:
            candidate = node.args[0]
        for kw in node.keywords:
            if kw.arg == "curve":
                candidate = kw.value
                break
        if not isinstance(candidate, ast.Call):
            return None
        if isinstance(candidate.func, ast.Attribute):
            return candidate.func.attr
        if isinstance(candidate.func, ast.Name):
            return candidate.func.id
        return None
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Commit**

```bash
git add src/pqcheck/detectors/python_detector.py tests/unit/detectors/test_python_detector.py
git commit -m "feat(detectors): extract RSA key_size and EC curve from Call kwargs

Literal-only extraction. Non-literal arguments (variables, expressions)
remain None — better to leave undefined than to guess."
```

---

## Task 7: Public `detect_python_file` + robustness

**Context:** Wrap the detector behind a file-level function the scanner orchestrator can call. Handle three failure modes without crashing the scan:
1. File too large (> 2 MiB) → return `[]`, do not parse.
2. `SyntaxError` while parsing → return `[]`.
3. Encoding errors → try UTF-8 then Latin-1 fallback; if both fail, return `[]`.

Limit chosen for v0.1: 2 MiB matches typical generated-code thresholds (Bazel codegen, protobuf .py). Tunable later.

**Files:**
- Modify: `src/pqcheck/detectors/python_detector.py`
- Modify: `tests/unit/detectors/test_python_detector.py`

- [ ] **Step 1: Add failing tests**

Append to `tests/unit/detectors/test_python_detector.py`:

```python
import pytest

from pqcheck.detectors.python_detector import detect_python_file


def test_detect_python_file_finds_md5(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    findings = detect_python_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
    assert findings[0].location.path == f


def test_detect_python_file_empty_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("", encoding="utf-8")
    assert detect_python_file(f) == []


def test_detect_python_file_syntax_error_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "broken.py"
    f.write_text("def (:\n", encoding="utf-8")
    assert detect_python_file(f) == []


def test_detect_python_file_too_large_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "huge.py"
    f.write_bytes(b"# pad\n" * (400 * 1024))  # ~2.4 MiB
    assert detect_python_file(f) == []


def test_detect_python_file_latin1_fallback(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    # Latin-1 byte 0xe9 ('é') is invalid UTF-8 start byte alone.
    f.write_bytes(b"# coment\xe9\nimport hashlib\nhashlib.md5(b'x')\n")
    findings = detect_python_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detect_python_file_undecodable_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    # Random bytes that decode to garbage in latin-1 but no valid Python.
    f.write_bytes(b"\xff\xfe\xfd not python at all \x00\x01\x02")
    # latin-1 will decode but ast.parse will SyntaxError → empty.
    assert detect_python_file(f) == []


def test_detect_python_file_missing_returns_empty(tmp_path: Path) -> None:
    assert detect_python_file(tmp_path / "nope.py") == []
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v -k detect_python_file`
Expected: 7 tests FAIL.

- [ ] **Step 2: Implement `detect_python_file`**

Append to `src/pqcheck/detectors/python_detector.py`:

```python
_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB cap — skip generated/oversized files.


def detect_python_file(path: Path) -> list[CryptoFinding]:
    """Detect Python crypto primitive usage in `path`.

    Returns an empty list (never raises) for: missing file, file > 2 MiB,
    encoding failure on both UTF-8 and Latin-1, or a SyntaxError during
    parsing. The scanner orchestrator surfaces these as `files_skipped`
    rather than aborting the whole scan.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return []
    if size > _MAX_FILE_BYTES:
        return []
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    source: str | None = None
    for encoding in ("utf-8", "latin-1"):
        try:
            source = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if source is None:
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []
    detector = PythonDetector(source_path=path, source=source)
    detector.visit(tree)
    return detector.findings
```

Run: `uv run pytest tests/unit/detectors/test_python_detector.py -v`
Expected: all tests PASS.

- [ ] **Step 3: Confirm strict mypy still clean**

Run: `uv run mypy src/pqcheck/detectors/`
Expected: `Success: no issues found`.

- [ ] **Step 4: Commit**

```bash
git add src/pqcheck/detectors/python_detector.py tests/unit/detectors/test_python_detector.py
git commit -m "feat(detectors): public detect_python_file with size/encoding/syntax guards

2 MiB cap, latin-1 fallback after utf-8, swallow SyntaxError. Never
raises — orchestrator reports skipped files separately."
```

---

## Task 8: Integration fixtures + verify 85% gate holds

**Context:** End-to-end verification against real-looking Python files. The project's `--cov-fail-under=85` stays put — we just confirm the new detector code lands well above it.

**Files:**
- Create: `tests/fixtures/python/known_bad.py`
- Create: `tests/fixtures/python/known_good.py`
- Create: `tests/fixtures/python/mixed_pycryptodome.py`
- Create: `tests/fixtures/python/edge_syntax_error.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_python_detector_integration.py`
- (no change to `pyproject.toml`)

- [ ] **Step 1: Create the fixture files**

Create `tests/fixtures/python/known_bad.py`:

```python
"""Fixture: every primitive here is BANNED by policy."""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def weak_hashes() -> None:
    hashlib.md5(b"x")
    hashlib.sha1(b"y")
    hashes.MD5()
    hashes.SHA1()


def shor_targets() -> None:
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec.generate_private_key(curve=ec.SECP256R1())
    dh.generate_parameters(generator=2, key_size=2048)


def broken_ciphers() -> None:
    Cipher(algorithms.TripleDES(b"k" * 24), modes.CBC(b"i" * 8))
    Cipher(algorithms.AES(b"k" * 32), modes.ECB())
```

Create `tests/fixtures/python/known_good.py`:

```python
"""Fixture: every primitive here is APPROVED by policy."""

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def strong_hashes() -> None:
    hashlib.sha256(b"x")
    hashlib.sha384(b"y")
    hashlib.sha3_256(b"z")
    hashlib.blake2b(b"q")


def aes_gcm_only() -> None:
    Cipher(algorithms.AES(b"k" * 32), modes.GCM(b"i" * 12))
```

Create `tests/fixtures/python/mixed_pycryptodome.py`:

```python
"""Fixture: pycryptodome surface, banned + acceptable mixed."""

from Crypto.Cipher import AES, DES
from Crypto.Hash import MD5, SHA256
from Crypto.PublicKey import RSA


def banned_block() -> None:
    DES.new(b"k" * 8, DES.MODE_ECB)
    MD5.new(b"x")
    RSA.generate(2048)


def acceptable_block() -> None:
    SHA256.new(b"x")
    AES.new(b"k" * 32, AES.MODE_GCM)
```

Create `tests/fixtures/python/edge_syntax_error.py`:

```python
# Intentionally invalid — used to verify detect_python_file returns [].
def (:
```

- [ ] **Step 2: Write the integration test**

Create `tests/integration/__init__.py` (empty file).

Create `tests/integration/test_python_detector_integration.py`:

```python
from pathlib import Path

import pytest

from pqcheck.detectors.python_detector import detect_python_file
from pqcheck.models import QuantumRisk


FIXTURES = Path(__file__).parent.parent / "fixtures" / "python"


@pytest.mark.integration
def test_known_bad_emits_only_vulnerable_or_broken() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    assert findings, "expected detections in known_bad.py"
    for f in findings:
        assert f.quantum_risk in {QuantumRisk.BROKEN, QuantumRisk.VULNERABLE}, (
            f"{f.algorithm} should be flagged"
        )


@pytest.mark.integration
def test_known_bad_includes_expected_algorithms() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    algorithms = {f.algorithm for f in findings}
    assert {"MD5", "SHA-1", "RSA", "ECDSA", "DH", "3DES", "AES"} <= algorithms


@pytest.mark.integration
def test_known_bad_rsa_key_size_extracted() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    rsa = [f for f in findings if f.algorithm == "RSA"]
    assert len(rsa) == 1
    assert rsa[0].key_size == 2048


@pytest.mark.integration
def test_known_bad_aes_ecb_mode_extracted() -> None:
    findings = detect_python_file(FIXTURES / "known_bad.py")
    aes = [f for f in findings if f.algorithm == "AES"]
    assert len(aes) == 1
    assert aes[0].mode == "ECB"


@pytest.mark.integration
def test_known_good_emits_no_broken_or_vulnerable() -> None:
    findings = detect_python_file(FIXTURES / "known_good.py")
    assert findings, "expected detections in known_good.py"
    for f in findings:
        assert f.quantum_risk is QuantumRisk.SAFE


@pytest.mark.integration
def test_mixed_pycryptodome_separates_banned_from_acceptable() -> None:
    findings = detect_python_file(FIXTURES / "mixed_pycryptodome.py")
    banned = {f.algorithm for f in findings if f.quantum_risk is not QuantumRisk.SAFE}
    safe = {f.algorithm for f in findings if f.quantum_risk is QuantumRisk.SAFE}
    assert {"DES", "MD5", "RSA"} <= banned
    assert {"SHA-256", "AES"} <= safe


@pytest.mark.integration
def test_edge_syntax_error_returns_empty() -> None:
    assert detect_python_file(FIXTURES / "edge_syntax_error.py") == []
```

Run: `uv run pytest tests/integration/test_python_detector_integration.py -v -m integration`
Expected: 7 tests PASS.

- [ ] **Step 3: Run the full suite with the existing 85% gate**

Run: `uv run pytest --cov=pqcheck --cov-report=term-missing`
Expected: ALL tests PASS, coverage ≥ 85% (in practice the detector + models + algorithms cover well above 95% individually), no `FAIL Required test coverage` line.

If `python_detector.py` shows uncovered branches in `--cov-report=term-missing`, add the missing-branch test before moving on. Common gaps to expect: error branches in `detect_python_file`, the `ast.Name` curve fallback, the unresolved-cipher-arg skip — all already covered by Tasks 5-7 tests, but verify with `--cov-report=term-missing`.

- [ ] **Step 4: Run lint + mypy gates**

Run: `uv run ruff check . && uv run mypy`
Expected: both succeed with no diagnostics.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/python/ tests/integration/__init__.py tests/integration/test_python_detector_integration.py
git commit -m "test(detectors): integration fixtures for python AST detector

Banned vs approved primitive sets, pycryptodome surface, and a
syntax-error edge case. All covered by detect_python_file end-to-end."
```

---

## Acceptance criteria for this plan

- [ ] `from pqcheck.detectors.python_detector import detect_python_file` works.
- [ ] `detect_python_file(path)` returns `list[CryptoFinding]`, never raises.
- [ ] All algorithms in `tests/fixtures/python/known_bad.py` produce findings with `quantum_risk in {BROKEN, VULNERABLE}`.
- [ ] All algorithms in `tests/fixtures/python/known_good.py` produce findings with `quantum_risk == SAFE`.
- [ ] `uv run pytest` passes with the existing `--cov-fail-under=85` on the whole project.
- [ ] `uv run mypy` passes strict-mode.
- [ ] `uv run ruff check .` clean.
- [ ] Zero new third-party dependencies (verify: `git diff pyproject.toml` shows no changes).

## Follow-on work (NOT in this plan)

- Walker that finds `.py` files (with `.gitignore` + `.pqcheckignore` awareness) — Task 3 of the master plan.
- Scanner orchestrator that calls `detect_python_file` per file + aggregates into `ScanResult` — Task 9.
- Computed `severity` + `base_severity` + `confidence_band` on `CryptoFinding` — added with the policy engine task.
- 10-repo precision corpus benchmark — Task 16. **At that point** `/autoresearch:plan` with `Metric: precision @ HIGH/CRITICAL`, `Direction: higher_is_better`, `Verify: python tests/corpus/run_bench.py | jq .precision` becomes the right tool to iterate on detector tuning.
