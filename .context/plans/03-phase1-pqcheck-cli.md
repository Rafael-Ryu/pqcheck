# Phase 1 — `pqcheck` CLI Implementation Plan

> Documento canônico pós-cortes. Versão enxuta: arquitetura + acceptance criteria. Execução granular vai em GitHub issues, não nesta spec.

---

## Goals

1. CLI Python OSS shippable em PyPI + cibuildwheel 3-platform (Linux x86_64 + macOS x86_64 + macOS arm64). aarch64 Linux + Windows AMD64 = v0.3+.
2. Scan Java/Python/Go (+ lockfiles modernos) → CycloneDX 1.6 CBOM + SARIF 2.1.0
3. Policy engine schema-validado com `pqcheck-policy-v1.yaml` shipped no wheel
4. Severity = base × confidence_band
5. Releases assinadas via Sigstore keyless (ML-DSA-65 sidecar via broker pattern = Phase 3+)
6. Self-audit dogfood

---

## Architecture

```
Customer dev machine:
  pqcheck scan ./repo --policy pqcheck-policy-v1.yaml --strict --format cbom -o cbom.json
    ↓
  walker (gitignore + .pqcheckignore aware)
    ↓
  parsers (tree-sitter Java, ast Python, tree-sitter Go)
    ↓
  detectors (regex + AST + dep tree)
    ↓
  scanner orchestrator
    ↓
  policy engine (load YAML, validate JSON Schema, apply rules per finding)
    ↓
  CBOM emit (CycloneDX 1.6 + schema validation) | SARIF 2.1.0 | terminal | JSON
    ↓
  exit code (policy-driven)
```

**Tech stack:**
- Python 3.12+, Typer 0.15, py-tree-sitter 0.23, tree-sitter-{java,go}, ast stdlib (Python)
- `cyclonedx-python-lib` via `uv.lock`
- pydantic 2, Rich 13, pytest 8 + hypothesis
- ruff + mypy strict
- uv (build/lock)
- **Signing:** Sigstore keyless (Fulcio cert via GitHub Actions OIDC). ML-DSA-65 sidecar via broker pattern adicionado em Phase 3.

---

## File structure

```
packages/pqcheck/
├── pyproject.toml
├── README.md
├── LICENSE                          # Apache 2.0
├── SECURITY.md                      # GPG + Transitive PQC Risk (5 items)
├── CHANGELOG.md
├── .python-version
├── cibuildwheel.toml
├── uv.lock
├── pqcheck-policy-v1.yaml           # shipped no wheel
├── pqcheck-policy.schema.json
├── src/pqcheck/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                       # Typer: scan, version, self-audit, policy show/validate, verify-release
│   ├── config.py                    # Pydantic Settings + .pqcheckignore loader
│   ├── models.py                    # CryptoFinding, ConfidenceBand, Severity, base × confidence
│   ├── discover/
│   │   └── walker.py                # gitignore + .pqcheckignore aware
│   ├── parsers/
│   │   ├── base.py
│   │   ├── tree_sitter_loader.py
│   │   ├── java_parser.py
│   │   ├── python_parser.py         # ast stdlib
│   │   └── go_parser.py
│   ├── detectors/
│   │   ├── registry.py
│   │   ├── algorithms.py
│   │   ├── java_detector.py         # JCE: KeyPairGenerator, Cipher, MessageDigest, Signature, Mac, KeyAgreement; coalescer init→getInstance
│   │   ├── python_detector.py       # cryptography, pycryptodome, hashlib
│   │   └── go_detector.py           # crypto/rsa, crypto/ecdsa, crypto/aes, crypto/sha*, crypto/mlkem (Go 1.24+)
│   ├── deps/
│   │   ├── pom_xml.py               # parse pom.xml direto (Maven effective-pom = Phase 3)
│   │   ├── pip_reqs.py
│   │   ├── poetry_lock.py
│   │   ├── pipfile_lock.py
│   │   ├── pdm_lock.py
│   │   ├── pyproject_toml.py        # PEP 621 dependencies + PEP 735 dependency-groups (v0.1)
│   │   ├── uv_lock.py               # uv.lock parser (v0.1; ecosystem 2025-26)
│   │   ├── go_mod.py                # via src/pqcheck/bin/<goos>-<goarch>/modfile-parser subprocess (importlib.resources path + SHA-256 check)
│   │   └── go_sum.py
│   ├── policy/
│   │   ├── schema.py                # pydantic models
│   │   ├── loader.py                # YAML safe_load + JSON Schema validate
│   │   └── engine.py                # apply rules to ScanResult → PolicyDecision
│   ├── cbom/
│   │   ├── emit.py                  # CycloneDX 1.6 with policy_id
│   │   ├── component.py
│   │   └── validator.py             # CycloneDX 1.6 JSON Schema validation
│   ├── reports/
│   │   ├── terminal.py              # Rich
│   │   ├── json_report.py
│   │   └── sarif.py                 # 2.1.0 + partialFingerprints + semanticVersion + policy_id
│   ├── signing/
│   │   ├── sigstore.py              # Sigstore keyless verify
│   │   └── verify.py                # consume-side verify
│   ├── schemas/                     # bundled JSON Schemas
│   │   ├── bom-1.6.schema.json
│   │   └── pqcheck-policy.schema.json
│   └── grammars/                    # bundled tree-sitter .so
├── tools/                           # separate Go modules
│   └── modfile-parser/
│       ├── go.mod
│       ├── cmd/modfile-parser/main.go
│       └── (no vendor/ for v0.1 — go.mod + go.sum suficiente)
├── scripts/
│   ├── build_grammars.sh
│   └── release.sh                   # Sigstore keyless
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── unit/
│   ├── integration/
│   └── corpus/                      # 10 repos pinned para v0.1 (expand to 50 conforme adoção)
│       ├── corpus.yaml
│       └── run_bench.py
└── .github/                         # workflows live in repo root
```

---

## Implementation tasks (resumo — detalhe em GitHub issues)

### Task 1 — Bootstrap (Python 3.12 + uv + lockfile)

**`pyproject.toml` essencial:**
```toml
[project]
name = "pqcheck"
version = "0.0.1"
requires-python = ">=3.12"
license = { text = "Apache-2.0" }
dependencies = [
    "typer==0.15.*",
    "rich==13.9.*",
    "pydantic==2.9.*",
    "pydantic-settings==2.6.*",
    "tree-sitter==0.23.*",
    "tree-sitter-java==0.23.*",
    "tree-sitter-go==0.23.*",
    "cyclonedx-python-lib==8.5.*",
    "jsonschema==4.23.*",
    "packageurl-python==0.16.*",
    "lxml==5.3.*",
    "PyYAML==6.0.*",
    "pathspec==0.12.*",
]

[project.optional-dependencies]
sigstore = ["sigstore==3.5.*"]
# Note: NO pqc-preview / oqs-python extra in v0.1. The v0.1 PQC surface is
# `pqcheck verify-release` which uses Sigstore keyless (currently ECDSA Fulcio).
# Non-FIPS / upstream-explicitly-non-production PQC libraries are NOT shipped
# in any v0.1.x release path. Reintroduce only via CIRCL-Go bridge when broker-
# pattern verification ships in v0.3+. See ADR commitment to never ship liboqs
# in a production release path.
dev = [
    "pytest==8.3.*", "pytest-cov==6.0.*", "pytest-xdist==3.6.*",
    "hypothesis==6.115.*", "syrupy==4.7.*", "ruff==0.7.*", "mypy==1.13.*",
    "types-lxml", "types-PyYAML",
]

[project.scripts]
pqcheck = "pqcheck.cli:app"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/pqcheck"]
include = ["src/pqcheck/schemas/*", "src/pqcheck/grammars/*", "src/pqcheck/bin/*/*"]

[tool.ruff]
target-version = "py312"
line-length = 100
[tool.ruff.lint]
select = ["E","F","W","I","UP","B","SIM","RUF","S","PL","PTH"]
ignore = ["S101","PLR0913"]

[tool.mypy]
python_version = "3.12"
strict = true

[tool.pytest.ini_options]
addopts = "-ra --strict-markers --cov=pqcheck --cov-fail-under=85"
```

**`cibuildwheel.toml`:**
```toml
[tool.cibuildwheel]
build = "cp312-* cp313-*"
skip = "*-musllinux_*"
archs.linux = ["x86_64"]                  # aarch64 = v0.3+
archs.macos = ["x86_64", "arm64"]
# Windows AMD64 = v0.3+

before-build = """
cd ../../tools/modfile-parser && \
CGO_ENABLED=0 go build -trimpath -o ../../packages/pqcheck/src/pqcheck/bin/$GOOS-$GOARCH/modfile-parser ./cmd/modfile-parser
"""

# CI assertion (added to cli-release.yml):
#   assert unzip -l dist/*.whl | grep -E "bin/(linux|darwin)-(x86_64|arm64)/modfile-parser$"
#   returns expected paths, with fresh-venv smoke tests across all three wheel targets.
```

### modfile-parser security envelope

Subprocess invocation limits (enforced in `src/pqcheck/go_mod.py`):
- timeout: 30 seconds (hard kill)
- stdout cap: 16 MiB (truncate + raise)
- argv encoding: strict UTF-8; non-UTF-8 paths → reject with `unknown_deps` result, not crash
- non-zero exit → record as `unknown_deps`, continue scan (do not abort)

Runtime SHA-256 verification:
- Wheel build embeds the binary hash as a Python constant `_MODFILE_PARSER_SHA256` in
  `src/pqcheck/_constants.py` (generated at build time by hatch hook).
- Each invocation verifies the bundled binary hash before exec; mismatch → refuse.

Build constraints (`cmd/main.go`):
- Use `golang.org/x/mod/modfile.Parse` ONLY. Never `go mod` or `go list`
  (these would touch GOPROXY at scan time).
- Reject `replace` directives whose target starts with `/` or contains `..`.
- Refuse non-UTF-8 module paths.

Adversarial fixtures under `tests/fixtures/adversarial-gomod/`:
1. `01-million-requires.mod` — 10⁶ require entries (resource bound check)
2. `02-path-traversal.mod` — `replace example.com/x => /etc/passwd`
3. `03-non-utf8.mod` — non-UTF-8 module path bytes
4. `04-embedded-escapes.mod` — `// indirect` comments with ANSI escape sequences
5. `05-deep-nesting.mod` — pathologically nested require blocks

Integration test asserts each fixture produces a controlled error or `unknown_deps`
result — never a crash, hang, or unbounded output.

### Task 2 — Domain models com severity × confidence

```python
# src/pqcheck/models.py
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


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConfidenceBand(str, Enum):
    HIGH = "high"      # >= 0.8
    MEDIUM = "medium"  # 0.5 - 0.8
    LOW = "low"        # < 0.5


def _band(c: float) -> ConfidenceBand:
    if c >= 0.8: return ConfidenceBand.HIGH
    if c >= 0.5: return ConfidenceBand.MEDIUM
    return ConfidenceBand.LOW


_QUANTUM_MAP = {
    "RSA": QuantumRisk.VULNERABLE, "DSA": QuantumRisk.VULNERABLE,
    "ECDSA": QuantumRisk.VULNERABLE, "ECDH": QuantumRisk.VULNERABLE,
    "DH": QuantumRisk.VULNERABLE, "ED25519": QuantumRisk.VULNERABLE,
    "ED448": QuantumRisk.VULNERABLE, "X25519": QuantumRisk.VULNERABLE,
    "X448": QuantumRisk.VULNERABLE,
    "ELGAMAL": QuantumRisk.VULNERABLE,
    "GOST-R-34.10-2001": QuantumRisk.VULNERABLE,
    "SM2": QuantumRisk.VULNERABLE,
    "BLS12-381": QuantumRisk.VULNERABLE,
    "AES": QuantumRisk.SAFE, "CHACHA20": QuantumRisk.SAFE,
    "SHA-256": QuantumRisk.SAFE, "SHA-384": QuantumRisk.SAFE,
    "SHA-512": QuantumRisk.SAFE,
    "ML-KEM": QuantumRisk.SAFE, "ML-DSA": QuantumRisk.SAFE,
    "SLH-DSA": QuantumRisk.SAFE,
    "MD5": QuantumRisk.BROKEN, "SHA-1": QuantumRisk.BROKEN,
    "DES": QuantumRisk.BROKEN, "3DES": QuantumRisk.BROKEN,
    "RC4": QuantumRisk.BROKEN,
}

_WEAK_MODES = {"ECB", "CBC", "CFB", "OFB"}
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


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
    evidence: str  # Phase 3 aggregate ingest redacts to (hash_prefix, ast_node_kind, line_range) — no raw evidence leaves the customer environment.
    detector_id: str = "unknown"
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    @computed_field
    @property
    def quantum_risk(self) -> QuantumRisk:
        return _QUANTUM_MAP.get(self.algorithm.upper(), QuantumRisk.UNKNOWN)

    @computed_field
    @property
    def confidence_band(self) -> ConfidenceBand:
        return _band(self.confidence)

    @computed_field
    @property
    def base_severity(self) -> Severity:
        risk = self.quantum_risk
        if risk == QuantumRisk.BROKEN: return Severity.CRITICAL
        if risk == QuantumRisk.VULNERABLE:
            if self.key_size and self.key_size < 2048: return Severity.CRITICAL
            return Severity.HIGH
        if risk == QuantumRisk.SAFE:
            if self.algorithm.upper() == "AES" and self.key_size and self.key_size < 256:
                return Severity.MEDIUM
            if self.mode and self.mode.upper() in _WEAK_MODES:
                return Severity.MEDIUM
            return Severity.LOW
        return Severity.INFO

    @computed_field
    @property
    def severity(self) -> Severity:
        base = self.base_severity
        band = self.confidence_band
        idx = _SEVERITY_ORDER.index(base)
        if band == ConfidenceBand.LOW: idx = max(0, idx - 2)
        elif band == ConfidenceBand.MEDIUM: idx = max(0, idx - 1)
        return _SEVERITY_ORDER[idx]

    # IMPORTANT: policy engine reads `base_severity` AND `confidence_band` as separate fields.
    # `severity` is a derived UI-facing field. CLI `--fail-on high` gates on `base_severity`,
    # NOT on the demoted `severity`. `--fail-on policy` delegates to YAML rules (which may
    # branch on confidence_band per 02:467-470). Default is `--fail-on policy`.


class CryptoDependency(BaseModel):
    model_config = ConfigDict(frozen=True)
    purl: str
    name: str
    version: str | None = None
    ecosystem: str
    declared_in: Path
    introduces_algorithms: tuple[str, ...] = ()


class ScanResult(BaseModel):
    target: Path
    findings: list[CryptoFinding] = Field(default_factory=list)
    dependencies: list[CryptoDependency] = Field(default_factory=list)
    duration_ms: int = 0
    files_scanned: int = 0
    scanner_version: str
    policy_id: str | None = None
    policy_decisions: list = Field(default_factory=list)
```

### Task 3-7 — Walker, parsers, detectors

Standard implementations:
- Walker via `pathspec` (gitignore + .pqcheckignore)
- Java parser via tree-sitter query `method_invocation`
- Java detector com coalescer `getInstance("RSA")` + `initialize(2048)` → single finding (confidence 0.7-0.95 baseado em proximity + scope)
- Python detector via ast stdlib: `cryptography.hazmat.primitives.asymmetric.{rsa,ec,dh,dsa,ed25519,x25519}`, `hashlib.{md5,sha1,sha256,...}`, `Cipher(algorithms.AES(...), modes.GCM(...))` (confidence 0.85-1.0)
- Go detector via tree-sitter: `crypto/rsa.GenerateKey`, `crypto/ecdsa.GenerateKey`, `crypto/aes.NewCipher`, `cipher.NewGCM`, `crypto/mlkem` Go 1.24+ (confidence 0.85-1.0)

### Task 8 — Lockfile dep parsers

- `pom_xml.py`: parse XML direto (lossy mas adequado para v0.1)
- Python lockfiles: poetry.lock, Pipfile.lock, pdm.lock, requirements.txt — parser específico extraindo `(name, version, sha256)` quando disponível
- `go_mod.py` via subprocess do bundled `modfile-parser` (importlib.resources + SHA-256 verification via build-time hashing)

Maven effective-pom subprocess + nsjail sub-sandbox = Phase 3.

### Task 9 — Scanner orchestrator

Combines detectors + dep parsers; exception swallowing per file; policy decision integration.

```python
# src/pqcheck/scanner.py
from pathlib import Path
from pqcheck import __version__
from pqcheck.models import ScanResult
from pqcheck.policy.schema import CryptoPolicy

def scan(root: Path, policy: CryptoPolicy | None = None) -> ScanResult:
    result = ScanResult(target=root, scanner_version=__version__)
    # ... walk + detect + dep parse ...
    if policy:
        from pqcheck.policy.engine import evaluate
        result.policy_decisions = evaluate(result, policy)
        result.policy_id = f"{policy.metadata.name}-{policy.metadata.version}"
    return result
```

### Task 10 — CBOM emit (CycloneDX 1.6) + schema validation

Bundled `bom-1.6.schema.json` em `src/pqcheck/schemas/`. CBOM components incluem `properties.policy_id` quando policy aplicada.

```python
# src/pqcheck/cbom/validator.py
import json
from importlib.resources import files
from jsonschema import validate, ValidationError

def validate_cyclonedx_16(doc_json: str) -> list[str]:
    schema = json.loads(files("pqcheck.schemas").joinpath("bom-1.6.schema.json").read_text())
    try:
        validate(instance=json.loads(doc_json), schema=schema)
        return []
    except ValidationError as e:
        return [str(e)]
```

### Task 11 — SARIF 2.1.0

Com `partialFingerprints` estáveis (SHA-256 truncado de algo|family|path|line|detector_id), `semanticVersion`, `properties.policy_id`. Sanitização de evidence strings em `message.text` via control-character filter (NOT bleach, which HTML-escaped `<>&` and broke downstream SARIF consumers):
`message.text = "".join(c for c in raw if unicodedata.category(c) != 'Cc' or c in ('\n','\t'))`

### Task 12 — Typer CLI

```python
# src/pqcheck/cli.py
@app.command()
def scan(
    path: Path = typer.Argument(...),
    policy: Path | None = typer.Option(None, "--policy", "-p"),
    output: Path | None = typer.Option(None, "--output", "-o"),
    fmt: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f"),
    fail_on: str = typer.Option("policy", "--fail-on"),
    strict: bool = typer.Option(False, "--strict"),
) -> None:
    """
    --strict: gate semantics —
        (1) upgrades every warn-on rule to fail-on;
        (2) treats QuantumRisk.UNKNOWN as VULNERABLE;
        (3) refuses YAML failing JSON Schema;
        (4) refuses policies missing severity-rules section.
    --fail-on policy (default): delegates to YAML severity-rules (which may branch on
        confidence_band per 02:467-470).
    --fail-on high|critical|...: gates on `base_severity`, NOT on the demoted `severity`.
    """
    ...

@app.command("policy")
def policy_cmd(): ...

@app.command("policy show")
def policy_show(name: str = typer.Argument("cryptoct-default-1.0.0")): ...

@app.command("policy validate")
def policy_validate(path: Path = typer.Argument(...)): ...

@app.command("self-audit")
def self_audit() -> None: ...

@app.command("verify-release")
def verify_release(
    artifact: Path = typer.Argument(...),
    bundle: Path = typer.Option(..., "--bundle", help="Sigstore bundle file"),
) -> None:
    """Verify a release artifact with Sigstore keyless."""
    ...
```

### Task 13 — Release signing via Sigstore keyless

```yaml
# .github/workflows/cli-release.yml
name: CLI Release
on:
  push:
    tags: ["pqcheck-v*"]
permissions:
  id-token: write
  contents: write
  attestations: write
jobs:
  build-and-release:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@<pinned-sha>
      - name: Setup Go (for modfile-parser)
        uses: actions/setup-go@<pinned-sha>
        with: { go-version: "1.24.5" }
      - name: Build modfile-parser
        run: |
          cd tools/modfile-parser && CGO_ENABLED=0 go build -trimpath -o ../../packages/pqcheck/src/pqcheck/bin/$(go env GOOS)-$(go env GOARCH)/modfile-parser ./cmd/modfile-parser
      - uses: astral-sh/setup-uv@<pinned-sha>
      - name: Build wheels (3-platform matrix)
        working-directory: packages/pqcheck
        env:
          CIBW_BUILD: "cp312-* cp313-*"
        run: pip install cibuildwheel==2.21.* && cibuildwheel --output-dir dist
      - name: Sigstore sign
        uses: sigstore/gh-action-sigstore-python@<pinned-sha>
        with: { inputs: packages/pqcheck/dist/* }
      - uses: pypa/gh-action-pypi-publish@<pinned-sha>
        with: { packages-dir: ./packages/pqcheck/dist/, attestations: true }
      - uses: softprops/action-gh-release@<pinned-sha>
        with: { files: "packages/pqcheck/dist/*" }
```

ML-DSA-65 sidecar via broker pattern = adicionado em Phase 3 (ver `02-quantum-safe-crypto-policy.md §6.2`).

### Task 14 — Policy engine

Loader + JSON Schema validate + engine que aplica rules em ScanResult → PolicyDecision. Detalhe em `src/pqcheck/policy/`.

### Task 15 — CycloneDX schema validation em CI

```yaml
# .github/workflows/cli-ci.yml — step
- name: Validate CBOM output schema
  run: |
    pqcheck scan tests/fixtures/java --policy pqcheck-policy-v1.yaml --format cbom -o /tmp/cbom.json
    python -m pqcheck.cbom.validator /tmp/cbom.json
```

### Task 16 — Precision corpus benchmark (10-repo for v0.1)

```python
# tests/corpus/run_bench.py
"""Benchmark pqcheck against 10 public repos with known expected findings."""
import json
from pathlib import Path
import yaml

def main():
    # NOTE: corpus.yaml is populated pre-launch with 10 repos targeting precision >= 0.85
    # per acceptance criterion at 03:680. v0.1 ship-blocker — must not be empty at HN launch.
    corpus = yaml.safe_load(Path("tests/corpus/corpus.yaml").read_text())
    tp, fp, fn = 0, 0, 0
    # ... benchmark ...
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    results = {"tp": tp, "fp": fp, "fn": fn, "precision": precision}
    Path("tests/corpus/last_bench.json").write_text(json.dumps(results, indent=2))
    if precision < 0.85:
        print(f"::warning::Precision {precision:.2f} below threshold; investigate")

if __name__ == "__main__":
    main()
```

Auto-relax workflow + CHANGELOG-lint = Phase 3 quando corpus expandir para 50+ repos.

### Task 17 — README + SECURITY.md + LICENSE + demo

**README.md:**

```markdown
# pqcheck — Post-Quantum CBOM Scanner

[![PyPI](https://img.shields.io/pypi/v/pqcheck)](https://pypi.org/project/pqcheck/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Generate a Cryptography Bill of Materials (CBOM) for your codebase in seconds. Detect every RSA, ECDSA, AES, SHA usage and map your migration path to post-quantum cryptography. Built for Brazilian fintech AppSec teams preparing for NIST FIPS 203/204/205 + ANPD Art. 46 + Drex migrations.

## Quickstart

\`\`\`bash
pip install pqcheck
pqcheck scan ./my-repo --policy pqcheck-policy-v1.yaml
pqcheck scan ./my-repo --format cbom -o cbom.json
pqcheck scan ./my-repo --format sarif -o pqcheck.sarif
\`\`\`

## Verifying releases (v0.1.x developer preview)

\`\`\`bash
# Sigstore keyless verification (Phase 1-2) — canonical path
pqcheck verify-release --bundle pqcheck-0.1.0.sigstore pqcheck-0.1.0-py3-none-any.whl

# Internal verification pins:
#   - issuer: https://token.actions.githubusercontent.com
#   - identity regex: ^https://github.com/cryptoct/pqcheck/.github/workflows/cli-release\.yml@refs/tags/pqcheck-v
#   - workflow SHA + tag-ref required
# These pins are baked into the pqcheck binary as constants — no --opt-out flag.
# Tag-protection rule on `pqcheck-v*` requires admin signoff; `git tag -s` mandatory.
\`\`\`

ML-DSA-65 sidecar signing (post-quantum verification) será adicionado em v0.3+ via broker pattern (ver `docs/plans/02-quantum-safe-crypto-policy.md §6.2`).

## Quantum-safe where we control the protocol

`pqcheck` is quantum-safe in code we control:
- All TLS uses hybrid X25519MLKEM768 (downgrade disabled in OpenSSL 3.5+ config)
- Internal MACs use HMAC-SHA-384
- No RSA, no ECDSA, no SHA-1, no MD5 in our code

We are honest about transitive dependencies — see [SECURITY.md](./SECURITY.md) Transitive PQC Risk section (5 top-impact items).

Run `pqcheck self-audit` to verify our claims locally.

## Pricing

| Tier | BR (Pix em Phase 3) | Intl (Stripe) |
|---|---|---|
| CLI | Free forever | Free forever |
| GitHub App | R$ 250/dev/mo | $50/dev/mo |

## Status

v0.0.x / v0.1.x — developer preview (Sigstore keyless signed). For SaaS dashboard with managed multi-repo CBOM, PR comments, compliance reports, see [cryptoct.com](https://cryptoct.com).

## License

Apache 2.0 for the CLI.
```

**SECURITY.md:**

```markdown
# Security Policy

## Reporting

- Email: security@cryptoct.com (PGP key: `0xABCD...`)
- Signal: contact via cryptoct.com/security
- Response: 24h best effort (founders)

## Hall of Fame

Public list of acknowledged researchers at https://cryptoct.com/security/hall-of-fame

## Bug Bounty

Currently informal (Phase 1-2). Intigriti program launching in Phase 3 (Q3 2026).

## Transitive PQC Risk (5 top-impact)

| # | Item | Cripto atual | Mitigation |
|---|---|---|---|
| T1 | GitHub App JWT | RS256 (RSA-2048) | TLS PQC outer + ML-DSA-65 sig em payload (Phase 3) |
| T2 | Sigstore Fulcio cert | ECDSA P-256 | Phase 3: ML-DSA-65 sidecar via broker pattern |
| T3 | AWS KMS HSM | RSA/ECC | BYOK customer KMS para audit log na Phase 4 (zero-knowledge) |
| T4 | Stripe TLS (US-hosted) | Classical TLS | Watch upstream; aguardando Stripe PQC roadmap |
| T5 | Browser TLS CA pública | ECC | Hybrid X25519MLKEM768 key exchange compensa |

Detalhe completo em [docs/plans/02-quantum-safe-crypto-policy.md §8](./docs/plans/02-quantum-safe-crypto-policy.md).
```

### Task 18 — GitHub Actions CI

Workflows pinned a SHA, ephemeral runners GitHub-hosted (self-hosted = Phase 3).

### Task 19 — HN launch (Sem 4)

```markdown
# Show HN: pqcheck — Cryptography Bill of Materials for Java/Python/Go (BR-vertical, ANPD Art. 46 aligned)

I built pqcheck — an open-source CLI that scans your source + dependency manifests to produce a CycloneDX 1.6 CBOM. Identifies every cryptographic primitive in use — RSA, ECDSA, AES, SHA, MD5 — with key sizes, modes, curves, and quantum-risk classification per finding.

Why? NIST published CSWP 39 in Dec 2025 telling regulated orgs to produce CBOMs ahead of FIPS 203/204/205 migrations. ANPD Art. 46 (LGPD) + BCB 4893 + Drex/CBDC create concrete BR regulatory pressure. Snyk/Endor do SBOM, not CBOM. IBM CBOMkit exists but is Java-only batch. pqcheck does CBOM + policy enforcement, open source, dev-first.

It's the CLI of CryptoCT, the platform I'm building for Brazilian fintech AppSec. CLI is free forever, Apache 2.0.

pqcheck is honest about its PQC status:
- v0.1.x developer preview — Sigstore keyless signed
- All TLS uses hybrid X25519MLKEM768
- Internal MACs use HMAC-SHA-384
- ML-DSA-65 sidecar release signing in v0.3+

`pip install pqcheck && pqcheck scan ./your-repo --policy pqcheck-policy-v1.yaml`

Repo: github.com/cryptoct/pqcheck

Happy to answer questions on CBOM design, NIST PQC, or why I think AppSec needs CBOM yesterday — and why the BR vertical pitch leads with ANPD Art. 46 over BCB 4893.
```

---

## Acceptance criteria (v0.1.x developer preview)

- [ ] `pip install pqcheck` succeeds on Linux x86_64, macOS x86_64, macOS arm64
- [ ] `pqcheck scan ./repo --policy pqcheck-policy-v1.yaml` generates valid CycloneDX 1.6 CBOM
- [ ] CycloneDX 1.6 JSON Schema validation passes in CI
- [ ] Java, Python, Go detection working with confidence scores 0.5-1.0
- [ ] Lockfile parsers: pom.xml direto; poetry.lock, Pipfile.lock, pdm.lock, requirements.txt, pyproject.toml (PEP 621 + PEP 735), uv.lock; go.mod via bundled modfile-parser + go.sum
- [ ] `severity = base × confidence_band` correctly demoting LOW/MEDIUM bands
- [ ] Engine reads `base_severity` + `confidence_band` separately; `severity` field is UI-only. Unit test asserts (HIGH-base, LOW-band) → engine sees HIGH on `base_severity`. Integration test asserts `--fail-on high` triggers on RSA at 0.4 confidence.
- [ ] `--policy`, `--strict`, `--fail-on policy` flags working
- [ ] SARIF 2.1.0 with `partialFingerprints` stable + `policy_id`
- [ ] `pqcheck verify-release` validates Sigstore bundle
- [ ] `pqcheck self-audit` produces self-cbom.json
- [ ] cibuildwheel produces 3-platform wheels
- [ ] All Python deps pinned via `uv.lock`
- [ ] All Go deps pinned via `go.mod` + `go.sum`
- [ ] Sigstore keyless release signing working
- [ ] DPIA + ROPA published in `docs/compliance/`
- [ ] CODEOWNERS protects `pqcheck-policy*.yaml`
- [ ] Defensive packages registered on PyPI, Docker Hub, GitHub org, npm `@cryptoct`
- [ ] Sub-processor disclosure published in `docs/compliance/sub-processor-disclosure.md`
- [ ] Precision corpus benchmark (10 repos) ≥ 0.85 on HIGH/CRITICAL buckets. **Fallback:** se 1st eval < 0.85, ship v0.1 com `--strict` opt-in apenas (default `--strict=false`) + roadmap visible em CHANGELOG para target 0.85 em v0.1.5 via customer feedback iteration
- [ ] Phase 3 ingest acceptance test (`test_ingest_rejects_raw_evidence`): server-side endpoint REJECTS CBOM/SARIF cujo `evidence` field não match `(hash_prefix, ast_node_kind, line_range)` pattern. Garantia "source NUNCA persistido" depende deste teste (cross-ref 01:110, 03:338).
- [ ] `pqcheck self-audit` rodando em CI release pipeline; gate hard contra qualquer transitive dep introduzindo crypto banido (supply-chain mitigation)
- [ ] K-service rotation register publishable + signed em `keys.cryptoct.com/k-service-rotation.json` (Phase 3 hard blocker — cross-ref 02:185-186)
- [ ] CODEOWNERS configured para `migrations/`, `pqcheck-policy*.yaml`, `tools/circl-bridge/`, `tools/pqcheck-courier/` com 4-eyes obrigatório
- [ ] 4 ADRs criados em `docs/adr/`: 0001-mofn-quorum-rationale.md, 0002-tls-root-quorum-rationale.md, 0003-shamir-ram-opsec.md, 0004-ceremony-trust-root.md
- [ ] 85%+ test coverage in pytest
- [ ] No "quantum-safe end-to-end" language in any marketing copy

---

## Timeline (revisado — pós-audit)

Timeline original "Sem 1-3" foi otimista. Realista com 2 founders FT:

- **Sem 1-2:** Tasks 1-7 (Bootstrap, models, walker, parsers Java/Python/Go, detectors)
- **Sem 3-4:** Tasks 8-12 (lockfile parsers incluindo pyproject.toml + uv.lock; scanner orchestrator; CBOM CycloneDX 1.6; SARIF; Typer CLI)
- **Sem 5:** Tasks 13-15 (Sigstore keyless signing GHA; policy engine + JSON Schema validate; CI CycloneDX validation)
- **Sem 6:** Tasks 16-19 (corpus 10-repo benchmark; README/SECURITY.md; CI hardening; HN launch draft)

v0.0.x unsigned dev releases shipped a partir da Sem 2.

**Re-baseline rationale:** original 3-semana timeline subestimou tree-sitter ABI setup, cibuildwheel cross-platform debugging, lockfile parser surface (8 formatos), e CycloneDX 1.6 schema integration. 4-6 semanas é realista para output com `--cov-fail-under=85`.
