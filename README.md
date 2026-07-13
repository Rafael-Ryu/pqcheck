# pqcheck

[![CI](https://github.com/Rafael-Ryu/pqcheck/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/Rafael-Ryu/pqcheck/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/pqcheck)](https://pypi.org/project/pqcheck/)
[![Python](https://img.shields.io/pypi/pyversions/pqcheck)](https://pypi.org/project/pqcheck/)
[![License](https://img.shields.io/pypi/l/pqcheck)](LICENSE)
[![Sigstore](https://img.shields.io/badge/releases-signed%20with%20Sigstore-blue)](SECURITY.md)

Generate a Cryptography Bill of Materials (CBOM) for your codebase in
seconds, and gate CI on a crypto policy you can read.

`pqcheck` scans source code and dependency lockfiles for cryptographic
algorithm usage — RSA, ECDSA, AES modes, legacy hashes, post-quantum
primitives — and emits a CycloneDX 1.6 CBOM plus SARIF 2.1.0, evaluated
against a versionable YAML policy. It runs on a laptop and in CI with no
server, no account, and no network access during the scan.

Why now: NIST IR 8547 deprecates RSA and ECC by 2030 and disallows them
by 2035. Every migration framework (OMB M-23-02, the EU coordinated
roadmap, FS-ISAC guidance) makes inventory the first step. The existing
open tooling for that step needs a SonarQube server; the commercial
options start at enterprise pricing. This is the `pip install` version.

**Status: pre-release.** v0.1.0 lands on PyPI with Sigstore-signed
wheels. Until then: `uv sync --all-extras && uv run pqcheck --help`.
[Leia em português](README.pt-br.md).

## Quickstart

```console
$ pqcheck scan ./your-repo --policy cryptoct-default
✗ src/auth.py:42 — RSA [banned/critical, confidence high] — Shor — migrate to ML-KEM-768
⚠ src/hash.py:7  — BLAKE2B [default/medium, confidence high]
✓ src/aead.py:12 — AES [approved/info, confidence high]
dependencies: 47 parsed
policy cryptoct-default-1.0.0: 1 fail, 1 warn, 1 allow
```

Machine-readable outputs:

```console
$ pqcheck scan . --policy cryptoct-default --format cbom -o cbom.cdx.json
$ pqcheck scan . --format sarif -o pqcheck.sarif   # imports into GitHub Code Scanning
```

Gate CI (`exit 1` when the policy trips):

```console
$ pqcheck scan . --policy br-bcb-conservative --fail-on policy
$ pqcheck self-audit          # fixed policy, CBOM always written
```

`--fail-on high` gates on base severity instead; `--strict` treats WARN
decisions as failures. A finding's displayed severity is demoted by
detection confidence, but gating always reads the base severity — low
confidence never lets RSA through.

Verify a release yourself (needs the `sigstore` extra; the `.sigstore.json`
bundle ships next to each wheel on the GitHub release):

```console
$ pqcheck verify-release pqcheck-0.0.1-py3-none-any.whl
OK: pqcheck-0.0.1-py3-none-any.whl verified against pqcheck-0.0.1-py3-none-any.whl.sigstore.json
```

## What it detects

| Surface | Coverage |
|---|---|
| Python source | stdlib `hashlib`, `cryptography` (current + legacy + decrepit paths), `pycryptodome` — via AST, no execution |
| Go source | stdlib `crypto/*` and `golang.org/x/crypto` — union of a bundled `go/types` analyzer (semantic: key sizes, curves, modes) and a tree-sitter pass that also covers GOOS/cgo-gated files, which type resolution cannot see by construction |
| Lockfiles | `pyproject.toml`, `uv.lock`, `requirements.txt`, `pom.xml`, `go.mod`+`go.sum`, `package-lock.json` |

Java is next on the roadmap; it is not in v0.1.

## Policies

Six bundled policies, all plain YAML you can fork:

- `cryptoct-default` / `cryptoct-strict` / `cryptoct-advisory` — the
  general tiers (fail / fail-hard / report-only).
- `br-bcb-conservative` — for Brazilian financial institutions aligning
  their inventory with the cybersecurity controls of Res. CMN 4.893/2021.
- `br-drex-piloto` — the strictest profile, for teams that want new code
  quantum-safe by construction.
- `br-vendor-dd` — advisory profile for vendor due-diligence annexes.

To be clear about the regulatory framing: **no Brazilian regulation
currently mandates a cryptographic inventory or PQC migration.** The BR
profiles anticipate that direction; they do not claim an obligation that
does not exist.

`pqcheck policy show <name>` prints any of them resolved;
`pqcheck policy validate <file>` checks your own against the schema.

## Measured precision and recall

Every HIGH/CRITICAL finding across a 10-repo public corpus (pyjwt,
paramiko, sigstore-python, age, go-jose, smallstep/crypto, …) was
human-adjudicated by reading the flagged line: **255 findings, 0 false
positives**. Recall on the same repos, against a ground truth of 527
adjudicated call sites, is 1.00. The honest caveat: that corpus's miss
list drove the catalog expansion, so it is a tuning set and says
nothing about generalization. A held-out set of 6 unseen repos
(authlib, borgbackup, certbot, cosign, wireguard-go, certmagic)
measured recall 0.989 (273/276; the 3 misses are borgbackup's
Cython/OpenSSL binding, outside the import-resolution model) and
precision 0.99 (76/77). One round of fixes came from that miss list,
so the held-out set is no longer strictly untouched either — future
generalization claims need fresh repos. Protocols, pinned SHAs, and
verdicts are in `tests/corpus/`.

## Known limitations

- Findings carry no usage context yet: the policy cannot distinguish
  "RSA verifying a third-party webhook" from "RSA encrypting data at
  rest". Context-scoped rules are parsed but deliberately not shipped in
  the bundled policies until detectors emit context.
- Hybrid-scheme detection covers `filippo.io/hpke` (X25519MLKEM768);
  other hybrid constructions still read as their classical component.
- Only the repo root's `.gitignore`/`.pqcheckignore` are honored.
- Dependency findings are inventory (`introduces` metadata in the CBOM);
  they do not trip the policy gate in v0.1 — call sites do.

## Development

Requires Python 3.12+ and [`uv`](https://github.com/astral-sh/uv):
`uv sync --all-extras`, then `uv run pytest`, `uv run ruff check .`,
`uv run mypy`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [SECURITY.md](SECURITY.md) for the vulnerability
disclosure process and the honest list of classical crypto this project
itself transitively depends on.
