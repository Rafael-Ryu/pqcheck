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

**Status: v0.1.0** is on PyPI with Sigstore-signed wheels:
`pip install pqcheck`. From a clone: `uv sync --all-extras && uv run
pqcheck --help`. [Leia em português](README.pt-br.md).

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
$ pqcheck verify-release pqcheck-0.1.0-py3-none-any.whl
OK: pqcheck-0.1.0-py3-none-any.whl verified against pqcheck-0.1.0-py3-none-any.whl.sigstore.json
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
human-adjudicated by reading the flagged line: **261 findings, 0 false
positives**. Recall on the same repos, against a ground truth of 584
adjudicated call sites, is 1.00. The honest caveat: that corpus's miss
list drove the catalog expansion, so it is a tuning set and says
nothing about generalization. A held-out set of 6 unseen repos
(authlib, borgbackup, certbot, cosign, wireguard-go, certmagic)
measures recall 0.9834 (296/301). Precision on that set was a one-time
manual adjudication (76/77 when measured on 2026-07-12); unlike the
tuning-corpus precision it is not re-checked on every change, so read it
as indicative rather than a live gate. The 5
remaining misses are all structural — authlib's dataflow-dependent
digest calls and borgbackup's Cython/OpenSSL binding, the same gap
classes documented under [Known limitations](#known-limitations)
below. Three rounds of fixes came from the held-out miss list, so it
is no longer strictly untouched either — future generalization claims
need fresh repos. Protocols, pinned SHAs, and verdicts are in
`tests/corpus/`.

## Known limitations

pqcheck is a static, single-repo scanner, and these gaps follow from
that design:

- No dataflow analysis: an algorithm reached through a variable,
  parameter, or lookup table is either missed or reported as a generic
  low-confidence finding — e.g. `.digest()` called on a hash object
  passed in as a parameter, or a cipher picked from a dict at runtime.
  authlib is the clearest example in the held-out corpus.
- No C-extension or FFI visibility: crypto implemented behind an
  in-repo Cython or C binding, like borgbackup's OpenSSL binding, is
  invisible to source-level detection — only the Python or Go call
  surface is scanned.
- Catalog-scoped detection: pqcheck flags what's in its curated Python
  and Go catalogs. A library or symbol outside the catalog produces no
  findings, and no findings isn't evidence of no crypto.
- Static analysis only: there's no runtime or dynamic-dispatch
  resolution. `hashlib.new(name_var)` with a name computed at runtime,
  or `getattr`-based dispatch, resolve to nothing.
- Usage-context blindness: a symbol match carries no intent. "RSA
  verifying a third-party webhook" reads the same as "RSA encrypting
  data at rest," and an `ECDH()` call used only for key-format
  conversion gets flagged the same as a real key agreement (one known
  false positive in the held-out set). Context-scoped policy rules are
  parsed but not shipped in the bundled policies until detectors emit
  context.
- Hybrid-scheme detection covers the catalogued hybrid KEM identifiers
  (`filippo.io/hpke` X25519MLKEM768, `crypto/tls` X25519MLKEM768 on Go
  1.24+, and cloudflare/circl's X-Wing and Kyber768-draft); other hybrid
  constructions read as their classical component.
- Only the repo root's `.gitignore`/`.pqcheckignore` are honored.
- Dependency findings are inventory (`introduces` metadata in the CBOM);
  they do not trip the policy gate in v0.1 — call sites do.

See `tests/corpus/` for the adjudication protocol behind these numbers.

## Development

Requires Python 3.12+ and [`uv`](https://github.com/astral-sh/uv):
`uv sync --all-extras`, then `uv run pytest`, `uv run ruff check .`,
`uv run mypy`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [SECURITY.md](SECURITY.md) for the vulnerability
disclosure process and the honest list of classical crypto this project
itself transitively depends on.
