# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository
(Security → Report a vulnerability). Best-effort response within 72
hours. Please do not open public issues for security reports.

## Supported versions

Pre-1.0: only the latest release receives fixes.

## What pqcheck's own crypto looks like

pqcheck's own code uses SHA-256 only (binary integrity pins,
fingerprints). This is not a promise — it is a CI gate: `pqcheck
self-audit` runs against this repository on every push and fails the
build on any finding the bundled policy bans.

## Transitive PQC risk (v0.1, honest list)

Where pqcheck depends on infrastructure we do not control, classical
cryptography remains. Owner for all items: maintainer; review with each
release.

| # | Item | Crypto today | Mitigation / position |
|---|---|---|---|
| T1 | Sigstore Fulcio signing certs (release signatures) | ECDSA P-256 | Upstream limitation; signatures are short-lived and transparency-logged (Rekor). Native ML-DSA verification is planned post-v0.1 when Sigstore ships PQC. |
| T2 | Distribution channel (PyPI, GitHub) | Classical TLS | Inherited. Compensating control: Sigstore-signed wheels — verify the artifact, not the channel. |
| T3 | GitHub Actions OIDC (build identity) | RS256 | Upstream limitation; workflows and third-party actions are SHA-pinned, wheels reproducible (`-trimpath`, zeroed buildid). |
| T4 | `cryptography` library in the dependency tree (via the `sigstore` extra) | Classical primitives present | Verification-only usage; visible in our own self-CBOM as dependency metadata. |
| T5 | Go module authentication at build time (sumdb) | Ed25519 | Build-time only; scans run with `GOPROXY=off` and never touch the network. `go.sum` content hashes are SHA-256. |

## Scanning hostile repositories

pqcheck is designed to scan untrusted code: detectors never execute the
target, file reads are size-capped and refuse symlinks, the bundled Go
analyzer runs in a hardened environment (no network, no toolchain
auto-download, no cgo, memory and time limits) and is SHA-256-pinned to
the wheel. If you find a way for a scanned repository to escape that
envelope, that is exactly the report we most want.
