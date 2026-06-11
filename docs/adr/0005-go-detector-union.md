# ADR 0005 — Go detection is the union of go/types and tree-sitter, not a hand-off

Date: 2026-06-11
Status: accepted

## Context

The Go detector was pivoted from tree-sitter (syntactic) to a bundled
`go/types` analyzer on 2026-05-25, with tree-sitter kept as a
"transitional baseline" to be retired once the analyzer proved parity on
a precision corpus. The corpus now exists (tests/corpus, 10 pinned
repos, every HIGH/CRITICAL finding human-adjudicated) and the
measurement is in:

| configuration                  | Go findings (unique call sites) | fp |
|--------------------------------|--------------------------------|----|
| tree-sitter only               | 197                            | 0  |
| analyzer (as shipped)          | 34                             | 0  |
| analyzer + `Tests: true`       | 156                            | 0  |
| union, deduped per call site   | 197                            | 0  |

Three structural facts drive the numbers:

1. `packages.Config.Tests` defaulted to false — `*_test.go` was never
   analyzed, and 177 of the 197 corpus findings live in test files.
   Test code ships crypto too; an inventory that skips it under-reports.
2. Even with tests on, `go/types` is blind by construction to files
   excluded by build constraints under the scan environment: GOOS-gated
   code (smallstep's `mackms` is darwin-only) and cgo-gated code
   (`pkcs11`) vanish when scanning with GOOS=linux / CGO_ENABLED=0.
   That code still ships to its platforms.
3. On this corpus the analyzer contributed zero call sites tree-sitter
   missed. Its remaining value is metadata fidelity (key size, curve,
   mode via const-folding and use-def linking — the difference between
   "AES" and "AES-128", which policy rules ban differently) and
   robustness to aliased imports, which this corpus does not exercise.

The retirement gate ("analyzer ≥ tree-sitter tp, ≤ fp") therefore
fails: hand-off semantics — trusting a clean analyzer run and skipping
the syntactic pass — would silently drop up to 83% of findings on a
repo like smallstep/crypto.

## Decision

- `detect_go_module` returns the **union** of both detectors, deduped
  per call site `(path, line, algorithm)`, the semantic finding winning
  duplicates because it carries richer parameters. The dedup covers the
  semantic list itself: `Tests: true` type-checks production files once
  per package variant, duplicating findings (25 duplicates over the
  corpus).
- The analyzer sets `Tests: true`.
- tree-sitter is **not** transitional and is not retired. It is the
  permanent detection floor: it runs always, covers build-tag- and
  cgo-gated files, and is the sole detector when the bundled binary is
  absent or unverified.

## Consequences

- The bundled analyzer stays in the wheel for metadata fidelity, not
  coverage. If its build/packaging cost ever needs justifying again,
  the bar is: corpus findings whose parameter sets only it resolves.
- Per-module scan cost is both passes; tree-sitter is cheap relative to
  the analyzer's `go list`, so the overhead is marginal.
- The corpus fingerprint excludes `detector_id` so adjudications track
  call sites, not attribution.
- Revisit only with new corpus evidence (e.g. an aliasing-heavy repo
  where the analyzer surfaces unique sites).
