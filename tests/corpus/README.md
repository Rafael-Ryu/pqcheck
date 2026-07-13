# Precision corpus

Measures **precision** (tp / (tp + fp)) of `pqcheck scan` on the
HIGH/CRITICAL severity buckets over 10 pinned public repos
(`corpus.yaml`). Target: ≥ 0.85 (v0.1 ship-blocker, plan 03 Task 16).

## Protocol

1. `uv run python tests/corpus/run_bench.py` — clones each repo shallow at
   its pinned SHA into `tests/corpus/.cache/`, scans with
   `cryptoct-default`, and prints every HIGH/CRITICAL finding with a stable
   fingerprint.
2. **Adjudication is human**: for each fingerprint, read the flagged line
   in the repo and record a verdict in `verdicts.yaml`:
   `<fingerprint>: {verdict: tp|fp, note: "..."}`. A finding is `tp` when
   the flagged call really constructs/uses the reported primitive in
   shipped code; test fixtures inside the target repo count as `tp` too
   (the scanner cannot know intent), but note it.
3. Re-run the bench: precision is computed **only over adjudicated
   findings**; pending ones are listed, never guessed. Results land in
   `last_bench.json`.

Recall (fn) is out of scope for the 0.85 gate — it is measured separately
by the corpus v2 below.

Network required for the first run (clones). Not part of the default
pytest run.

## Recall (planted fixtures)

Precision alone can't catch a detector that silently stops firing. This
harness measures **recall** (detected / planted) over `tests/corpus/planted/`
— small `.py` and `.go` files with known crypto call sites, one per line,
annotated in `planted/expected.yaml`.

1. `uv run python tests/corpus/run_recall.py` scans `tests/corpus/planted/`
   with no policy (raw findings, not severity-gated) and diffs
   `(path, line, algorithm)` against the manifest.
2. Misses print as `path:line  algorithm` and land in `last_recall.json`
   alongside the recall ratio. Always exits 0 — this is a report, not a
   ship gate (unlike `run_bench.py --check`).
3. Go fixtures have no `go.mod` on purpose: the tree-sitter detector is the
   permanent floor (ADR 0005) and resolves `pkg.Func(...)` calls without a
   compiled module, so the harness never needs a Go toolchain.

**Honest limitation**: this is recall on synthetic, single-call-per-line
fixtures the detectors were built against — it says nothing about recall on
real, idiomatic, multi-line, refactored code in the wild. That gap is what
the corpus v2 below measures.

## Recall (corpus v2 — real-world)

Measures recall on the same 10 pinned repos, against a ground truth built by
an oracle that is deliberately independent of the detectors: a line-level
regex sweep (`run_recall_v2.py`) for tokens derived from the crypto catalogs,
matched textually with no AST/import/type resolution. The oracle over-matches
by design (comments, strings, look-alike names, files the detectors cannot
parse); adjudication in `ground_truth.yaml` separates real call sites
(`site`) from noise (`not_site`), same protocol as `verdicts.yaml`.

1. `uv run python tests/corpus/run_recall_v2.py --candidates` — sweep the
   pinned clones, list oracle hits not yet adjudicated (also written to
   `last_candidates.json`).
2. Adjudicate each candidate into `ground_truth.yaml`: `site` when the line
   really invokes a crypto-library primitive (test files count, aliased
   imports count); `not_site` for comments/strings, definitions, in-repo
   wrappers and same-name non-crypto APIs. Pending candidates block the
   measurement — recall over a partial ground truth would overstate.
3. `uv run python tests/corpus/run_recall_v2.py` — scans each repo with no
   policy and reports recall = detected/`site`, matched by
   (repo, path, line). Report, not gate: always exits 0; results in
   `last_recall_v2.json` with per-repo counts and the full miss list.

First measurement (2026-07-12, 792 candidates adjudicated): recall **0.70**
(370/527 sites). Python is near-perfect (89/98; the 9 paramiko misses are
indirect algorithm variables — `Cipher(cipher(key), ...)` — the documented
no-dataflow limitation, plus `bcrypt.kdf` and multi-line artifacts, where the
finding lands on the `Cipher(` line and the ground truth also marks the
`algorithms.AES(` argument line). Go misses are dominated by catalog scope,
not detector bugs: `crypto/rand.Read` (41), `crypto/elliptic.P256/P384/P521`
curve constructors (77), `golang.org/x/crypto/curve25519.X25519` (13) and
receiver-method forms like `pub.ECDH()` (11) are not catalog symbols today.
Those are recall signal for catalog expansion, kept as misses on purpose —
measuring recall only against the shipped catalog would inflate the number
by construction.

**Honest limitations**: recall is relative to the oracle — crypto that
matches no catalog token (vendored primitives with renamed symbols,
hand-rolled ciphers) is invisible to the ground truth too. Qualified-only
tokens (`AES.new`, `rand.Read`…) miss aliased imports (`mathrand.Int()` in
age is a known, accepted example) and bare from-imports of generic names.
The oracle being strictly broader than the detectors everywhere else
(commented-out code, build-gated files, unparseable sources) is what lets
real misses surface.

## Recall (held-out)

Corpus-v2 recall reached 1.00 after catalog/detector work driven by its own
miss list — so it can no longer say whether the detectors generalize. The
held-out set (`holdout.yaml`: authlib, borgbackup, certbot restricted to
`acme/`, cosign, wireguard-go, certmagic — different authors, domains and
idioms from `corpus.yaml`) is measured with the same oracle and protocol,
but its misses are **reported, never patched**. Fixing a gap found here
would turn the held-out set into another tuning set; expansion backlog
still comes from corpus v2 only.

Same tooling, parametrized:

    uv run python tests/corpus/run_recall_v2.py --candidates \
        --corpus tests/corpus/holdout.yaml \
        --ground-truth tests/corpus/holdout_ground_truth.yaml   # sweep
    uv run python tests/corpus/run_recall_v2.py \
        --corpus tests/corpus/holdout.yaml \
        --ground-truth tests/corpus/holdout_ground_truth.yaml   # measure

Results land in `last_recall_holdout.json` / `last_candidates_holdout.json`;
the default invocation (no flags) is byte-identical to corpus v2. A corpus
entry may carry `path:` to restrict the sweep and scan to a subdirectory
(certbot's full tree is 20+ plugin packages of non-crypto glue; `acme/`
keeps candidate volume comparable to the other repos).

First measurement (2026-07-12, 383 candidates adjudicated, 276 sites):
recall **0.95** (261/276). The 15 misses: go-containerregistry `v1.SHA256`
(8, catalog scope — third-party digest helper), `blake2s.Sum256` and
`math/rand.Uint32` (catalog scope — near-miss variants of shipped symbols),
`math/rand/v2` qualified calls (1, mechanism — versioned import path not
resolved by either Go engine even though the catalog has the symbol),
`rng.Uint32()` on a `*rand.Rand` (1, mechanism — local-variable receiver),
and borgbackup's in-repo Cython OpenSSL binding (3, outside the
import-resolution model by construction). Held-out precision over all 77
HIGH/CRITICAL findings on the same repos: 0.99 (76 tp / 1 fp — `pub.ECDH()`
called for key-format conversion, not key agreement).

**Note (2026-07-12, second pass):** the 12 in-scope misses above were fixed
directly from this held-out miss list — the `/vN` versioned-import bug (both
the tree-sitter package-identifier binding and, once a `*rand.Rand` method
catalog closed a related gap, the go/types receiver-method resolution) and
the `v1.SHA256` / `blake2s.Sum256` / `blake2b.Sum*` / `math/rand.Uint32`
catalog gaps. That makes this set no longer strictly untouched — the same
caveat corpus v2 carries now applies here too. Recall after the fix:
**0.989** (273/276); only borgbackup's Cython/OpenSSL binding (3, outside
the import-resolution model by construction) remains. Re-running with
`--candidates` surfaced no new oracle candidates, so no ground-truth
adjudication changed. Future generalization claims need a fresh, disjoint
repo set. The go/types engine only participates in this measurement when
the bundled binary is built (`cd tools/crypto-analyzer && go build -o
../../src/pqcheck/bin/<goos>-<goarch>/crypto-analyzer ./cmd/crypto-analyzer`)
and pointed at via `PQCHECK_CRYPTO_ANALYZER` — without it these scripts
silently fall back to tree-sitter only, undercounting recall by the
`*rand.Rand` method sites.
