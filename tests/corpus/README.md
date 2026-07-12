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

Recall (fn) is out of scope for the 0.85 gate — it would need an
independent ground-truth sweep per repo. Tracked for the corpus v2.

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
real, idiomatic, multi-line, refactored code in the wild. A labeled
real-world corpus (corpus v2) is future work, same caveat as the precision
corpus's fn gap above.
