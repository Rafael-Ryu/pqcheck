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
