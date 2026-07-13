"""Recall benchmark over the planted fixture tree (tests/corpus/planted/).

Usage:
    uv run python tests/corpus/run_recall.py

Scans tests/corpus/planted/ (synthetic call sites with known crypto primitive
uses) and compares every emitted CryptoFinding against the manifest in
planted/expected.yaml. Unlike run_bench.py this is a report, not a gate: it
always exits 0. Results land in last_recall.json.

This measures recall on synthetic, single-call-per-line fixtures — it is not
a substitute for real-world recall, which would need an independently
labeled corpus of shipped code (tracked as future work, corpus v2). See
README.md "Recall (planted fixtures)".
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from pqcheck.scanner import scan

CORPUS_DIR = Path(__file__).parent
PLANTED_DIR = CORPUS_DIR / "planted"


def _load_expected() -> list[tuple[str, int, str]]:
    manifest = yaml.safe_load((PLANTED_DIR / "expected.yaml").read_text(encoding="utf-8"))
    return [(str(e["path"]), int(e["line"]), str(e["algorithm"])) for e in manifest["planted"]]


def main() -> int:
    expected = _load_expected()
    result = scan(PLANTED_DIR)

    detected_keys: set[tuple[str, int, str]] = set()
    for finding in result.findings:
        rel = finding.location.path.relative_to(PLANTED_DIR).as_posix()
        detected_keys.add((rel, finding.location.line, finding.algorithm))

    misses: list[str] = []
    hit_count = 0
    for key in expected:
        if key in detected_keys:
            hit_count += 1
        else:
            misses.append(f"{key[0]}:{key[1]}  {key[2]}")

    planted_total = len(expected)
    recall = hit_count / planted_total if planted_total else 0.0

    print(f"planted: {planted_total}  detected: {hit_count}  recall: {recall:.2%}")
    if misses:
        print(f"\n{len(misses)} planted call sites not detected:")
        for line in misses:
            print(f"  {line}")

    if result.errors:
        print(f"\n{len(result.errors)} scan errors (informational, not gated):")
        for line in result.errors:
            print(f"  {line}")

    (CORPUS_DIR / "last_recall.json").write_text(
        json.dumps(
            {
                "planted": planted_total,
                "detected": hit_count,
                "recall": round(recall, 4),
                "misses": misses,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
