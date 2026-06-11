"""Precision benchmark over the pinned public-repo corpus.

Usage:
    uv run python tests/corpus/run_bench.py [--repo NAME] [--check]

Clones each corpus repo shallow at its pinned SHA, scans it with the
cryptoct-default policy, and reports every HIGH/CRITICAL decision with a
stable fingerprint. Precision is computed only over findings a human has
adjudicated in verdicts.yaml — pending findings are listed, never
guessed. --check exits 1 when adjudicated precision < 0.85 or anything
is still pending (the ship-gate mode).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import subprocess
from pathlib import Path

import yaml

from pqcheck.models import ScanResult, Severity
from pqcheck.policy.loader import load_default_policy
from pqcheck.scanner import scan

CORPUS_DIR = Path(__file__).parent
CACHE = CORPUS_DIR / ".cache"
TARGET_PRECISION = 0.85
_GATED = (Severity.HIGH, Severity.CRITICAL)


def _clone_pinned(name: str, url: str, sha: str) -> Path:
    dest = CACHE / f"{name}-{sha[:12]}"
    if (dest / ".git").is_dir():
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    for cmd in (
        ["git", "init", "-q"],
        ["git", "remote", "add", "origin", url],
        ["git", "fetch", "-q", "--depth", "1", "origin", sha],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    ):
        subprocess.run(cmd, cwd=dest, check=True, timeout=300)
    return dest


def _fingerprint(repo: str, result: ScanResult, index: int) -> str:
    decision = result.policy_decisions[index]
    finding = decision.finding
    rel = finding.location.path
    with contextlib.suppress(ValueError):
        rel = rel.relative_to(result.target)
    # detector_id is deliberately NOT part of the fingerprint: a verdict
    # adjudicates a call site, and must survive the same site being
    # re-attributed to a different detector (e.g. tree-sitter -> go/types).
    material = "|".join(
        [
            repo,
            finding.algorithm,
            finding.family.value,
            rel.as_posix(),
            str(finding.location.line),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="bench a single corpus repo by name")
    parser.add_argument("--check", action="store_true", help="ship-gate mode")
    args = parser.parse_args(argv)

    corpus = yaml.safe_load((CORPUS_DIR / "corpus.yaml").read_text(encoding="utf-8"))
    verdicts_path = CORPUS_DIR / "verdicts.yaml"
    verdicts: dict[str, dict[str, str]] = {}
    if verdicts_path.is_file():
        loaded = yaml.safe_load(verdicts_path.read_text(encoding="utf-8")) or {}
        # An all-digit hex fingerprint parses as a YAML integer; normalize
        # keys to strings so the lookup never silently misses.
        verdicts = {str(k): v for k, v in loaded.items()}

    policy = load_default_policy("cryptoct-default")
    tp = fp = 0
    pending: list[str] = []
    per_repo: dict[str, dict[str, int]] = {}

    for entry in corpus["repos"]:
        name = entry["name"]
        if args.repo and name != args.repo:
            continue
        root = _clone_pinned(name, entry["url"], entry["sha"])
        result = scan(root, policy)
        counts = {"gated": 0, "tp": 0, "fp": 0, "pending": 0}
        for i, decision in enumerate(result.policy_decisions):
            if decision.base_severity not in _GATED:
                continue
            counts["gated"] += 1
            fingerprint = _fingerprint(name, result, i)
            verdict = verdicts.get(fingerprint, {}).get("verdict")
            if verdict == "tp":
                tp, counts["tp"] = tp + 1, counts["tp"] + 1
            elif verdict == "fp":
                fp, counts["fp"] = fp + 1, counts["fp"] + 1
            else:
                counts["pending"] += 1
                loc = decision.finding.location
                rel = loc.path
                with contextlib.suppress(ValueError):
                    rel = rel.relative_to(result.target)
                pending.append(
                    f"{fingerprint}  {name}:{rel.as_posix()}:{loc.line}"
                    f"  {decision.finding.algorithm}"
                    f" [{decision.base_severity.value}]"
                    f"  {decision.finding.evidence[:60]}"
                )
        per_repo[name] = counts
        print(f"{name}: {counts['gated']} gated, {counts['tp']} tp, "
              f"{counts['fp']} fp, {counts['pending']} pending")

    adjudicated = tp + fp
    precision = tp / adjudicated if adjudicated else 0.0
    (CORPUS_DIR / "last_bench.json").write_text(
        json.dumps(
            {"tp": tp, "fp": fp, "pending": len(pending),
             "precision": round(precision, 4), "per_repo": per_repo},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if pending:
        print(f"\n{len(pending)} findings pending adjudication (add to verdicts.yaml):")
        for line in pending:
            print(f"  {line}")
    print(f"\nadjudicated precision: {precision:.2%} over {adjudicated} findings")

    if args.check and (pending or precision < TARGET_PRECISION):
        print("::error::ship gate: pending adjudications or precision below 0.85")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
