"""Real-world recall benchmark over the pinned public-repo corpus (corpus v2).

Usage:
    uv run python tests/corpus/run_recall_v2.py [--candidates] [--repo NAME]

Ground truth is built by an oracle deliberately independent of the detectors:
a line-level regex sweep for tokens derived from the same crypto catalogs the
detectors read (crypto-catalog.json + the Python symbol table), but matched
textually — no AST, no imports, no type resolution. The oracle over-matches
on purpose (comments, strings, look-alike names, files the detectors can't
parse); human adjudication in ground_truth.yaml separates real call sites
(`site`) from noise (`not_site`). Recall is then detected/`site` matched by
(repo, path, line).

Modes:
    --candidates  sweep the clones and list oracle hits not yet adjudicated
                  in ground_truth.yaml (also written to last_candidates.json)
    default       scan each repo with no policy and report recall over the
                  adjudicated `site` entries; results in last_recall_v2.json.
                  A report, not a gate: always exits 0 (like run_recall.py),
                  except that pending candidates make the measurement refuse
                  to print a number — recall over a partial ground truth
                  would silently overstate.

Honest limitation: recall here is relative to the oracle. A crypto use that
matches no catalog token (a vendored primitive with renamed symbols, a
hand-rolled cipher) is invisible to the ground truth too. The oracle being
strictly broader than the detectors (it sees commented-out code, build-gated
files, unparseable sources) is what gives real misses a chance to surface.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml
from run_bench import _clone_pinned

from pqcheck.detectors.algorithms import _PYTHON_SYMBOLS, load_go_catalog
from pqcheck.scanner import scan

CORPUS_DIR = Path(__file__).parent

# Bare-name patterns for these would fire on every `x.new(...)`, `x.sign(...)`
# or `r.Read(...)` in sight; they are only matched with their qualifying
# prefix (e.g. `AES.new(`, `rand.Read(`). Cost accepted: a from-imported bare
# `sign(...)` escapes the oracle — the qualified spelling still covers it.
_GENERIC_TAILS = {
    "new", "New", "generate", "Read", "verify", "sign", "Sum", "Int", "Int64", "Int31",
    "str",  # nacl.pwhash.str — bare form is the Python builtin
    # Go catalog depth (W1): tails that collide with near-universal
    # identifiers (file/db handles, generic map methods, the cipher.Stream
    # interface method every stream cipher implements) — the qualified
    # spelling (`pbkdf2.Key(`, `secretbox.Seal(`, `salsa20.XORKeyStream(`)
    # still covers real usage without the bare form drowning the oracle.
    "Key", "Open", "Seal", "GenerateKeyPair", "XORKeyStream",
}


def _oracle_pattern() -> re.Pattern[str]:
    """One alternation over every catalog symbol, two shapes per symbol.

    `pkg.Func(` catches the qualified spelling; a bare `Func(` catches
    from-imports and Go dot-imports. The bare shape is skipped for tails too
    generic to mean crypto on their own.
    """
    patterns: set[str] = set()
    for qualified in set(_PYTHON_SYMBOLS) | set(load_go_catalog()):
        # Go call sites qualify by package name, which for versioned import
        # paths ("math/rand/v2.Int") is the segment before the /vN suffix.
        path_parts = qualified.split("/")
        if len(path_parts) >= 2 and re.fullmatch(r"v\d+\.\w+", path_parts[-1]):
            path_parts[-2:] = [path_parts[-2] + "." + path_parts[-1].split(".", 1)[1]]
        parts = path_parts[-1].split(".")
        tail = parts[-1]
        if len(parts) >= 2:
            patterns.add(rf"\b{re.escape(parts[-2])}\.{re.escape(tail)}\s*\(")
        if tail not in _GENERIC_TAILS and len(tail) >= 3:
            patterns.add(rf"\b{re.escape(tail)}\s*\(")
    return re.compile("|".join(sorted(patterns)))


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None  # pragma: no cover - latin-1 is total over bytes


def _fingerprint(repo: str, rel: str, line: int) -> str:
    return hashlib.sha256(f"{repo}|{rel}|{line}".encode()).hexdigest()[:16]


def _sweep(root: Path, rx: re.Pattern[str]) -> list[tuple[str, int, str]]:
    """(relative path, line number, matched token) per oracle hit."""
    hits: list[tuple[str, int, str]] = []
    for path in sorted(root.rglob("*")):
        if path.suffix not in {".py", ".go"} or ".git" in path.parts:
            continue
        text = _read_text(path)
        if text is None:
            continue
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(text.splitlines(), 1):
            match = rx.search(line)
            if match:
                hits.append((rel, lineno, match.group(0).rstrip("(").strip()))
    return hits


def _load_ground_truth(path: Path) -> dict[str, dict[str, object]]:
    if not path.is_file():
        return {}
    loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    # Same hazard as verdicts.yaml: an all-digit hex fingerprint parses as int.
    return {str(k): v for k, v in loaded.items()}


def _clone_root(entry: dict[str, object]) -> Path:
    """Clone root, narrowed to entry['path'] when a corpus entry restricts scope."""
    root = _clone_pinned(str(entry["name"]), str(entry["url"]), str(entry["sha"]))
    subdir = entry.get("path")
    return root / str(subdir) if subdir else root


def _output_paths(corpus_path: Path) -> tuple[Path, Path]:
    """(candidates file, recall file) — byte-compatible names for the default corpus."""
    stem = corpus_path.stem
    if stem == "corpus":
        return CORPUS_DIR / "last_candidates.json", CORPUS_DIR / "last_recall_v2.json"
    return CORPUS_DIR / f"last_candidates_{stem}.json", CORPUS_DIR / f"last_recall_{stem}.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidates", action="store_true", help="list unadjudicated oracle hits")
    parser.add_argument("--repo", help="restrict to a single corpus repo by name")
    parser.add_argument(
        "--corpus", type=Path, default=CORPUS_DIR / "corpus.yaml",
        help="corpus manifest (repo list) to sweep/scan",
    )
    parser.add_argument(
        "--ground-truth", type=Path, default=CORPUS_DIR / "ground_truth.yaml",
        help="adjudication file matching --corpus",
    )
    args = parser.parse_args(argv)

    corpus = yaml.safe_load(args.corpus.read_text(encoding="utf-8"))
    repos = [e for e in corpus["repos"] if not args.repo or e["name"] == args.repo]
    ground_truth = _load_ground_truth(args.ground_truth)
    rx = _oracle_pattern()
    candidates_path, recall_path = _output_paths(args.corpus)

    if args.candidates:
        pending: list[dict[str, object]] = []
        for entry in repos:
            root = _clone_root(entry)
            for rel, lineno, token in _sweep(root, rx):
                fp = _fingerprint(entry["name"], rel, lineno)
                if fp not in ground_truth:
                    pending.append(
                        {"fingerprint": fp, "repo": entry["name"], "path": rel,
                         "line": lineno, "token": token}
                    )
        candidates_path.write_text(
            json.dumps(pending, indent=2) + "\n", encoding="utf-8"
        )
        for c in pending:
            print(f"{c['fingerprint']}  {c['repo']}:{c['path']}:{c['line']}  {c['token']}")
        print(f"\n{len(pending)} candidates pending adjudication (add to ground_truth.yaml)")
        return 0

    sites = {
        (str(v["repo"]), str(v["path"]), int(v["line"])): fp
        for fp, v in ground_truth.items()
        if v.get("verdict") == "site"
    }
    # Refuse to compute recall while the oracle still has unadjudicated hits.
    stale = 0
    for entry in repos:
        root = _clone_root(entry)
        for rel, lineno, _ in _sweep(root, rx):
            if _fingerprint(entry["name"], rel, lineno) not in ground_truth:
                stale += 1
    if stale:
        print(f"{stale} oracle hits unadjudicated — run --candidates and adjudicate first")
        return 0

    misses: list[str] = []
    hit_count = 0
    per_repo: dict[str, dict[str, int]] = {}
    for entry in repos:
        name = entry["name"]
        root = _clone_root(entry)
        detected = {
            (name, f.location.path.relative_to(root).as_posix(), f.location.line)
            for f in scan(root).findings
        }
        repo_sites = [k for k in sites if k[0] == name]
        repo_hits = sum(1 for k in repo_sites if k in detected)
        hit_count += repo_hits
        per_repo[name] = {"sites": len(repo_sites), "detected": repo_hits}
        misses.extend(
            f"{k[0]}:{k[1]}:{k[2]}" for k in sorted(repo_sites) if k not in detected
        )
        print(f"{name}: {len(repo_sites)} sites, {repo_hits} detected")

    total = sum(1 for k in sites if not args.repo or k[0] == args.repo)
    recall = hit_count / total if total else 0.0
    print(f"\nsites: {total}  detected: {hit_count}  recall: {recall:.2%}")
    if misses:
        print(f"\n{len(misses)} ground-truth sites not detected:")
        for line in misses:
            print(f"  {line}")

    recall_path.write_text(
        json.dumps(
            {"sites": total, "detected": hit_count, "recall": round(recall, 4),
             "per_repo": per_repo, "misses": misses},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
