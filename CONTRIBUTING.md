# Contributing

Pre-1.0 the API and internals move fast; open an issue before large PRs.

## Setup

Python 3.12+ and [`uv`](https://github.com/astral-sh/uv). Go 1.25+ only
if you touch `tools/crypto-analyzer`.

```console
$ uv sync --all-extras
$ uv run pytest          # coverage gate: 85%
$ uv run ruff check .
$ uv run mypy            # strict
```

For the Go analyzer: `cd tools/crypto-analyzer && go generate ./... &&
go vet ./... && go test ./...`.

## Ground rules

- Branch from `develop` (`feat/...`, `fix/...`); PRs target `develop`.
- Conventional commits; the body explains *why*, not *what*.
- Every change lands with tests. Parsers and detectors follow the
  never-raise contract: hostile input degrades, it never crashes a scan.
- New detection goes through the catalog (`detectors/algorithms.py` /
  `data/crypto-catalog.json`) so policy rules apply uniformly across
  languages — and the canonical name needs a `_QUANTUM_MAP` entry (an
  invariant test will remind you).
- Policy changes: bundled policies must only encode semantics the engine
  evaluates (a test enforces this), and regulatory claims are framed as
  alignment, never obligation.
- Significant architecture changes: open an issue first and state the
  alternatives you rejected — decisions get recorded with their data.

## Precision corpus

`uv run python tests/corpus/run_bench.py` (network on first run). If
your change adds findings on the corpus, adjudicate them in
`tests/corpus/verdicts.yaml` per the protocol in `tests/corpus/README.md`.
