# pqcheck

Post-quantum cryptography risk scanner for source code and dependency graphs.

**Status:** pre-alpha, private development. Working name; may change before public release.

## Development setup

Requires Python 3.12+ and [`uv`](https://github.com/astral-sh/uv).

```bash
uv sync --all-extras
uv run pytest
uv run ruff check .
uv run mypy
```

Try the CLI skeleton:

```bash
uv run pqcheck version
```

## Layout

```
src/pqcheck/        # package source
tests/              # pytest suite (unit + integration + corpus)
tools/              # auxiliary build tools (Go modfile-parser, etc.)
scripts/            # build / release helpers
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
