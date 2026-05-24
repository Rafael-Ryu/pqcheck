## Summary

`src/pqcheck/deps/pyproject_toml.py` currently fails on PEP 735 dependency groups and silently misses `[build-system].requires` when no dependency groups are present.

## Evidence

`uv run pytest` on `develop` reports:

```text
7 failed, 175 passed
```

The failures all point at `src/pqcheck/deps/pyproject_toml.py:101`:

```text
NameError: name 'data' is not defined
```

`uv run ruff check .` also reports:

```text
F821 Undefined name `data`
--> src/pqcheck/deps/pyproject_toml.py:101:20
```

`uv run mypy` reports:

```text
src/pqcheck/deps/pyproject_toml.py:101: error: Name "data" is not defined  [name-defined]
```

Targeted reproductions:

```python
from pathlib import Path
from pqcheck.deps.pyproject_toml import parse

p = Path("/tmp/pqcheck-dependency-groups.toml")
p.write_text(
    '[project]\nname = "demo"\ndependencies = []\n'
    '[dependency-groups]\n'
    'dev = ["ruff", {include-group = "test"}]\n'
    'test = ["pytest"]\n'
)
parse(p)  # NameError: name 'data' is not defined
```

```python
from pathlib import Path
from pqcheck.deps.pyproject_toml import parse

p = Path("/tmp/pqcheck-build-system-only.toml")
p.write_text(
    '[build-system]\n'
    'requires = ["setuptools", "cryptography>=43"]\n'
    'build-backend = "setuptools.build_meta"\n'
)
parse(p)  # []
```

## Impact

- CI is red on the branch.
- Any `pyproject.toml` with `[dependency-groups]` can crash parsing.
- Build-time dependencies declared by PEP 518 are omitted from the dependency inventory, including crypto packages such as `cryptography`.

## Expected Fix

Move `[build-system].requires` handling back into `_iter_requirement_strings(data)` and keep `_expand_one_group()` independent of `data`. Add/keep tests for:

- PEP 735 groups.
- `include-group` transitive resolution and cycles.
- build-system-only `pyproject.toml`.
- runtime/build-system deduplication.
