# Autoresearch Security/Debug Audit

Date: 2026-05-24
Branch: develop
Remote: https://github.com/Rafael-Ryu/pqcheck.git
Base commit: e991a2b

## Commands Run

```text
uv run pytest
uv run ruff check .
uv run mypy
PYTHONPATH=src python targeted reproductions for pyproject, detector aliases, PyCryptodome modes, and star imports
timeout 2s symlink-to-/dev/zero reproduction for detect_python_file
gh issue list --repo Rafael-Ryu/pqcheck --state open --limit 100 --json number,title,url,labels
```

## Verification Results

```text
uv run pytest: 7 failed, 175 passed
uv run ruff check .: failed with F821 Undefined name `data`
uv run mypy: failed with Name "data" is not defined
gh issue list: []
```

## Issues Created

- AR-001: https://github.com/Rafael-Ryu/pqcheck/issues/33
- AR-002: https://github.com/Rafael-Ryu/pqcheck/issues/34
- AR-003: https://github.com/Rafael-Ryu/pqcheck/issues/37
- AR-004: https://github.com/Rafael-Ryu/pqcheck/issues/36
- AR-005: https://github.com/Rafael-Ryu/pqcheck/issues/35

See `findings.tsv` and the `issue-ar-*.md` files in this directory for local copies of the evidence and issue bodies.
