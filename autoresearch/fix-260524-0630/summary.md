# Autoresearch Fix Round

Date: 2026-05-24
Base branch: develop
Base commit: e991a2be97da0752714ca7d78e4373b1f207f36e

Goal: fix issues #33, #34, #37, #36, and #35, one branch and PR per issue.

## Result

All five fixes were implemented in separate `fix/...` branches with Conventional Commit messages and opened as PRs against `develop`.

## Pull Requests

- #33 -> PR #38: https://github.com/Rafael-Ryu/pqcheck/pull/38
  - Branch: `fix/pyproject-groups-build-requires`
  - Commit: `fix(deps): keep build-system requires outside PEP 735 groups`
  - Labels: `bug`, `false-negative`
- #34 -> PR #39: https://github.com/Rafael-Ryu/pqcheck/pull/39
  - Branch: `fix/python-detector-safe-read`
  - Commit: `fix(detectors): read python sources through capped fd`
  - Labels: `bug`, `security`
- #37 -> PR #40: https://github.com/Rafael-Ryu/pqcheck/pull/40
  - Branch: `fix/pycryptodome-mode-constants`
  - Commit: `fix(detectors): extract pycryptodome mode constants`
  - Labels: `bug`, `false-negative`
- #36 -> PR #41: https://github.com/Rafael-Ryu/pqcheck/pull/41
  - Branch: `fix/hashlib-new-aliases`
  - Commit: `fix(detectors): normalize hashlib.new aliases`
  - Labels: `bug`, `false-negative`
- #35 -> PR #42: https://github.com/Rafael-Ryu/pqcheck/pull/42
  - Branch: `fix/crypto-star-imports`
  - Commit: `fix(detectors): emit findings from crypto star imports`
  - Labels: `bug`, `false-negative`

Each PR body contains `Closes #N` so GitHub will close the linked issue when the PR is merged.

## Verification

- #33: focused pyproject/deps tests passed; `ruff`, `mypy`, and full `uv run pytest` passed with 182 tests.
- #34: detector focused tests passed; `ruff`, `mypy`, and full `uv run pytest` passed with 187 tests.
- #37: detector/catalog/integration focused tests passed; `ruff`, `mypy`, and full `uv run pytest` passed with 189 tests.
- #36: detector focused tests passed; `ruff`, `mypy`, and full `uv run pytest` passed with 186 tests.
- #35: detector focused tests passed; `ruff`, `mypy`, and full `uv run pytest` passed with 188 tests.

Notes: branches #34, #37, #36, and #35 include the #33 commit as a prerequisite so complete verification passes while PR #38 is still pending. After #38 merges, GitHub should reduce those PR diffs to their issue-specific commits.
