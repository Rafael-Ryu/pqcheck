"""Walk a repository and classify the files the scanner cares about.

Ignore semantics in v0.1: the root-level `.gitignore` and `.pqcheckignore`
(gitwildmatch, via pathspec) plus a builtin always-ignore set for VCS
metadata, virtualenvs, and tool caches. Nested `.gitignore` files are not
honored yet — documented limitation. Go `vendor/` is deliberately scanned:
vendored code ships in the final binary, so its crypto is in scope.

Symlinks are never followed (neither directories nor files), matching the
detector-side `_source_read` hardening. The walk never raises: unreadable
directories or ignore files become `Discovery.errors` entries and the walk
continues.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pathspec

_ALWAYS_IGNORE_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".eggs",
    "dist",
    "build",
})

MANIFEST_NAMES = frozenset({
    "pyproject.toml",
    "uv.lock",
    "requirements.txt",
    "pom.xml",
    "go.mod",
    "package-lock.json",
})

_IGNORE_FILES = (".gitignore", ".pqcheckignore")


@dataclass(frozen=True)
class Discovery:
    python_files: tuple[Path, ...] = ()
    go_files: tuple[Path, ...] = ()
    manifests: tuple[Path, ...] = ()
    errors: tuple[str, ...] = ()


def _load_ignore_spec(root: Path) -> tuple[pathspec.PathSpec, list[str]]:
    lines: list[str] = []
    errors: list[str] = []
    for name in _IGNORE_FILES:
        ignore_file = root / name
        try:
            if ignore_file.is_file() and not ignore_file.is_symlink():
                text = ignore_file.read_text(encoding="utf-8", errors="replace")
                lines.extend(text.splitlines())
        except OSError as exc:
            errors.append(f"{ignore_file}: {exc.strerror or exc}")
    return pathspec.GitIgnoreSpec.from_lines(lines), errors


def discover(root: Path) -> Discovery:
    root = root.resolve()
    spec, errors = _load_ignore_spec(root)
    python_files: list[Path] = []
    go_files: list[Path] = []
    manifests: list[Path] = []

    if not root.is_dir():
        errors.append(f"{root}: not a directory")
        return Discovery(errors=tuple(errors))

    def on_error(exc: OSError) -> None:
        errors.append(f"{exc.filename or root}: {exc.strerror or exc}")

    for dirpath, dirnames, filenames in root.walk(on_error=on_error, follow_symlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in _ALWAYS_IGNORE_DIRS
            and not spec.match_file((dirpath / d).relative_to(root).as_posix() + "/")
        )
        for filename in sorted(filenames):
            file_path = dirpath / filename
            try:
                if file_path.is_symlink():
                    continue
            except OSError as exc:  # pragma: no cover - racy filesystem edge
                errors.append(f"{file_path}: {exc.strerror or exc}")
                continue
            if spec.match_file(file_path.relative_to(root).as_posix()):
                continue
            if filename.endswith(".py"):
                python_files.append(file_path)
            elif filename.endswith(".go"):
                go_files.append(file_path)
            elif filename in MANIFEST_NAMES:
                manifests.append(file_path)

    return Discovery(
        python_files=tuple(sorted(python_files)),
        go_files=tuple(sorted(go_files)),
        manifests=tuple(sorted(manifests)),
        errors=tuple(errors),
    )
