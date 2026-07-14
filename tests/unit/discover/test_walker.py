import os
from pathlib import Path

import pytest

from pqcheck.discover.walker import Discovery, discover


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        f = tmp_path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    return tmp_path


def test_classifies_python_go_and_manifests(tmp_path: Path) -> None:
    root = _tree(tmp_path, {
        "app/main.py": "x = 1\n",
        "svc/handler.go": "package svc\n",
        "pyproject.toml": "[project]\nname='x'\n",
        "svc/go.mod": "module example.com/svc\n",
        "uv.lock": "version = 1\n",
        "pom.xml": "<project/>\n",
        "web/package-lock.json": "{}\n",
        "README.md": "docs\n",
    })
    d = discover(root)
    assert [p.name for p in d.python_files] == ["main.py"]
    assert [p.name for p in d.go_files] == ["handler.go"]
    assert sorted(p.name for p in d.manifests) == [
        "go.mod", "package-lock.json", "pom.xml", "pyproject.toml", "uv.lock",
    ]
    assert d.errors == ()


def test_classifies_key_material_files(tmp_path: Path) -> None:
    root = _tree(tmp_path, {
        "certs/server.pem": "",
        "certs/server.key": "",
        "certs/ca.crt": "",
        "certs/ca.der": "",
        "certs/README.md": "not key material",
    })
    d = discover(root)
    assert sorted(p.name for p in d.key_material_files) == [
        "ca.crt", "ca.der", "server.key", "server.pem",
    ]


def test_results_are_absolute_sorted_and_deterministic(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"b/z.py": "", "a/a.py": "", "a/m.py": ""})
    d1 = discover(root)
    d2 = discover(root)
    assert d1 == d2
    assert all(p.is_absolute() for p in d1.python_files)
    rels = [p.relative_to(root).as_posix() for p in d1.python_files]
    assert rels == sorted(rels)


def test_gitignore_at_root_prunes_files_and_dirs(tmp_path: Path) -> None:
    root = _tree(tmp_path, {
        ".gitignore": "generated/\n*_pb2.py\n",
        "generated/gen.py": "",
        "app/real.py": "",
        "app/schema_pb2.py": "",
    })
    d = discover(root)
    assert [p.name for p in d.python_files] == ["real.py"]


def test_pqcheckignore_extends_gitignore(tmp_path: Path) -> None:
    root = _tree(tmp_path, {
        ".pqcheckignore": "third_party/\n",
        "third_party/vendored.py": "",
        "mine.py": "",
    })
    d = discover(root)
    assert [p.name for p in d.python_files] == ["mine.py"]


def test_builtin_ignores_skip_caches_and_envs(tmp_path: Path) -> None:
    # .venv carries an entire site-packages worth of third-party crypto;
    # scanning it would drown first-party findings and double-count deps.
    root = _tree(tmp_path, {
        ".git/hook.py": "",
        ".venv/lib/pkg.py": "",
        "node_modules/lib/x.go": "",
        "__pycache__/c.py": "",
        "dist/built.py": "",
        "src/ok.py": "",
    })
    d = discover(root)
    assert [p.name for p in d.python_files] == ["ok.py"]
    assert d.go_files == ()


def test_go_vendor_dir_is_scanned(tmp_path: Path) -> None:
    # Vendored Go code ships in the final binary — its crypto is in scope.
    root = _tree(tmp_path, {"vendor/dep/dep.go": "package dep\n", "main.go": "package main\n"})
    d = discover(root)
    assert sorted(p.name for p in d.go_files) == ["dep.go", "main.go"]


@pytest.mark.skipif(os.name == "nt", reason="symlink semantics differ on Windows")
def test_symlinked_files_and_dirs_are_skipped(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.py").write_text("", encoding="utf-8")
    (root / "link.py").symlink_to(outside / "secret.py")
    (root / "linkdir").symlink_to(outside, target_is_directory=True)
    d = discover(root)
    assert [p.name for p in d.python_files] == ["real.py"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions required")
def test_unreadable_dir_is_an_error_not_a_crash(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"ok.py": "", "locked/hidden.py": ""})
    locked = root / "locked"
    locked.chmod(0o000)
    try:
        d = discover(root)
    finally:
        locked.chmod(0o755)
    assert [p.name for p in d.python_files] == ["ok.py"]
    assert any("locked" in e for e in d.errors)


def test_nonexistent_root_yields_empty_discovery_with_error(tmp_path: Path) -> None:
    d = discover(tmp_path / "nope")
    assert d == Discovery(errors=d.errors)
    assert d.errors  # surfaced, not swallowed silently


def test_unreadable_ignore_file_is_an_error_not_a_crash(tmp_path: Path) -> None:
    if os.name == "nt":  # pragma: no cover
        pytest.skip("POSIX permissions required")
    root = _tree(tmp_path, {".gitignore": "x\n", "a.py": ""})
    (root / ".gitignore").chmod(0o000)
    try:
        d = discover(root)
    finally:
        (root / ".gitignore").chmod(0o644)
    assert [p.name for p in d.python_files] == ["a.py"]
    assert any(".gitignore" in e for e in d.errors)


def test_oversized_ignore_file_is_skipped_with_error(tmp_path: Path) -> None:
    # A hostile repo can ship a giant .gitignore; the walk must cap the read
    # (safe_read_bytes) instead of pulling it into memory whole.
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    with (tmp_path / ".gitignore").open("wb") as f:
        f.seek(5 * 1024 * 1024)
        f.write(b"\n")
    d = discover(tmp_path)
    assert [p.name for p in d.python_files] == ["app.py"]
    assert any("skipped (unreadable or oversized)" in e for e in d.errors)
