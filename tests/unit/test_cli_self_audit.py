import json
from pathlib import Path

from typer.testing import CliRunner

from pqcheck.cli import app

runner = CliRunner()


def _repo(tmp_path: Path, source: str) -> Path:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return tmp_path


def test_self_audit_clean_project_passes_and_writes_cbom(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "import hashlib\nhashlib.sha256(b'x')\n")
    out = tmp_path / "self-cbom.json"
    result = runner.invoke(app, ["self-audit", str(repo), "-o", str(out)])
    assert result.exit_code == 0
    assert "self-audit clean" in result.output
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"


def test_self_audit_gates_banned_crypto(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "import hashlib\nhashlib.md5(b'x')\n")
    out = tmp_path / "self-cbom.json"
    result = runner.invoke(app, ["self-audit", str(repo), "-o", str(out)])
    assert result.exit_code == 1
    assert "tripped" in result.output
    # the artifact is still written: a failing audit must leave evidence
    assert out.is_file()


def test_self_audit_honors_pqcheckignore(tmp_path: Path) -> None:
    repo = _repo(tmp_path, "import hashlib\nhashlib.sha256(b'x')\n")
    bad = repo / "fixtures" / "bad.py"
    bad.parent.mkdir()
    bad.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    (repo / ".pqcheckignore").write_text("fixtures/\n", encoding="utf-8")
    result = runner.invoke(
        app, ["self-audit", str(repo), "-o", str(tmp_path / "c.json")]
    )
    assert result.exit_code == 0
