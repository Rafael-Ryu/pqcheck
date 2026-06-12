import io
import json
import sys
from importlib.resources import files
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pqcheck.__main__ as main_module
from pqcheck.cli import _configure_output_streams, app

runner = CliRunner()

_RSA_SRC = (
    "from cryptography.hazmat.primitives.asymmetric import rsa\n"
    "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
)
_SHA256_SRC = "import hashlib\nhashlib.sha256(b'x')\n"
_BLAKE2_SRC = "import hashlib\nhashlib.blake2b(b'x')\n"


def _repo(tmp_path: Path, source: str) -> Path:
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    return tmp_path


def test_main_module_exposes_app() -> None:
    assert main_module.app is app


def test_scan_without_policy_lists_findings_and_passes(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(_repo(tmp_path, _RSA_SRC))])
    assert result.exit_code == 0
    assert "RSA" in result.output
    assert "app.py" in result.output


def test_scan_with_policy_gates_banned_rsa(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(_repo(tmp_path, _RSA_SRC)), "--policy", "cryptoct-default"]
    )
    assert result.exit_code == 1
    assert "✗" in result.output
    assert "tripped at critical" in result.output


def test_scan_with_policy_passes_approved_sha256(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(_repo(tmp_path, _SHA256_SRC)), "--policy", "cryptoct-default"]
    )
    assert result.exit_code == 0
    assert "✓" in result.output


def test_strict_gates_default_action_warns(tmp_path: Path) -> None:
    # BLAKE2b is neither approved nor banned in cryptoct-default → default
    # warn. Plain run passes; --strict turns the warn into a failure.
    repo = _repo(tmp_path, _BLAKE2_SRC)
    relaxed = runner.invoke(app, ["scan", str(repo), "--policy", "cryptoct-default"])
    strict = runner.invoke(
        app, ["scan", str(repo), "--policy", "cryptoct-default", "--strict"]
    )
    assert relaxed.exit_code == 0
    assert strict.exit_code == 1


def test_fail_on_severity_reads_base_severity(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan", str(_repo(tmp_path, _RSA_SRC)),
            "--policy", "cryptoct-default", "--fail-on", "high",
        ],
    )
    assert result.exit_code == 1


def test_cbom_output_is_written_and_gate_still_applies(tmp_path: Path) -> None:
    out = tmp_path / "out" / "cbom.cdx.json"
    out.parent.mkdir()
    result = runner.invoke(
        app,
        [
            "scan", str(_repo(tmp_path, _RSA_SRC)),
            "--policy", "cryptoct-default", "--format", "cbom", "-o", str(out),
        ],
    )
    assert result.exit_code == 1  # gate fires after the artifact is written
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert any(c["type"] == "cryptographic-asset" for c in doc["components"])


def test_sarif_output_to_stdout(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(_repo(tmp_path, _RSA_SRC)), "--format", "sarif"]
    )
    assert result.exit_code == 0
    doc = json.loads(result.stdout)
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_output_flag_requires_machine_format(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "-o", str(tmp_path / "x.json")]
    )
    assert result.exit_code == 2


def test_fail_on_requires_policy(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high"])
    assert result.exit_code == 2


def test_unknown_policy_name_is_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--policy", "no-such-policy"])
    assert result.exit_code == 2


def test_policy_show_prints_resolved_policy() -> None:
    result = runner.invoke(app, ["policy", "show", "cryptoct-default"])
    assert result.exit_code == 0
    assert '"cryptoct-default"' in result.stdout


def test_policy_validate_accepts_valid_and_rejects_invalid(tmp_path: Path) -> None:
    good = tmp_path / "good.yaml"
    good.write_text(
        files("pqcheck.policy")
        .joinpath("defaults/cryptoct-default.yaml")
        .read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    bad = tmp_path / "bad.yaml"
    bad.write_text("apiVersion: nope\n", encoding="utf-8")

    ok = runner.invoke(app, ["policy", "validate", str(good)])
    nok = runner.invoke(app, ["policy", "validate", str(bad)])
    assert ok.exit_code == 0 and "valid:" in ok.stdout
    assert nok.exit_code == 1


def test_output_streams_degrade_on_legacy_codepages(monkeypatch: pytest.MonkeyPatch) -> None:
    # Windows consoles default to cp1252, which cannot encode the report
    # marks; the configured stream must replace instead of raising (the
    # Windows CI cell crashed on the first ✓ before this).
    legacy = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", legacy)
    _configure_output_streams()
    print("✓ RSA — Shor", file=sys.stdout)  # would raise UnicodeEncodeError unconfigured
    sys.stdout.flush()
    # the mark degrades to "?"; the em dash exists in cp1252 (0x97) and
    # survives. Normalize newlines: Windows text streams emit \r\n.
    assert legacy.buffer.getvalue().replace(b"\r\n", b"\n") == b"? RSA \x97 Shor\n"
