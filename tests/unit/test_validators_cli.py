"""The two artifact validators' CLI paths — both are release gates in CI.

The aggregate 85% coverage threshold hid these modules at ~50%: everything
below `validate_*()` (argument handling, unreadable input, the violation
report, the exit codes CI branches on) was unexercised. A per-module gate in
ci.yml keeps them from sliding back.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pqcheck.cbom import validator as cbom_validator
from pqcheck.output import sarif_validator

_MINIMAL_CBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [],
}

_MINIMAL_SARIF = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{"tool": {"driver": {"name": "pqcheck"}}, "results": []}],
}

_CASES = [
    pytest.param(cbom_validator, _MINIMAL_CBOM, "valid CycloneDX 1.6", id="cbom"),
    pytest.param(sarif_validator, _MINIMAL_SARIF, "valid SARIF 2.1.0", id="sarif"),
]


@pytest.mark.parametrize(("module", "doc", "ok_message"), _CASES)
def test_main_accepts_a_valid_document(
    module, doc, ok_message, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    assert module.main([str(path)]) == 0
    assert ok_message in capsys.readouterr().out


@pytest.mark.parametrize(("module", "doc", "ok_message"), _CASES)
def test_main_reports_violations_and_exits_one(
    module, doc, ok_message, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = {**doc, "version": "not-a-number"}
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(broken), encoding="utf-8")

    assert module.main([str(path)]) == 1
    assert capsys.readouterr().err.strip()


@pytest.mark.parametrize(("module", "doc", "ok_message"), _CASES)
def test_main_rejects_wrong_argument_count(
    module, doc, ok_message, capsys: pytest.CaptureFixture[str]
) -> None:
    assert module.main([]) == 2
    assert "usage:" in capsys.readouterr().err


@pytest.mark.parametrize(("module", "doc", "ok_message"), _CASES)
def test_main_reports_unreadable_input(
    module, doc, ok_message, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert module.main([str(tmp_path / "missing.json")]) == 2
    assert "cannot load" in capsys.readouterr().err


@pytest.mark.parametrize(("module", "doc", "ok_message"), _CASES)
def test_main_reports_malformed_json(
    module, doc, ok_message, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "doc.json"
    path.write_text("{not json", encoding="utf-8")

    assert module.main([str(path)]) == 2
    assert "cannot load" in capsys.readouterr().err
