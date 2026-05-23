from typer.testing import CliRunner

import pqcheck.__main__ as main_module
from pqcheck.cli import app


def test_scan_stub_exits_with_usage_error() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "."])
    assert result.exit_code == 64


def test_main_module_exposes_app() -> None:
    assert main_module.app is app
