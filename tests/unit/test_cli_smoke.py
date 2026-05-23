from typer.testing import CliRunner

from pqcheck import __version__
from pqcheck.cli import app


def test_version_subcommand_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
