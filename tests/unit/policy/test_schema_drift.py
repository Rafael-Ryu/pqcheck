import json
from importlib.resources import files

from pqcheck.policy.loader import main
from pqcheck.policy.schema import export_json_schema

SCHEMA_PATH = "schemas/pqcheck-policy.schema.json"


def test_committed_json_schema_matches_models():
    committed = files("pqcheck").joinpath(SCHEMA_PATH).read_text(encoding="utf-8")
    expected = json.dumps(export_json_schema(), indent=2, sort_keys=True) + "\n"
    assert committed == expected, (
        "pqcheck-policy.schema.json is stale; regenerate with:\n"
        "  uv run python -c \"import json; from pqcheck.policy.schema import "
        "export_json_schema; open('src/pqcheck/schemas/pqcheck-policy.schema.json','w')"
        ".write(json.dumps(export_json_schema(), indent=2, sort_keys=True) + chr(10))\""
    )


def test_loader_main_ok(capsys, tmp_path):
    p = tmp_path / "p.yaml"
    p.write_text(files("pqcheck.policy").joinpath("defaults", "cryptoct-default.yaml").read_text())
    assert main([str(p)]) == 0
    assert "OK: cryptoct-default" in capsys.readouterr().out


def test_loader_main_rejects_bad_arity():
    assert main([]) == 2


def test_loader_main_invalid_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("kind: NotAPolicy\n")
    assert main([str(bad)]) == 1
