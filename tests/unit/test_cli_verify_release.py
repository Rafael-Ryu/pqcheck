from pathlib import Path

import pytest
from sigstore.errors import VerificationError
from sigstore.models import Bundle
from sigstore.verify import Verifier
from typer.testing import CliRunner

from pqcheck.cli import app

runner = CliRunner()


@pytest.fixture
def artifact(tmp_path: Path) -> Path:
    wheel = tmp_path / "pqcheck-0.0.1-py3-none-any.whl"
    wheel.write_bytes(b"not a real wheel")
    (tmp_path / "pqcheck-0.0.1-py3-none-any.whl.sigstore.json").write_text("{}", encoding="utf-8")
    return wheel


def _patch_verifier(monkeypatch: pytest.MonkeyPatch, verify_error: str | None = None) -> None:
    class FakeVerifier:
        def verify_artifact(self, input_: bytes, bundle: object, policy: object) -> None:
            if verify_error is not None:
                raise VerificationError(verify_error)

    monkeypatch.setattr(Verifier, "production", staticmethod(FakeVerifier))
    monkeypatch.setattr(Bundle, "from_json", staticmethod(lambda raw: object()))


def test_verified_artifact_passes(monkeypatch: pytest.MonkeyPatch, artifact: Path) -> None:
    _patch_verifier(monkeypatch)
    result = runner.invoke(app, ["verify-release", str(artifact)])
    assert result.exit_code == 0
    assert "OK: pqcheck-0.0.1-py3-none-any.whl verified" in result.output


def test_explicit_bundle_and_identity(monkeypatch: pytest.MonkeyPatch, artifact: Path) -> None:
    _patch_verifier(monkeypatch)
    bundle = artifact.with_name(artifact.name + ".sigstore.json")
    result = runner.invoke(
        app,
        [
            "verify-release",
            str(artifact),
            "--bundle",
            str(bundle),
            "--identity",
            "https://github.com/Rafael-Ryu/pqcheck/.github/workflows/cli-release.yml@refs/tags/pqcheck-v0.0.1",
        ],
    )
    assert result.exit_code == 0


def test_failed_verification_exits_1(monkeypatch: pytest.MonkeyPatch, artifact: Path) -> None:
    _patch_verifier(monkeypatch, verify_error="signature mismatch")
    result = runner.invoke(app, ["verify-release", str(artifact)])
    assert result.exit_code == 1
    assert "verification FAILED" in result.output


def test_missing_bundle_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    wheel = tmp_path / "lonely.whl"
    wheel.write_bytes(b"x")
    result = runner.invoke(app, ["verify-release", str(wheel)])
    assert result.exit_code == 2
    assert "bundle not found" in result.output


def test_malformed_bundle_exits_2(artifact: Path) -> None:
    # real Bundle.from_json rejects the "{}" placeholder bundle
    result = runner.invoke(app, ["verify-release", str(artifact)])
    assert result.exit_code == 2
    assert "invalid bundle" in result.output
