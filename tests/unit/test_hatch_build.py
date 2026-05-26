import hashlib
import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _load_hatch_build() -> object:
    spec = importlib.util.spec_from_file_location("hatch_build", _ROOT / "hatch_build.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hatch_build = _load_hatch_build()


def test_write_sha256_constant_writes_hash(tmp_path: Path) -> None:
    binary = tmp_path / "crypto-analyzer"
    binary.write_bytes(b"fake-binary")
    out = tmp_path / "_constants.py"

    digest = hatch_build.write_sha256_constant(binary, out)

    assert digest == hashlib.sha256(b"fake-binary").hexdigest()
    assert f'CRYPTO_ANALYZER_SHA256 = "{digest}"' in out.read_text(encoding="utf-8")


def test_write_sha256_constant_skips_when_binary_absent(tmp_path: Path) -> None:
    out = tmp_path / "_constants.py"

    assert hatch_build.write_sha256_constant(tmp_path / "absent", out) is None
    assert not out.exists()
