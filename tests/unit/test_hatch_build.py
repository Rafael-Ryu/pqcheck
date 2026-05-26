import hashlib
import importlib.util
import types
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]


def _load_hatch_build() -> types.ModuleType:
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


def _make_hook(root: Path) -> object:
    """Instantiate CryptoAnalyzerHashHook without a real build environment.

    BuildHookInterface degrades to `object` when hatchling is absent, so we
    only need to set the `root` attribute that `initialize` reads.
    """
    hook = hatch_build.CryptoAnalyzerHashHook.__new__(hatch_build.CryptoAnalyzerHashHook)
    hook.root = str(root)
    return hook


def test_initialize_sets_infer_tag_when_binary_present(tmp_path: Path) -> None:
    # Lay out a fake binary at the path the hook expects.
    platform_dir = hatch_build._platform_dir()
    binary_name = hatch_build._binary_name()
    bin_dir = tmp_path / "src" / "pqcheck" / "bin" / platform_dir
    bin_dir.mkdir(parents=True)
    (bin_dir / binary_name).write_bytes(b"fake-binary")

    hook = _make_hook(tmp_path)
    build_data: dict[str, object] = {}
    hook.initialize("1.0", build_data)  # type: ignore[union-attr]

    assert build_data.get("infer_tag") is True


def test_initialize_does_not_set_infer_tag_when_binary_absent(tmp_path: Path) -> None:
    # No binary on disk — source-install path.
    hook = _make_hook(tmp_path)
    build_data: dict[str, object] = {}
    hook.initialize("1.0", build_data)  # type: ignore[union-attr]

    assert "infer_tag" not in build_data
