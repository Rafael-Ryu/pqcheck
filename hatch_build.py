"""Build-time hook: pin the bundled crypto-analyzer's SHA-256.

cibuildwheel's before-build compiles the Go binary into
src/pqcheck/bin/<goos>-<goarch>/crypto-analyzer, then this hook hashes it and
injects src/pqcheck/detectors/_constants.py into the wheel (via force_include, so
the source tree stays clean). The runtime bridge imports that constant and
refuses any binary whose hash does not match. A source build with no binary
present writes nothing, leaving verification lenient.
"""

from __future__ import annotations

import hashlib
import os
import platform
import sys
import tempfile
from pathlib import Path

try:
    from hatchling.builders.hooks.plugin.interface import BuildHookInterface
except ImportError:  # importable for unit tests outside the build environment
    BuildHookInterface = object  # type: ignore[assignment,misc]

_WHEEL_TARGET = "pqcheck/detectors/_constants.py"


def _platform_dir() -> str:
    """Return <goos>-<goarch> for the binary being packaged.

    cibuildwheel passes GOOS/GOARCH per matrix job (so cross-built macOS wheels
    pin the right binary); a plain local build falls back to the host's values.
    """
    goos_map = {"linux": "linux", "darwin": "darwin", "win32": "windows"}
    goarch_map = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
    goos = os.environ.get("GOOS") or goos_map.get(sys.platform, "")
    goarch = os.environ.get("GOARCH") or goarch_map.get(platform.machine().lower(), "")
    return f"{goos}-{goarch}"


def _binary_name() -> str:
    """Match the name the Windows build emits and the runtime bridge expects.

    cibuildwheel passes GOOS per matrix job; a local build falls back to the
    host's sys.platform.
    """
    goos = os.environ.get("GOOS") or ("windows" if sys.platform == "win32" else "")
    return "crypto-analyzer.exe" if goos == "windows" else "crypto-analyzer"


def write_sha256_constant(binary: Path, out: Path) -> str | None:
    """Hash `binary` and write the constant module to `out`. None if absent."""
    if not binary.is_file():
        return None
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    out.write_text(
        "# Generated at build time by hatch_build.py. Do not edit or commit.\n"
        f'CRYPTO_ANALYZER_SHA256 = "{digest}"\n',
        encoding="utf-8",
    )
    return digest


class CryptoAnalyzerHashHook(BuildHookInterface):  # type: ignore[misc]
    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, object]) -> None:
        binary = Path(self.root) / "src" / "pqcheck" / "bin" / _platform_dir() / _binary_name()
        out = Path(tempfile.mkdtemp(prefix="pqcheck-build-")) / "_constants.py"
        if write_sha256_constant(binary, out) is None:
            return
        # A platform-specific binary is present, so this wheel must carry a
        # platform tag; without it every platform emits py3-none-any and only
        # the last upload survives on PyPI (filename collision). pure_python=False
        # keeps the metadata consistent: a binary-bearing wheel targets platlib,
        # not purelib (Root-Is-Purelib: false).
        build_data["infer_tag"] = True
        build_data["pure_python"] = False
        force_include = build_data.setdefault("force_include", {})
        if isinstance(force_include, dict):
            force_include[str(out)] = _WHEEL_TARGET
