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

import packaging.tags

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


def _platform_tag() -> str:
    """Wheel platform tag for the host the wheel is built on.

    cibuildwheel runs each build in the target's own environment (the manylinux
    container, the macOS arch, the Windows runner), so the host's most-specific
    platform tag is the target's; auditwheel/delocate later normalise the
    linux/macOS form. The binary is ABI-agnostic, so only the platform portion
    matters.
    """
    return next(packaging.tags.sys_tags()).platform


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
        # The binary is invoked as a subprocess, not linked against the CPython
        # ABI, so the wheel installs on any Python 3 for this platform. Tag it
        # py3-none-<platform> rather than the interpreter-specific tag infer_tag
        # would derive: one wheel per platform then serves every supported (and
        # future) 3.x, instead of one wheel locked per minor version. A platform
        # tag is still required — py3-none-any would collide across platforms on
        # PyPI. pure_python=False keeps the wheel in platlib (not Root-Is-Purelib).
        build_data["tag"] = f"py3-none-{_platform_tag()}"
        build_data["pure_python"] = False
        force_include = build_data.setdefault("force_include", {})
        if isinstance(force_include, dict):
            force_include[str(out)] = _WHEEL_TARGET
