"""End-to-end bridge test: real crypto-analyzer binary over a real Go module.

Builds the analyzer on demand (skipping when `go` is unavailable, as on the
Python-only CI) and drives detect_go_module through the actual subprocess, so the
semantic path — not just the mocked unit tests — is exercised locally.
"""

import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from pqcheck.detectors.go_module_detector import detect_go_module

_REPO = Path(__file__).resolve().parents[2]
_ANALYZER_DIR = _REPO / "tools" / "crypto-analyzer"
_CATALOG = _REPO / "src" / "pqcheck" / "data" / "crypto-catalog.json"


@pytest.fixture(scope="module")
def crypto_analyzer_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("go") is None:
        pytest.skip("go toolchain not available")
    # The embed source is gitignored; copy the single-source catalog in, exactly
    # as the Inc4 build step will, then build the binary.
    shutil.copyfile(_CATALOG, _ANALYZER_DIR / "internal" / "catalog" / "crypto-catalog.json")
    out = tmp_path_factory.mktemp("bin") / "crypto-analyzer"
    result = subprocess.run(
        ["go", "build", "-o", str(out), "./cmd/crypto-analyzer"],
        cwd=_ANALYZER_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"go build failed: {result.stderr}")
    return out


@pytest.mark.integration
def test_detect_go_module_semantic_path(
    crypto_analyzer_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PQCHECK_CRYPTO_ANALYZER", str(crypto_analyzer_binary))
    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.24\n", encoding="utf-8")
    (tmp_path / "main.go").write_text(
        textwrap.dedent(
            """
            package main

            import (
                "crypto/aes"
                "crypto/cipher"
                "crypto/rand"
                "crypto/rsa"
            )

            func main() {
                rsa.GenerateKey(rand.Reader, 2048)
                block, _ := aes.NewCipher(make([]byte, 32))
                cipher.NewGCM(block)
            }
            """
        ).lstrip(),
        encoding="utf-8",
    )

    findings = detect_go_module(tmp_path)

    by_algo = {f.algorithm: f for f in findings}
    assert {"RSA", "AES"} <= by_algo.keys()
    assert by_algo["RSA"].key_size == 2048
    assert by_algo["RSA"].detector_id == "go-types"
    assert by_algo["AES"].mode == "GCM"  # mode linked to the block cipher (#99)
