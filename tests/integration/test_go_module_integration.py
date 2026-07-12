"""End-to-end bridge test: real crypto-analyzer binary over a real Go module.

Builds the analyzer on demand (skipping when `go` is unavailable, as on the
Python-only CI) and drives detect_go_module through the actual subprocess, so the
semantic path — not just the mocked unit tests — is exercised locally.
"""

import hashlib
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from pqcheck.detectors import go_module_detector as gmd
from pqcheck.detectors.go_module_detector import detect_go_module
from pqcheck.models import QuantumRisk

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
    # main.go: RSA keygen + AES with mode linked (GCM).
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
    # extra.go: ECDSA with a named curve AND AES whose block var is never passed
    # to a mode constructor, so the analyzer emits mode == "" (no-mode finding).
    (tmp_path / "extra.go").write_text(
        textwrap.dedent(
            """
            package main

            import (
                "crypto/aes"
                "crypto/ecdsa"
                "crypto/elliptic"
                "crypto/rand"
            )

            func extra() {
                ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
                block, _ := aes.NewCipher(make([]byte, 16))
                _ = block
            }
            """
        ).lstrip(),
        encoding="utf-8",
    )

    findings = detect_go_module(tmp_path)

    assert all(f.detector_id == "go-types" for f in findings)

    algos = {f.algorithm for f in findings}
    assert {"RSA", "AES", "ECDSA"} <= algos

    # RSA: key size resolved via type info.
    rsa_findings = [f for f in findings if f.algorithm == "RSA"]
    assert any(f.key_size == 2048 for f in rsa_findings)

    # AES with mode linked (GCM) — from main.go.
    aes_findings = [f for f in findings if f.algorithm == "AES"]
    assert any(f.mode == "GCM" for f in aes_findings), "expected AES+GCM finding"

    # AES without a linked mode — block var not passed to any mode constructor.
    assert any(f.mode is None for f in aes_findings), "expected AES with no linked mode"

    # ECDSA with curve extracted from elliptic.P256() call argument.
    ecdsa_findings = [f for f in findings if f.algorithm == "ECDSA"]
    assert any(f.curve == "P-256" for f in ecdsa_findings), "expected ECDSA with P-256 curve"


@pytest.mark.integration
def test_detect_go_module_resolves_ecdh_method_and_hpke_hybrid(
    crypto_analyzer_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # End-to-end: the real analyzer binary + JSON bridge for the method-call
    # detection added to close the corpus-v2 recall gap (smallstep/crypto
    # pub.ECDH(), age's hpke.MLKEM768X25519().GenerateKey()).
    monkeypatch.setenv("PQCHECK_CRYPTO_ANALYZER", str(crypto_analyzer_binary))
    (tmp_path / "go.mod").write_text(
        "module example.com/m\n\ngo 1.24\n\nrequire filippo.io/hpke v0.4.0\n",
        encoding="utf-8",
    )
    (tmp_path / "vendor" / "modules.txt").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "vendor" / "modules.txt").write_text(
        "# filippo.io/hpke v0.4.0\n## explicit; go 1.24\nfilippo.io/hpke\n",
        encoding="utf-8",
    )
    hpke_dir = tmp_path / "vendor" / "filippo.io" / "hpke"
    hpke_dir.mkdir(parents=True, exist_ok=True)
    (hpke_dir / "hpke.go").write_text(
        textwrap.dedent(
            """
            package hpke

            type PrivateKey interface{}
            type KEM interface{ GenerateKey() (PrivateKey, error) }
            type hybridKEM struct{}
            func (hybridKEM) GenerateKey() (PrivateKey, error) { return nil, nil }
            func MLKEM768X25519() KEM { return hybridKEM{} }
            """
        ).lstrip(),
        encoding="utf-8",
    )
    (tmp_path / "main.go").write_text(
        textwrap.dedent(
            """
            package main

            import (
                "crypto/ecdsa"
                "filippo.io/hpke"
            )

            func f(pub *ecdsa.PublicKey) {
                pub.ECDH()
                hpke.MLKEM768X25519().GenerateKey()
            }
            """
        ).lstrip(),
        encoding="utf-8",
    )

    findings = detect_go_module(tmp_path)
    by_algo = {f.algorithm: f for f in findings}

    assert by_algo["ECDH"].confidence == 1.0
    assert by_algo["ECDH"].quantum_risk == QuantumRisk.VULNERABLE

    assert by_algo["X25519MLKEM768"].confidence == 1.0
    assert by_algo["X25519MLKEM768"].quantum_risk == QuantumRisk.HYBRID
    assert all(f.detector_id == "go-types" for f in findings)


@pytest.mark.integration
def test_bundled_binary_passes_real_sha256_pin(
    crypto_analyzer_binary: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The must-succeed direction of the pin: a real binary whose real SHA-256
    # matches a real pin, driven through the bundled (untrusted) branch — proving
    # the digest the bridge computes matches the one hatch_build writes, and the
    # exec path works without the trusted env override. The unit tests only cover
    # synthetic bytes and the mismatch (fail-closed) direction.
    real_pin = hashlib.sha256(crypto_analyzer_binary.read_bytes()).hexdigest()
    monkeypatch.delenv("PQCHECK_CRYPTO_ANALYZER", raising=False)
    monkeypatch.setattr(gmd, "_CRYPTO_ANALYZER_SHA256", real_pin)
    monkeypatch.setattr(gmd, "_locate_binary", lambda: (crypto_analyzer_binary, False))

    (tmp_path / "go.mod").write_text("module example.com/m\n\ngo 1.24\n", encoding="utf-8")
    (tmp_path / "main.go").write_text(
        'package main\nimport "crypto/md5"\nfunc main() { md5.New() }\n', encoding="utf-8"
    )

    findings = detect_go_module(tmp_path)

    assert {f.algorithm for f in findings} == {"MD5"}
    assert all(f.detector_id == "go-types" for f in findings)
