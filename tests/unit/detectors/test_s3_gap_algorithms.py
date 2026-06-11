"""Policy §3 algorithms that were missing from the §13-derived catalogs.

RIPEMD-160, Blowfish, and IDEA are banned by the normative §3 of the
crypto policy but were absent from detector catalogs and default
policies (tracked gap; M2 reconciliation). RSA padding variants from §3
(PKCS1v15 / OAEP-SHA1) are deliberately NOT detected separately: any RSA
use already fails CRITICAL, which is the §3 rationale verbatim.
"""

from pathlib import Path

from pqcheck.detectors.python_detector import detect_python_file
from pqcheck.models import _QUANTUM_MAP, QuantumRisk
from pqcheck.policy.loader import load_default_policy


def _detect(tmp_path: Path, source: str) -> list[str]:
    f = tmp_path / "x.py"
    f.write_text(source, encoding="utf-8")
    return [finding.algorithm for finding in detect_python_file(f)]


def test_hashlib_new_ripemd160(tmp_path: Path) -> None:
    algos = _detect(tmp_path, 'import hashlib\nhashlib.new("ripemd160", b"x")\n')
    assert "RIPEMD-160" in algos


def test_pycryptodome_ripemd160_and_blowfish(tmp_path: Path) -> None:
    algos = _detect(tmp_path, """
from Crypto.Hash import RIPEMD160
from Crypto.Cipher import Blowfish
RIPEMD160.new(b"x")
Blowfish.new(b"k" * 16, Blowfish.MODE_CBC)
""")
    assert "RIPEMD-160" in algos
    assert "Blowfish" in algos


def test_cryptography_decrepit_blowfish_idea(tmp_path: Path) -> None:
    algos = _detect(tmp_path, """
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish, IDEA
Blowfish(b"k" * 16)
IDEA(b"k" * 16)
""")
    assert algos.count("Blowfish") == 1
    assert algos.count("IDEA") == 1


def test_cryptography_legacy_paths_still_match(tmp_path: Path) -> None:
    # Pre-cryptography-43 code imports these from primitives.ciphers — the
    # exact code population a legacy-fintech scan exists to find.
    algos = _detect(tmp_path, """
from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish, IDEA
Blowfish(b"k" * 16)
IDEA(b"k" * 16)
""")
    assert "Blowfish" in algos and "IDEA" in algos


def test_quantum_risk_classification() -> None:
    # 64-bit-block ciphers are classically broken (Sweet32 class), like 3DES.
    assert _QUANTUM_MAP["BLOWFISH"] is QuantumRisk.BROKEN
    assert _QUANTUM_MAP["IDEA"] is QuantumRisk.BROKEN
    # RIPEMD-160 has no practical collision; it is banned for its margin.
    assert _QUANTUM_MAP["RIPEMD-160"] is QuantumRisk.VULNERABLE


def test_default_policies_ban_the_s3_gap_set() -> None:
    for name in ("cryptoct-default", "cryptoct-strict", "cryptoct-advisory"):
        banned = {r.algorithm for r in load_default_policy(name).spec.banned}
        assert {"RIPEMD-160", "Blowfish", "IDEA"} <= banned, name
