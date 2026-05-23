import ast
from pathlib import Path

from pqcheck.detectors.python_detector import ImportResolver, PythonDetector
from pqcheck.models import AlgorithmFamily, CryptoFinding, QuantumRisk


def _resolver(source: str) -> ImportResolver:
    tree = ast.parse(source)
    r = ImportResolver()
    r.visit(tree)
    return r


def test_plain_import_records_module_name() -> None:
    r = _resolver("import hashlib")
    assert r.resolve_name("hashlib") == "hashlib"


def test_import_with_alias_records_alias() -> None:
    r = _resolver("import hashlib as h")
    assert r.resolve_name("h") == "hashlib"
    assert r.resolve_name("hashlib") is None


def test_dotted_import_records_full_path() -> None:
    r = _resolver("import cryptography.hazmat.primitives.hashes")
    assert r.resolve_name("cryptography") == "cryptography"


def test_from_import_records_qualified_symbol() -> None:
    r = _resolver("from hashlib import md5")
    assert r.resolve_name("md5") == "hashlib.md5"


def test_from_import_with_alias() -> None:
    r = _resolver("from hashlib import md5 as digest")
    assert r.resolve_name("digest") == "hashlib.md5"
    assert r.resolve_name("md5") is None


def test_from_dotted_module_import() -> None:
    r = _resolver(
        "from cryptography.hazmat.primitives import hashes"
    )
    assert r.resolve_name("hashes") == "cryptography.hazmat.primitives.hashes"


def test_star_import_recorded_as_sentinel() -> None:
    r = _resolver("from hashlib import *")
    assert r.has_star_import("hashlib") is True


def test_resolve_attribute_chain_on_name() -> None:
    tree = ast.parse("hashlib.md5()")
    r = ImportResolver()
    r.add_module("hashlib", "hashlib")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) == "hashlib.md5"


def test_resolve_attribute_chain_with_alias() -> None:
    tree = ast.parse("h.md5()")
    r = ImportResolver()
    r.add_module("h", "hashlib")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) == "hashlib.md5"


def test_resolve_attribute_chain_three_segments() -> None:
    tree = ast.parse("hashes.MD5()")
    r = ImportResolver()
    r.add_module("hashes", "cryptography.hazmat.primitives.hashes")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) == (
        "cryptography.hazmat.primitives.hashes.MD5"
    )


def test_resolve_attribute_unrecorded_base_returns_none() -> None:
    r = ImportResolver()
    r.add_module("other", "other")
    tree = ast.parse("unknown.attr()")
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) is None


def test_relative_import_is_skipped() -> None:
    r = _resolver("from . import sibling")
    assert r.resolve_name("sibling") is None


def test_unresolved_name_returns_none() -> None:
    tree = ast.parse("foo.bar()")
    r = ImportResolver()
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) is None


def test_resolve_attribute_chain_not_terminating_in_name_returns_none() -> None:
    tree = ast.parse('"abc".upper()')
    r = ImportResolver()
    call = tree.body[0].value
    assert isinstance(call, ast.Call)
    assert r.resolve_attribute(call.func) is None


def _scan(source: str, path: str = "sample.py") -> list[CryptoFinding]:
    tree = ast.parse(source)
    detector = PythonDetector(source_path=Path(path), source=source)
    detector.visit(tree)
    return detector.findings


def test_detector_finds_hashlib_md5_call() -> None:
    findings = _scan("import hashlib\nhashlib.md5(b'x')\n")
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "MD5"
    assert f.family is AlgorithmFamily.HASH
    assert f.quantum_risk is QuantumRisk.BROKEN
    assert f.location.line == 2
    assert f.detector_id == "python-ast"
    assert f.confidence == 1.0


def test_detector_finds_md5_via_from_import() -> None:
    findings = _scan("from hashlib import md5\nmd5(b'x')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detector_finds_md5_via_alias() -> None:
    findings = _scan("from hashlib import md5 as digest\ndigest(b'x')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detector_finds_rsa_keygen() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA"
    assert findings[0].family is AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    assert findings[0].quantum_risk is QuantumRisk.VULNERABLE


def test_detector_finds_pycryptodome_aes() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'\\x00' * 32, AES.MODE_GCM)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_detector_ignores_unknown_calls() -> None:
    findings = _scan("import os\nos.getcwd()\nprint('hi')\n")
    assert findings == []


def test_detector_records_evidence_snippet() -> None:
    findings = _scan("import hashlib\nhashlib.md5(b'x')\n")
    assert "hashlib.md5" in findings[0].evidence


def test_detector_starts_with_empty_findings() -> None:
    findings = _scan("x = 1\n")
    assert findings == []


def test_detector_demotes_confidence_for_hashlib_new_string() -> None:
    findings = _scan("import hashlib\nhashlib.new('md5')\n")
    # String-based dynamic dispatch — confidence demoted vs direct call.
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
    assert findings[0].confidence == 0.7


def test_detector_skips_cipher_wrapper() -> None:
    # Cipher wrapper is recognized in the catalog as "CIPHER-WRAPPER" but
    # Task 4 deliberately does NOT emit it — Task 5 handles the nested
    # algorithm/mode extraction. This test pins that contract.
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'k' * 32), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    # algorithms.AES(...) is itself a Call resolving to AES — it WILL be
    # emitted as a flat call finding in Task 4. modes.GCM(...) similarly.
    # We assert no CIPHER-WRAPPER finding shows up, regardless of how
    # many flat findings the inner calls generate.
    assert all(f.algorithm != "CIPHER-WRAPPER" for f in findings)
