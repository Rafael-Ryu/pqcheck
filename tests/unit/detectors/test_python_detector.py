import ast
import os
from pathlib import Path

import pytest

from pqcheck.detectors.python_detector import ImportResolver, PythonDetector, detect_python_file
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
    assert findings[0].mode == "GCM"


def test_detector_finds_pycryptodome_aes_ecb_mode() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'k' * 16, AES.MODE_ECB)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode == "ECB"


def test_detector_finds_pycryptodome_des_ecb_mode() -> None:
    src = (
        "from Crypto.Cipher import DES\n"
        "DES.new(b'k' * 8, DES.MODE_ECB)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "DES"
    assert findings[0].mode == "ECB"


def test_detector_finds_pycryptodome_des3_cbc_mode() -> None:
    src = (
        "from Crypto.Cipher import DES3\n"
        "DES3.new(b'k' * 24, DES3.MODE_CBC, iv=b'i' * 8)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "3DES"
    assert findings[0].mode == "CBC"


def test_detector_pycryptodome_mode_as_kwarg() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'k' * 16, mode=AES.MODE_GCM, nonce=b'n' * 12)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].mode == "GCM"


def test_detector_pycryptodome_unresolvable_mode_emits_none() -> None:
    # Mode arg is an Attribute but the base name is not in the import map
    # (e.g. used via a dynamic reference), so the qualified lookup fails.
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'k' * 16, some_module.MODE_ECB)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode is None


def test_detector_pycryptodome_non_attribute_mode_emits_none() -> None:
    # Mode arg is a Name (variable), not an Attribute — no qualified lookup
    # possible, so mode is None.
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'k' * 16, some_mode)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].mode is None


def test_detector_pycryptodome_no_mode_arg_emits_none() -> None:
    # Single-arg call (stream cipher pattern) — no mode to extract.
    src = (
        "from Crypto.Cipher import ChaCha20\n"
        "ChaCha20.new(b'k' * 32)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "CHACHA20"
    assert findings[0].mode is None


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


def test_cipher_wrapper_unwraps_to_single_finding() -> None:
    # CIPHER-WRAPPER is a catalog marker, never a real finding canonical:
    # the wrapper is unwrapped into one finding for the inner algorithm,
    # and the nested algorithms.X() Call is suppressed so generic_visit
    # cannot re-emit it as a flat finding.
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'k' * 32), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert all(f.algorithm != "CIPHER-WRAPPER" for f in findings)


def test_detector_finds_aes_gcm_cipher() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'\\x00' * 32), modes.GCM(b'\\x00' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "AES"
    assert f.mode == "GCM"
    assert f.family is AlgorithmFamily.SYMMETRIC_CIPHER


def test_detector_finds_aes_ecb_weak_mode() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'\\x00' * 32), modes.ECB())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode == "ECB"


def test_detector_finds_3des_via_cipher_wrapper() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithms.TripleDES(b'\\x00' * 24), modes.CBC(b'\\x00' * 8))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "3DES"
    assert findings[0].mode == "CBC"


def test_cipher_with_keyword_args() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import "
        "Cipher, algorithms, modes\n"
        "Cipher(algorithm=algorithms.AES(b'k'*32), mode=modes.GCM(b'i'*12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode == "GCM"


def test_cipher_without_resolvable_algorithm_skipped() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher\n"
        "Cipher(some_unknown_thing(), other_thing())\n"
    )
    findings = _scan(src)
    assert findings == []


def test_cipher_with_no_args_skipped() -> None:
    # Covers _cipher_arg returning None when neither positional nor keyword arg
    # is present — also exercises the return None at end of _cipher_arg.
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher\n"
        "Cipher()\n"
    )
    findings = _scan(src)
    assert findings == []


def test_cipher_with_non_call_mode_emits_algorithm_without_mode() -> None:
    # mode arg is a Name (variable), not a Call — _resolve_mode_target returns
    # None, emits the finding with mode=None but algorithm resolved.
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms\n"
        "my_mode = None\n"
        "Cipher(algorithms.AES(b'k'*32), my_mode)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode is None


def test_cipher_with_unresolvable_mode_call_emits_algorithm_without_mode() -> None:
    # mode arg is a Call but its callee is not in the import map — mode is None.
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms\n"
        "Cipher(algorithms.AES(b'k'*32), custom_mode())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode is None


def test_rsa_extracts_key_size() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 2048


def test_rsa_without_key_size_kwarg_emits_none() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=size)\n"
    )
    findings = _scan(src)
    assert findings[0].key_size is None


def test_ec_extracts_curve_name() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(curve=ec.SECP256R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "SECP256R1"


def test_ec_with_positional_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP384R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "SECP384R1"


def test_ec_with_no_args_returns_no_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key()\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve is None


def test_ec_with_non_call_curve_kwarg_returns_no_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(curve=some_variable)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve is None


def test_ec_with_unqualified_curve_name() -> None:
    # curve=SECP256R1() — no module qualifier, func is ast.Name not ast.Attribute
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1\n"
        "ec.generate_private_key(curve=SECP256R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "SECP256R1"


def test_key_size_kwarg_with_non_int_constant_emits_none() -> None:
    # key_size=2048.0 is a Constant but not an int — treated as non-literal.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048.0)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_key_size_kwarg_with_bool_emits_none() -> None:
    # bool is an int subclass; the extractor must not surface key_size=1 for True.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=True)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_pycryptodome_rsa_positional_key_size_extracted() -> None:
    # pycryptodome uses positional `bits` instead of a key_size kwarg.
    findings = _scan(
        "from Crypto.PublicKey import RSA\nRSA.generate(2048)\n"
    )
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA"
    assert findings[0].key_size == 2048


def test_pycryptodome_dsa_positional_key_size_extracted() -> None:
    findings = _scan(
        "from Crypto.PublicKey import DSA\nDSA.generate(3072)\n"
    )
    assert len(findings) == 1
    assert findings[0].algorithm == "DSA"
    assert findings[0].key_size == 3072


def test_pycryptodome_rsa_positional_bool_first_arg_emits_none() -> None:
    # Same bool/int-subclass guard for the positional path.
    findings = _scan(
        "from Crypto.PublicKey import RSA\nRSA.generate(True)\n"
    )
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_pycryptodome_rsa_positional_non_constant_emits_none() -> None:
    findings = _scan(
        "from Crypto.PublicKey import RSA\nRSA.generate(bits_var)\n"
    )
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_pycryptodome_rsa_bits_keyword_extracted() -> None:
    findings = _scan("from Crypto.PublicKey import RSA\nRSA.generate(bits=2048)\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "RSA"
    assert findings[0].key_size == 2048


def test_pycryptodome_dsa_bits_keyword_extracted() -> None:
    findings = _scan("from Crypto.PublicKey import DSA\nDSA.generate(bits=3072)\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "DSA"
    assert findings[0].key_size == 3072


def test_pycryptodome_rsa_bits_keyword_bool_emits_none() -> None:
    findings = _scan("from Crypto.PublicKey import RSA\nRSA.generate(bits=True)\n")
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_cryptography_rsa_bits_keyword_is_ignored() -> None:
    # `bits=` is a pycryptodome convention; cryptography uses `key_size=`.
    # A bits=… kwarg passed to cryptography.rsa.generate_private_key must
    # NOT be picked up as key_size — that would surface a wrong field.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, bits=2048)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_sha224_quantum_risk_is_safe() -> None:
    # SHA-224 is detected by the catalog; ensure it surfaces as SAFE,
    # not UNKNOWN.
    findings = _scan("import hashlib\nhashlib.sha224(b'x')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "SHA-224"
    assert findings[0].quantum_risk is QuantumRisk.SAFE


def test_ec_with_other_kwarg_but_no_curve_kwarg_returns_no_curve() -> None:
    # keywords present but none is `curve` — loop exits without break, candidate stays None.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(backend=default_backend())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve is None


def test_ec_with_subscript_callee_curve_returns_no_curve() -> None:
    # curve=CURVES[0]() — func is ast.Subscript, neither Attribute nor Name.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(curve=CURVES[0]())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve is None


def test_detect_python_file_finds_md5(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    findings = detect_python_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
    assert findings[0].location.path == f


def test_detect_python_file_empty_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("", encoding="utf-8")
    assert detect_python_file(f) == []


def test_detect_python_file_syntax_error_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "broken.py"
    f.write_text("def (:\n", encoding="utf-8")
    assert detect_python_file(f) == []


def test_detect_python_file_too_large_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "huge.py"
    f.write_bytes(b"# pad\n" * (400 * 1024))  # ~2.4 MiB
    assert detect_python_file(f) == []


def test_detect_python_file_latin1_fallback(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    # Latin-1 byte 0xe9 ('é') is invalid UTF-8 start byte alone.
    f.write_bytes(b"# coment\xe9\nimport hashlib\nhashlib.md5(b'x')\n")
    findings = detect_python_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detect_python_file_honors_pep263_cp1252_cookie(tmp_path: Path) -> None:
    # Regression for #11: a CP1252-specific byte (0x82 = curly single quote)
    # mid-string is not valid UTF-8 and would be misdecoded as Latin-1
    # without the PEP 263 cookie. The cookie wins, the source decodes
    # correctly, and the crypto call is still detected.
    f = tmp_path / "legacy.py"
    f.write_bytes(
        b"# -*- coding: cp1252 -*-\n"
        b"_label = 'doesn\x82t'\n"
        b"import hashlib\n"
        b"hashlib.md5(b'x')\n"
    )
    findings = detect_python_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detect_python_file_invalid_pep263_cookie_falls_back(tmp_path: Path) -> None:
    # `# coding: bogus-encoding` is a syntactically valid cookie but the
    # codec is unknown — LookupError on decode forces the latin-1 fallback.
    f = tmp_path / "bad_cookie.py"
    f.write_bytes(
        b"# coding: bogus-encoding\n"
        b"import hashlib\n"
        b"hashlib.md5(b'x')\n"
    )
    findings = detect_python_file(f)
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"


def test_detect_python_file_binary_content_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    # Binary bytes decode in latin-1 but the resulting text is unparseable;
    # the SyntaxError guard — not the encoding fallback — is what fires.
    f.write_bytes(b"\xff\xfe\xfd not python at all \x00\x01\x02")
    assert detect_python_file(f) == []


def test_detect_python_file_missing_returns_empty(tmp_path: Path) -> None:
    assert detect_python_file(tmp_path / "nope.py") == []


def test_detect_python_file_rejects_symlink_to_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "real.py"
    target.write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    link = tmp_path / "link.py"
    link.symlink_to(target)
    assert detect_python_file(link) == []


def test_detect_python_file_rejects_symlink_to_dev_zero(tmp_path: Path) -> None:
    # Regression for #3: stat() on a symlink follows it and reports st_size=0
    # for /dev/zero; the subsequent read_bytes() then blocks forever. The
    # O_NOFOLLOW open in detect_python_file must reject the symlink before
    # any read happens.
    if not Path("/dev/zero").exists():
        pytest.skip("/dev/zero unavailable on this platform")
    link = tmp_path / "zero.py"
    link.symlink_to("/dev/zero")
    assert detect_python_file(link) == []


def test_detect_python_file_rejects_fifo(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.py"
    os.mkfifo(fifo)
    assert detect_python_file(fifo) == []


def test_detect_python_file_rejects_directory(tmp_path: Path) -> None:
    d = tmp_path / "dir.py"
    d.mkdir()
    assert detect_python_file(d) == []


def test_detect_python_file_caps_growth_during_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regression for #12: even if fstat reports a small size, a read that
    # returns more bytes than the cap (file grew between fstat and read)
    # must be rejected, not OOM the process.
    f = tmp_path / "x.py"
    f.write_text("# small\n", encoding="utf-8")
    big = b"a" * 65536

    def fake_read(fd: int, n: int) -> bytes:
        return big[:n]

    monkeypatch.setattr(
        "pqcheck.detectors.python_detector.os.read",
        fake_read,
    )
    assert detect_python_file(f) == []
