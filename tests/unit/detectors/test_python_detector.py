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
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'k' * 16, some_module.MODE_ECB)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].mode is None


def test_detector_pycryptodome_non_attribute_mode_emits_none() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'k' * 16, some_mode)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].mode is None


def test_detector_pycryptodome_no_mode_arg_emits_none() -> None:
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


def test_detector_finds_hashlib_new_dashed_sha1_alias() -> None:
    findings = _scan("import hashlib\nhashlib.new('sha-1')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "SHA-1"
    assert findings[0].confidence == 0.7


def test_detector_finds_hashlib_new_uppercase_dashed_sha256_alias() -> None:
    findings = _scan("import hashlib\nhashlib.new('SHA-256')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "SHA-256"


def test_detector_finds_hashlib_new_dashed_sha3_alias() -> None:
    findings = _scan("import hashlib\nhashlib.new('sha3-256')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "SHA3-256"


def test_detector_ignores_unknown_hashlib_new_literal() -> None:
    findings = _scan("import hashlib\nhashlib.new('shake_128')\n")
    assert findings == []


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
    assert findings[0].curve == "P-256"


def test_ec_with_positional_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP384R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "P-384"


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
    assert findings[0].curve == "P-256"


def test_ec_secp256k1_keeps_policy_spelling() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.SECP256K1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "secp256k1"


def test_ec_unknown_curve_passes_through_unchanged() -> None:
    # A curve with no policy spelling keeps its library name rather than
    # silently dropping the information.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "ec.generate_private_key(ec.BrainpoolP256R1())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "BrainpoolP256R1"


def test_ecdh_exchange_marker_is_detected() -> None:
    # Standalone NIST-curve ECDH is invoked as key.exchange(ec.ECDH(), peer).
    # The ec.ECDH() marker is detectable at the call site without dataflow,
    # so it is flagged as key-agreement even when keygen labels the key ECDSA.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "shared = private_key.exchange(ec.ECDH(), peer_public_key)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "ECDH"
    assert findings[0].family is AlgorithmFamily.KEY_AGREEMENT
    assert findings[0].quantum_risk is QuantumRisk.VULNERABLE


def test_pycryptodome_ecc_string_curve_normalized() -> None:
    # pycryptodome takes the curve as a string (ECC.generate(curve="p256")),
    # not a class instance like `cryptography`. Normalize it to policy vocab.
    src = (
        "from Crypto.PublicKey import ECC\n"
        "ECC.generate(curve='p256')\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "ECDSA"
    assert findings[0].curve == "P-256"


def test_pycryptodome_ecc_unknown_string_curve_passes_through() -> None:
    src = (
        "from Crypto.PublicKey import ECC\n"
        "ECC.generate(curve='brainpoolP256r1')\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].curve == "brainpoolP256r1"


def test_ed25519_emits_eddsa_with_curve() -> None:
    # Policy bans `algorithm: EdDSA` with `curves: [Ed25519, Ed448]`. The
    # detector must speak that vocabulary so the eventual engine can match.
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ed25519\n"
        "ed25519.Ed25519PrivateKey.generate()\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "EdDSA"
    assert f.curve == "Ed25519"
    assert f.family is AlgorithmFamily.SIGNATURE
    assert f.quantum_risk is QuantumRisk.VULNERABLE


def test_ed448_emits_eddsa_with_curve() -> None:
    src = (
        "from cryptography.hazmat.primitives.asymmetric import ed448\n"
        "ed448.Ed448PrivateKey.generate()\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    f = findings[0]
    assert f.algorithm == "EdDSA"
    assert f.curve == "Ed448"
    assert f.family is AlgorithmFamily.SIGNATURE
    assert f.quantum_risk is QuantumRisk.VULNERABLE


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


def test_aes_wrapper_extracts_key_size_from_repeated_bytes_literal() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'k' * 32), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].key_size == 256


def test_aes_wrapper_extracts_128_from_16_byte_key() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(b'0123456789abcdef'), modes.ECB())\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 128


def test_aes128_class_reports_128_regardless_of_key() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES128(some_key), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 128


def test_aes256_class_reports_256_regardless_of_key() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES256(some_key), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 256


def test_pycryptodome_aes_extracts_key_size_from_key_literal() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(b'\\x00' * 16, AES.MODE_GCM)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].algorithm == "AES"
    assert findings[0].key_size == 128


def test_aes_wrapper_extracts_key_size_from_key_keyword() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(key=b'k' * 32), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 256


def test_pycryptodome_aes_extracts_key_size_from_key_keyword() -> None:
    src = (
        "from Crypto.Cipher import AES\n"
        "AES.new(key=b'k' * 16, mode=AES.MODE_GCM, nonce=b'n' * 12)\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size == 128


def test_aes_with_non_literal_key_emits_none() -> None:
    src = (
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "Cipher(algorithms.AES(key_from_kms), modes.GCM(b'i' * 12))\n"
    )
    findings = _scan(src)
    assert len(findings) == 1
    assert findings[0].key_size is None


def test_hash_input_bytes_not_misread_as_key_size() -> None:
    # hashlib.md5(b"data") — the bytes arg is hash input, not a key. The AES
    # extractor must not fire for non-AES symbols.
    findings = _scan("import hashlib\nhashlib.md5(b'sensitive data')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
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


def test_detect_python_file_deep_expression_returns_empty(tmp_path: Path) -> None:
    # A long operator chain (~117 KiB, well under the 2 MiB cap) recurses the
    # parser past sys.getrecursionlimit() and raises RecursionError — not a
    # SyntaxError. The detector must swallow it like any other unparseable file.
    f = tmp_path / "deep.py"
    f.write_text("x = a" + "+a" * 60_000 + "\n", encoding="utf-8")
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
    # Regression: stat() follows a symlink and reports st_size=0 for
    # /dev/zero; a later read would block forever.
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


def test_star_import_emits_finding_with_demoted_confidence() -> None:
    findings = _scan("from hashlib import *\nmd5(b'x')\n")
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
    assert findings[0].confidence == 0.7


def test_star_import_resolves_short_name_from_cryptography_hashes() -> None:
    findings = _scan(
        "from cryptography.hazmat.primitives.hashes import *\nMD5()\n"
    )
    assert len(findings) == 1
    assert findings[0].algorithm == "MD5"
    assert findings[0].confidence == 0.7


def test_star_import_safe_when_module_not_catalogued() -> None:
    findings = _scan("from os import *\ngetcwd()\n")
    assert findings == []


def test_star_import_unrelated_short_name_emits_nothing() -> None:
    findings = _scan("from hashlib import *\nnot_a_hash(b'x')\n")
    assert findings == []


def test_star_import_does_not_emit_cipher_wrapper_marker() -> None:
    findings = _scan(
        "from cryptography.hazmat.primitives.ciphers import *\n"
        "Cipher(some_algo, some_mode)\n"
    )
    assert findings == []


def test_star_import_does_not_double_emit_with_direct_call() -> None:
    findings = _scan(
        "import hashlib\nfrom hashlib import *\nhashlib.md5(b'x')\n"
    )
    assert len(findings) == 1
    assert findings[0].confidence == 1.0
