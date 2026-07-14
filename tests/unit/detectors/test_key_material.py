"""Tests for the key-material detector (certificates and keys on disk).

Fixtures are generated at test time with pyca `cryptography` and written to
`tmp_path` — never committed key/cert bytes, per the project's secret-scanner
constraint. Key/cert *construction* itself is routed through
`tests/fixtures/keymaterial.py` (see that module's docstring): it is excluded
from pqcheck's own self-audit, whereas this test file is not, and genuine RSA/
EC/EdDSA key generation written directly here would otherwise trip pqcheck's
self-audit on its own test suite.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, x448, x25519

from pqcheck.detectors.key_material import detect_key_material_file
from pqcheck.models import AlgorithmFamily, QuantumRisk
from tests.fixtures import keymaterial


def test_pem_rsa_certificate_is_classified_like_rsa_code_usage(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    cert = keymaterial.self_signed_cert(key)
    path = tmp_path / "server.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.family == AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    assert finding.key_size == 2048
    assert finding.quantum_risk == QuantumRisk.VULNERABLE
    assert finding.material_kind == "certificate"
    assert finding.cert_format == "PEM"
    assert finding.confidence == 1.0
    assert finding.location.path == path
    assert finding.location.line == 1


def test_pem_ec_certificate_captures_curve(tmp_path: Path) -> None:
    key = keymaterial.ec_key(ec.SECP256R1())
    cert = keymaterial.self_signed_cert(key)
    path = tmp_path / "ec.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "ECDSA"
    assert finding.family == AlgorithmFamily.SIGNATURE
    assert finding.curve == "P-256"
    assert finding.material_kind == "certificate"


def test_cert_chain_emits_one_finding_per_block_at_begin_line(tmp_path: Path) -> None:
    leaf_key = keymaterial.rsa_key(2048)
    ca_key = keymaterial.rsa_key(3072)
    leaf = keymaterial.self_signed_cert(leaf_key, common_name="leaf")
    ca = keymaterial.self_signed_cert(ca_key, common_name="ca")
    blob = (
        b"# a comment line before the chain\n"
        + leaf.public_bytes(serialization.Encoding.PEM)
        + ca.public_bytes(serialization.Encoding.PEM)
    )
    path = tmp_path / "chain.pem"
    path.write_bytes(blob)

    findings = detect_key_material_file(path)
    assert [f.key_size for f in findings] == [2048, 3072]
    assert all(f.material_kind == "certificate" for f in findings)
    # Second block's BEGIN header must not be on line 1 -- confirms per-block
    # line tracking rather than always reporting the file's first line.
    assert findings[0].location.line == 2
    assert findings[1].location.line > findings[0].location.line


def test_pem_private_key_is_related_crypto_material(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "server.key"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.family == AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    assert finding.key_size == 2048
    assert finding.material_kind == "private-key"
    assert finding.confidence == 1.0


def test_pem_public_key(tmp_path: Path) -> None:
    key = keymaterial.ed25519_key()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "id.pem"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "EdDSA"
    assert finding.curve == "Ed25519"
    assert finding.material_kind == "public-key"


def test_ed448_public_key(tmp_path: Path) -> None:
    key = keymaterial.ed448_key()
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "id.pem"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "EdDSA"
    assert finding.curve == "Ed448"
    assert finding.material_kind == "public-key"


def test_dsa_private_key_maps_to_signature_family(tmp_path: Path) -> None:
    key = dsa.generate_private_key(key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "dsa.key"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "DSA"
    assert finding.family == AlgorithmFamily.SIGNATURE


def test_x25519_private_key_maps_to_key_agreement(tmp_path: Path) -> None:
    key = x25519.X25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "x25519.key"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "X25519"
    assert finding.family == AlgorithmFamily.KEY_AGREEMENT


def test_x448_private_key_maps_to_key_agreement(tmp_path: Path) -> None:
    key = x448.X448PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "x448.key"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "X448"
    assert finding.family == AlgorithmFamily.KEY_AGREEMENT


def test_certificate_header_with_corrupted_body_is_header_only(tmp_path: Path) -> None:
    path = tmp_path / "broken.crt"
    path.write_bytes(b"-----BEGIN CERTIFICATE-----\nTk9UQVJFQUw=\n-----END CERTIFICATE-----\n")

    [finding] = detect_key_material_file(path)
    assert finding.material_kind == "certificate"
    assert finding.algorithm == "UNKNOWN"
    assert finding.confidence < 0.5


def test_public_key_header_with_corrupted_body_is_header_only(tmp_path: Path) -> None:
    path = tmp_path / "broken-pub.pem"
    path.write_bytes(b"-----BEGIN PUBLIC KEY-----\nTk9UQVJFQUw=\n-----END PUBLIC KEY-----\n")

    [finding] = detect_key_material_file(path)
    assert finding.material_kind == "public-key"
    assert finding.algorithm == "UNKNOWN"
    assert finding.confidence < 0.5


def test_unrecognized_pem_header_is_silent(tmp_path: Path) -> None:
    # CERTIFICATE REQUEST (a CSR) is a real OpenSSL header this detector does
    # not claim to understand -- it must not be misreported as a cert/key.
    path = tmp_path / "req.pem"
    path.write_bytes(
        b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
    )
    assert detect_key_material_file(path) == []


def test_der_private_key(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    der = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path = tmp_path / "server.der"
    path.write_bytes(der)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.material_kind == "private-key"


def test_der_public_key(tmp_path: Path) -> None:
    key = keymaterial.ec_key(ec.SECP384R1())
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    path = tmp_path / "server.der"
    path.write_bytes(der)

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "ECDSA"
    assert finding.curve == "P-384"
    assert finding.material_kind == "public-key"


def test_pem_extension_holding_raw_der_falls_back_to_der_parse(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    cert = keymaterial.self_signed_cert(key)
    path = tmp_path / "raw.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.cert_format == "DER"


def test_der_certificate(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    cert = keymaterial.self_signed_cert(key)
    path = tmp_path / "server.der"
    path.write_bytes(cert.public_bytes(serialization.Encoding.DER))

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.cert_format == "DER"
    assert finding.material_kind == "certificate"
    assert finding.location.line == 1


def test_encrypted_private_key_falls_back_to_low_confidence_header_only(
    tmp_path: Path,
) -> None:
    key = keymaterial.rsa_key(2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"a-test-password-not-a-secret"),
    )
    path = tmp_path / "encrypted.key"
    path.write_bytes(pem)

    [finding] = detect_key_material_file(path)
    assert finding.material_kind == "private-key"
    assert finding.confidence < 0.5
    assert finding.algorithm == "UNKNOWN"


def test_legacy_rsa_header_with_corrupted_body_still_names_rsa_at_low_confidence(
    tmp_path: Path,
) -> None:
    # Truncated/garbage body -- the label alone still lets us say "RSA".
    path = tmp_path / "broken.key"
    path.write_bytes(
        b"-----BEGIN RSA PRIVATE KEY-----\nTk9UQVJFQUxLRVk=\n-----END RSA PRIVATE KEY-----\n"
    )

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.family == AlgorithmFamily.ASYMMETRIC_ENCRYPTION
    assert finding.material_kind == "private-key"
    assert finding.confidence < 0.5


def test_truncated_typed_header_without_end_marker_falls_back_to_header_only(
    tmp_path: Path,
) -> None:
    # BEGIN with no matching END at all -- a severely truncated file. The
    # legacy RSA header still names the algorithm at low confidence, same as
    # a complete-but-corrupted block.
    path = tmp_path / "truncated.key"
    path.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nMIIEow")

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "RSA"
    assert finding.material_kind == "private-key"
    assert finding.confidence < 0.5


def test_truncated_agnostic_header_without_end_marker_falls_back_to_unknown(
    tmp_path: Path,
) -> None:
    path = tmp_path / "truncated.pem"
    path.write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIEow")

    [finding] = detect_key_material_file(path)
    assert finding.algorithm == "UNKNOWN"
    assert finding.material_kind == "certificate"
    assert finding.confidence < 0.5


def test_truncated_unrecognized_header_without_end_marker_stays_silent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "truncated-req.pem"
    path.write_bytes(b"-----BEGIN CERTIFICATE REQUEST-----\nMIIEow")

    assert detect_key_material_file(path) == []


def test_truncated_begin_after_complete_block_does_not_double_report(
    tmp_path: Path,
) -> None:
    # A complete block followed by a second, truncated BEGIN: the complete
    # block reports normally through the ordinary parse path, and the
    # truncated tail reports once via the header-only fallback -- never
    # both paths firing for the same BEGIN.
    key = keymaterial.rsa_key(2048)
    cert = keymaterial.self_signed_cert(key)
    blob = cert.public_bytes(serialization.Encoding.PEM) + b"-----BEGIN RSA PRIVATE KEY-----\nMII"
    path = tmp_path / "mixed.pem"
    path.write_bytes(blob)

    findings = detect_key_material_file(path)
    assert len(findings) == 2
    assert findings[0].material_kind == "certificate"
    assert findings[0].confidence == 1.0
    assert findings[1].material_kind == "private-key"
    assert findings[1].algorithm == "RSA"
    assert findings[1].confidence < 0.5


def test_complete_block_is_unaffected_by_begin_only_fallback(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    cert = keymaterial.self_signed_cert(key)
    path = tmp_path / "server.pem"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    findings = detect_key_material_file(path)
    assert len(findings) == 1
    assert findings[0].confidence == 1.0


def test_no_header_and_no_parse_is_silent(tmp_path: Path) -> None:
    path = tmp_path / "not-a-key.pem"
    path.write_bytes(b"just some random text, no PEM markers at all\n")
    assert detect_key_material_file(path) == []


def test_der_garbage_is_silent(tmp_path: Path) -> None:
    path = tmp_path / "garbage.der"
    path.write_bytes(b"\x00\x01\x02\x03not a real der blob" * 4)
    assert detect_key_material_file(path) == []


def test_missing_file_is_silent(tmp_path: Path) -> None:
    assert detect_key_material_file(tmp_path / "nope.pem") == []


def test_oversized_file_is_skipped(tmp_path: Path) -> None:
    key = keymaterial.rsa_key(2048)
    cert = keymaterial.self_signed_cert(key)
    pem = cert.public_bytes(serialization.Encoding.PEM)
    path = tmp_path / "huge.pem"
    # Pad well past the size cap with comment bytes outside any PEM block.
    path.write_bytes(pem + b"#" * (2 * 1024 * 1024))
    assert detect_key_material_file(path) == []


def test_symlink_is_skipped(tmp_path: Path) -> None:
    real = tmp_path / "real.pem"
    real.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    link = tmp_path / "link.pem"
    link.symlink_to(real)
    assert detect_key_material_file(link) == []
