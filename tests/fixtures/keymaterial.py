"""Test-only key/cert generation helpers.

Lives under `tests/fixtures/` — already excluded from pqcheck's own
self-audit via `.pqcheckignore` ("fixtures contain banned crypto on
purpose"). Generating an RSA/EC/EdDSA private key directly inside a *test*
file would otherwise trip pqcheck's self-audit on its own test suite (the
Python detector correctly flags real key generation, not just the assertion
that it's detectable) — routing the construction calls through here keeps
that real, intentional crypto usage out of scanned test files.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
from cryptography.x509.oid import NameOID


def rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def ec_key(curve: EllipticCurve) -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(curve)


def ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def ed448_key() -> ed448.Ed448PrivateKey:
    return ed448.Ed448PrivateKey.generate()


def self_signed_cert(
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    *,
    common_name: str = "test",
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .sign(private_key, hashes.SHA256())
    )
