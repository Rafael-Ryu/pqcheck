"""Key-material detector: certificates and keys sitting on disk as files.

Scans `*.pem`/`*.crt` (text, one or more PEM blocks — a cert chain splits
into one finding per block) and `*.key`/`*.der` (either PEM or a single raw
DER blob) for certificates, private keys, and public keys. Parsing goes
through pyca `cryptography`'s loaders; the resulting canonical algorithm
names (RSA, ECDSA, EdDSA, DSA, X25519, X448) are the same ones the Python/Go
source detectors emit, so an RSA-2048 certificate is classified by policy
identically to an RSA-2048 code usage finding.

When a block fails every loader (encrypted key, unsupported/legacy params,
corrupted body), or a BEGIN marker has no matching END at all (a severely
truncated file), but carries a recognizable PEM header, a lower-confidence
finding is still emitted — the header alone names the algorithm for the
legacy RSA/EC/DSA headers, and stays UNKNOWN for the algorithm-agnostic
PKCS8/SPKI/certificate headers. No header and no successful parse means
silent skip: this module never raises and never reports on a hostile or
irrelevant file, matching the scanner's never-raise contract.
"""

from __future__ import annotations

import re
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Literal, cast

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

from pqcheck.detectors._source_read import read_source_bytes
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation

_DETECTOR_ID = "key-material"

# Key/cert files are small by nature; a multi-megabyte .pem/.der is either a
# certificate bundle far larger than any real chain or an unrelated blob that
# happens to carry one of the watched extensions. Capped well below the
# 2 MiB general source cap in _source_read.py.
_MAX_KEY_MATERIAL_BYTES = 1 * 1024 * 1024

# Confidence for a header-only fallback finding (no successful parse). Below
# the policy engine's MEDIUM band threshold (0.5) by design -- these are
# name-only signals (encrypted key, corrupted body, unsupported params), not
# a verified attestation of the material's shape.
_HEADER_ONLY_CONFIDENCE = 0.3

_PARSE_EXCEPTIONS = (ValueError, TypeError, UnsupportedAlgorithm)

_PEM_BLOCK_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", re.DOTALL)

# A BEGIN marker with no matching END at all -- e.g. a severely truncated
# file cut off mid-body. Used only to find BEGIN headers _PEM_BLOCK_RE left
# unmatched (see _detect_pem_blocks); a BEGIN that IS part of a complete
# block is already reported through the ordinary parse path above.
_PEM_BEGIN_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")

# Legacy/typed PEM headers that name their algorithm outright, used only by
# the header-only fallback path (a successful parse asks the parsed key
# object directly instead of trusting the label).
_HEADER_PRIVATE_KEY_ALGORITHMS: dict[bytes, tuple[str, AlgorithmFamily]] = {
    b"RSA PRIVATE KEY": ("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION),
    b"EC PRIVATE KEY": ("ECDSA", AlgorithmFamily.SIGNATURE),
    b"DSA PRIVATE KEY": ("DSA", AlgorithmFamily.SIGNATURE),
}
_HEADER_PUBLIC_KEY_ALGORITHMS: dict[bytes, tuple[str, AlgorithmFamily]] = {
    b"RSA PUBLIC KEY": ("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION),
}
_PRIVATE_KEY_LABELS = frozenset({
    b"PRIVATE KEY", b"ENCRYPTED PRIVATE KEY", *_HEADER_PRIVATE_KEY_ALGORITHMS,
})
_PUBLIC_KEY_LABELS = frozenset({b"PUBLIC KEY", *_HEADER_PUBLIC_KEY_ALGORITHMS})
_CERTIFICATE_LABELS = frozenset({b"CERTIFICATE", b"X509 CERTIFICATE", b"TRUSTED CERTIFICATE"})

_EC_CURVE_CANONICAL = {
    "secp256r1": "P-256",
    "secp384r1": "P-384",
    "secp521r1": "P-521",
    "secp256k1": "secp256k1",
}


class _Classification:
    __slots__ = ("algorithm", "curve", "family", "key_size")

    def __init__(
        self,
        algorithm: str,
        family: AlgorithmFamily,
        key_size: int | None = None,
        curve: str | None = None,
    ) -> None:
        self.algorithm = algorithm
        self.family = family
        self.key_size = key_size
        self.curve = curve


def _classify_rsa(key: rsa.RSAPrivateKey | rsa.RSAPublicKey) -> _Classification:
    return _Classification("RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, key.key_size)


def _classify_dsa(key: dsa.DSAPrivateKey | dsa.DSAPublicKey) -> _Classification:
    return _Classification("DSA", AlgorithmFamily.SIGNATURE, key.key_size)


def _classify_ec(
    key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey,
) -> _Classification:
    curve = _EC_CURVE_CANONICAL.get(key.curve.name, key.curve.name)
    return _Classification("ECDSA", AlgorithmFamily.SIGNATURE, key.curve.key_size, curve)


_Classifier = Callable[[object], _Classification]

# (type tuple, classifier) pairs tried in order. A plain lookup table (rather
# than a chain of isinstance/return statements) keeps _classify_key's
# cyclomatic complexity low as more key types are added.
_KEY_TYPE_CLASSIFIERS: tuple[tuple[tuple[type, ...], _Classifier], ...] = (
    ((rsa.RSAPrivateKey, rsa.RSAPublicKey), cast("_Classifier", _classify_rsa)),
    ((dsa.DSAPrivateKey, dsa.DSAPublicKey), cast("_Classifier", _classify_dsa)),
    (
        (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey),
        cast("_Classifier", _classify_ec),
    ),
    (
        (ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey),
        lambda _k: _Classification("EdDSA", AlgorithmFamily.SIGNATURE, curve="Ed25519"),
    ),
    (
        (ed448.Ed448PrivateKey, ed448.Ed448PublicKey),
        lambda _k: _Classification("EdDSA", AlgorithmFamily.SIGNATURE, curve="Ed448"),
    ),
    (
        (x25519.X25519PrivateKey, x25519.X25519PublicKey),
        lambda _k: _Classification("X25519", AlgorithmFamily.KEY_AGREEMENT),
    ),
    (
        (x448.X448PrivateKey, x448.X448PublicKey),
        lambda _k: _Classification("X448", AlgorithmFamily.KEY_AGREEMENT),
    ),
)


def _classify_key(key: object) -> _Classification | None:
    """Map a parsed pyca key object (public or private) to its canonical."""
    for types, classifier in _KEY_TYPE_CLASSIFIERS:
        if isinstance(key, types):
            return classifier(key)
    return None  # pragma: no cover - defensive; every pyca key type is covered above


def _line_at(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, offset) + 1


def _cert_finding(
    cert: x509.Certificate,
    *,
    path: Path,
    line: int,
    cert_format: Literal["PEM", "DER"],
    confidence: float,
) -> CryptoFinding:
    classification = _classify_key(cert.public_key()) or _Classification(
        "UNKNOWN", AlgorithmFamily.SIGNATURE
    )
    # pyca emits UserWarning for X.509 attributes with nonstandard lengths;
    # hostile certificates would otherwise spray those onto stderr once per
    # rfc4514 conversion. The values still convert — only the noise is muted.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
    return CryptoFinding(
        algorithm=classification.algorithm,
        family=classification.family,
        key_size=classification.key_size,
        curve=classification.curve,
        location=SourceLocation(path=path, line=line, column=0),
        evidence=f"certificate CN-ish subject={subject}",
        detector_id=_DETECTOR_ID,
        confidence=confidence,
        material_kind="certificate",
        cert_subject=subject,
        cert_issuer=issuer,
        cert_not_valid_before=cert.not_valid_before_utc.isoformat(),
        cert_not_valid_after=cert.not_valid_after_utc.isoformat(),
        cert_format=cert_format,
    )


def _key_finding(
    key: object,
    *,
    path: Path,
    line: int,
    material_kind: Literal["private-key", "public-key"],
    confidence: float,
    evidence: str,
) -> CryptoFinding | None:
    classification = _classify_key(key)
    if classification is None:
        return None  # pragma: no cover - every pyca key type _classify_key handles
    return CryptoFinding(
        algorithm=classification.algorithm,
        family=classification.family,
        key_size=classification.key_size,
        curve=classification.curve,
        location=SourceLocation(path=path, line=line, column=0),
        evidence=evidence,
        detector_id=_DETECTOR_ID,
        confidence=confidence,
        material_kind=material_kind,
    )


def _header_only_finding(
    label: bytes, *, path: Path, line: int, evidence: str
) -> CryptoFinding | None:
    if label in _CERTIFICATE_LABELS:
        return CryptoFinding(
            algorithm="UNKNOWN",
            family=AlgorithmFamily.SIGNATURE,
            location=SourceLocation(path=path, line=line, column=0),
            evidence=evidence,
            detector_id=_DETECTOR_ID,
            confidence=_HEADER_ONLY_CONFIDENCE,
            material_kind="certificate",
            cert_format="PEM",
        )
    if label in _PRIVATE_KEY_LABELS:
        algorithm, family = _HEADER_PRIVATE_KEY_ALGORITHMS.get(
            label, ("UNKNOWN", AlgorithmFamily.SIGNATURE)
        )
        return CryptoFinding(
            algorithm=algorithm,
            family=family,
            location=SourceLocation(path=path, line=line, column=0),
            evidence=evidence,
            detector_id=_DETECTOR_ID,
            confidence=_HEADER_ONLY_CONFIDENCE,
            material_kind="private-key",
        )
    if label in _PUBLIC_KEY_LABELS:
        algorithm, family = _HEADER_PUBLIC_KEY_ALGORITHMS.get(
            label, ("UNKNOWN", AlgorithmFamily.SIGNATURE)
        )
        return CryptoFinding(
            algorithm=algorithm,
            family=family,
            location=SourceLocation(path=path, line=line, column=0),
            evidence=evidence,
            detector_id=_DETECTOR_ID,
            confidence=_HEADER_ONLY_CONFIDENCE,
            material_kind="public-key",
        )
    return None


def _detect_pem_block(block: bytes, label: bytes, *, path: Path, line: int) -> CryptoFinding | None:
    evidence = f"PEM block {label.decode('ascii', errors='replace')}"
    try:
        cert = x509.load_pem_x509_certificate(block)
    except _PARSE_EXCEPTIONS:
        pass
    else:
        return _cert_finding(cert, path=path, line=line, cert_format="PEM", confidence=1.0)

    try:
        private_key = serialization.load_pem_private_key(block, password=None)
    except _PARSE_EXCEPTIONS:
        pass
    else:
        return _key_finding(
            private_key,
            path=path,
            line=line,
            material_kind="private-key",
            confidence=1.0,
            evidence=evidence,
        )

    try:
        public_key = serialization.load_pem_public_key(block)
    except _PARSE_EXCEPTIONS:
        pass
    else:
        return _key_finding(
            public_key,
            path=path,
            line=line,
            material_kind="public-key",
            confidence=1.0,
            evidence=evidence,
        )

    return _header_only_finding(label, path=path, line=line, evidence=evidence)


def _detect_pem_blocks(data: bytes, path: Path) -> list[CryptoFinding]:
    findings: list[CryptoFinding] = []
    consumed: list[tuple[int, int]] = []
    for match in _PEM_BLOCK_RE.finditer(data):
        label = match.group(1)
        line = _line_at(data, match.start())
        consumed.append((match.start(), match.end()))
        finding = _detect_pem_block(match.group(0), label, path=path, line=line)
        if finding is not None:
            findings.append(finding)
    for match in _PEM_BEGIN_RE.finditer(data):
        # Skip a BEGIN that's already part of a complete block matched above
        # -- only a BEGIN with no matching END reaches the fallback below.
        if any(start <= match.start() < end for start, end in consumed):
            continue
        label = match.group(1)
        line = _line_at(data, match.start())
        evidence = f"PEM block {label.decode('ascii', errors='replace')} (truncated, no END marker)"
        finding = _header_only_finding(label, path=path, line=line, evidence=evidence)
        if finding is not None:
            findings.append(finding)
    return findings


def _detect_der_blob(data: bytes, path: Path) -> list[CryptoFinding]:
    try:
        cert = x509.load_der_x509_certificate(data)
    except _PARSE_EXCEPTIONS:
        pass
    else:
        return [_cert_finding(cert, path=path, line=1, cert_format="DER", confidence=1.0)]

    try:
        private_key = serialization.load_der_private_key(data, password=None)
    except _PARSE_EXCEPTIONS:
        pass
    else:
        finding = _key_finding(
            private_key,
            path=path,
            line=1,
            material_kind="private-key",
            confidence=1.0,
            evidence="DER private key",
        )
        return [finding] if finding is not None else []

    try:
        public_key = serialization.load_der_public_key(data)
    except _PARSE_EXCEPTIONS:
        pass
    else:
        finding = _key_finding(
            public_key,
            path=path,
            line=1,
            material_kind="public-key",
            confidence=1.0,
            evidence="DER public key",
        )
        return [finding] if finding is not None else []

    return []  # no ASCII header exists for DER, so a total parse failure stays silent


def detect_key_material_file(path: Path) -> list[CryptoFinding]:
    """Detect certificates/keys in a `*.pem`/`*.key`/`*.crt`/`*.der` file.

    Never raises: unreadable/oversized/symlinked files (see
    `read_source_bytes`) and any parse failure both degrade to an empty list
    or, for a recognizable-but-unparseable PEM header, a lower-confidence
    finding — never an exception.
    """
    data = read_source_bytes(path, max_bytes=_MAX_KEY_MATERIAL_BYTES)
    if data is None:
        return []
    if path.suffix == ".der":
        return _detect_der_blob(data, path)
    findings = _detect_pem_blocks(data, path)
    if findings:
        return findings
    # A .key/.pem/.crt file with no PEM markers at all might still be raw DER
    # (some tooling writes DER under a .pem/.key extension) -- try that before
    # giving up silently.
    return _detect_der_blob(data, path)
