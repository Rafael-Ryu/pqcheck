from pathlib import Path

import pytest
from tree_sitter import Language, Node, Parser

import pqcheck.detectors.go_detector as _go_det
from pqcheck.detectors.go_detector import (
    GoDetector,
    GoImportResolver,
    detect_go_file,
)
from pqcheck.detectors.tree_sitter_loader import go_language
from pqcheck.models import AlgorithmFamily, QuantumRisk


def test_go_language_returns_a_language() -> None:
    assert isinstance(go_language(), Language)


def test_go_language_is_cached() -> None:
    assert go_language() is go_language()


def _parse(src: str) -> tuple[Node, bytes]:
    raw = src.encode("utf-8")
    return Parser(go_language()).parse(raw).root_node, raw


def _resolver(src: str) -> GoImportResolver:
    root, raw = _parse(src)
    r = GoImportResolver()
    r.visit_root(root, raw)
    return r


def test_plain_import_binds_last_path_segment() -> None:
    r = _resolver('package m\nimport "crypto/rsa"\n')
    assert r.resolve("rsa") == "crypto/rsa"


def test_aliased_import_binds_alias() -> None:
    r = _resolver('package m\nimport crand "crypto/rand"\n')
    assert r.resolve("crand") == "crypto/rand"
    assert r.resolve("rand") is None


def test_versioned_import_v2_binds_pre_suffix_segment() -> None:
    r = _resolver('package m\nimport "math/rand/v2"\n')
    assert r.resolve("rand") == "math/rand/v2"
    assert r.resolve("v2") is None


def test_versioned_import_v1_binds_literal_v1_segment() -> None:
    r = _resolver(
        'package m\nimport "github.com/google/go-containerregistry/pkg/v1"\n'
    )
    assert r.resolve("v1") == "github.com/google/go-containerregistry/pkg/v1"


def test_versioned_import_v10_binds_pre_suffix_segment() -> None:
    # Generic /vN handling: not hardcoded to v2.
    r = _resolver('package m\nimport "example.com/mod/sub/v10"\n')
    assert r.resolve("sub") == "example.com/mod/sub/v10"
    assert r.resolve("v10") is None


def test_grouped_imports_all_resolve() -> None:
    r = _resolver('package m\nimport (\n  "crypto/rsa"\n  "crypto/aes"\n)\n')
    assert r.resolve("rsa") == "crypto/rsa"
    assert r.resolve("aes") == "crypto/aes"


def test_dot_import_recorded_separately() -> None:
    r = _resolver('package m\nimport . "crypto/md5"\n')
    assert r.resolve("md5") is None
    assert r.dot_imports() == ("crypto/md5",)


def test_blank_import_ignored() -> None:
    r = _resolver('package m\nimport _ "crypto/sha1"\n')
    assert r.resolve("sha1") is None
    assert r.dot_imports() == ()


def _findings(src: str):
    root, raw = _parse(src)
    det = GoDetector(Path("mem.go"), raw)
    det.run(root)
    return det.findings


def test_detects_rsa_with_key_size() -> None:
    fs = _findings(
        'package m\nimport (\n "crypto/rsa"\n "crypto/rand"\n)\n'
        "func f() { rsa.GenerateKey(rand.Reader, 2048) }\n"
    )
    rsa = [f for f in fs if f.algorithm == "RSA"]
    assert len(rsa) == 1
    assert rsa[0].key_size == 2048
    assert rsa[0].detector_id == "go-tree-sitter"
    assert rsa[0].confidence == 1.0


def test_detects_ecdsa_curve_from_elliptic_arg() -> None:
    fs = _findings(
        'package m\nimport (\n "crypto/ecdsa"\n "crypto/elliptic"\n "crypto/rand"\n)\n'
        "func f() { ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }\n"
    )
    ec = [f for f in fs if f.algorithm == "ECDSA"]
    assert len(ec) == 1
    assert ec[0].curve == "P-256"


def test_detects_math_rand_as_rng() -> None:
    fs = _findings(
        'package m\nimport "math/rand"\nfunc f() { rand.Intn(10) }\n'
    )
    assert [f.algorithm for f in fs] == ["MATH-RAND"]
    assert fs[0].family == AlgorithmFamily.RNG
    assert fs[0].quantum_risk == QuantumRisk.BROKEN


def test_detects_math_rand_v2_as_rng() -> None:
    # math/rand/v2's declared package name is "rand" (Go's semantic import
    # versioning convention), not the "v2" path segment -- an unaliased
    # import binds "rand" at call sites, matching the real package clause.
    fs = _findings(
        'package m\nimport "math/rand/v2"\nfunc f() { rand.IntN(10) }\n'
    )
    assert [f.algorithm for f in fs] == ["MATH-RAND"]


def test_math_rand_v2_stray_alias_segment_does_not_resolve() -> None:
    # Confirms the old (wrong) binding no longer fires: nothing in real Go
    # source refers to this package as "v2".
    fs = _findings(
        'package m\nimport "math/rand/v2"\nfunc f() { v2.IntN(10) }\n'
    )
    assert fs == []


def test_v1_versioned_import_path_binds_literal_segment() -> None:
    # Go's semantic import versioning never applies to v0/v1 (only v2+), so a
    # trailing "/v1" is a real, literal package name -- e.g.
    # go-containerregistry's pkg/v1, whose package clause is `package v1`.
    fs = _findings(
        'package m\n'
        'import "github.com/google/go-containerregistry/pkg/v1"\n'
        'func f() { v1.SHA256(nil) }\n'
    )
    assert [f.algorithm for f in fs] == ["SHA-256"]


def test_math_rand_uint32_and_uint64_detected() -> None:
    fs = _findings(
        'package m\nimport "math/rand"\n'
        "func f() { rand.Uint32(); rand.Uint64() }\n"
    )
    assert [f.algorithm for f in fs] == ["MATH-RAND", "MATH-RAND"]
    assert all(f.family == AlgorithmFamily.RNG for f in fs)


def test_blake2s_sum256_detected() -> None:
    fs = _findings(
        'package m\nimport "golang.org/x/crypto/blake2s"\n'
        "func f() { blake2s.Sum256(nil) }\n"
    )
    assert [f.algorithm for f in fs] == ["BLAKE2S"]


def test_blake2b_sum_variants_detected() -> None:
    fs = _findings(
        'package m\nimport "golang.org/x/crypto/blake2b"\n'
        "func f() { blake2b.Sum256(nil); blake2b.Sum384(nil); blake2b.Sum512(nil) }\n"
    )
    assert [f.algorithm for f in fs] == ["BLAKE2B", "BLAKE2B", "BLAKE2B"]


def test_crypto_rand_is_not_flagged_as_math_rand() -> None:
    fs = _findings(
        'package m\nimport "crypto/rand"\nfunc f() { rand.Read(nil) }\n'
    )
    assert [f.algorithm for f in fs] == ["CSPRNG"]
    assert fs[0].quantum_risk == QuantumRisk.SAFE


def test_ecdh_curve_does_not_double_count() -> None:
    fs = _findings(
        'package m\nimport (\n "crypto/ecdh"\n "crypto/rand"\n)\n'
        "func f() { ecdh.P256().GenerateKey(rand.Reader) }\n"
    )
    assert [f.algorithm for f in fs] == ["ECDH"]
    assert fs[0].curve == "P-256"


def test_mlkem_carries_parameter_set_from_catalog() -> None:
    # crypto/mlkem bakes the parameter set into the function name, so the
    # catalog carries it as key_size — without it the finding cannot match
    # the policy's parameter-sets approved rule and falls to default/medium
    # instead of approved/info (issue #217; same fix as the Python catalog
    # in #216).
    fs = _findings(
        'package m\nimport "crypto/mlkem"\n'
        "func f() { mlkem.GenerateKey768(); mlkem.GenerateKey1024() }\n"
    )
    assert [(f.algorithm, f.key_size) for f in fs] == [
        ("ML-KEM", 768),
        ("ML-KEM", 1024),
    ]
    assert all(f.quantum_risk == QuantumRisk.SAFE for f in fs)


def test_elliptic_p256_emits_own_finding() -> None:
    # elliptic.P256() called bare (not as an ecdsa.GenerateKey argument) is
    # a call_expression in its own right and resolves independently — the
    # curve object is usable for either ECDSA or ECDH, so the family is the
    # deliberately-ambiguous ELLIPTIC_CURVE, not signature/key-agreement.
    fs = _findings(
        'package m\nimport "crypto/elliptic"\nfunc f() { elliptic.P256() }\n'
    )
    assert [f.algorithm for f in fs] == ["ECC"]
    assert fs[0].family == AlgorithmFamily.ELLIPTIC_CURVE
    assert fs[0].curve == "P-256"
    assert fs[0].quantum_risk == QuantumRisk.VULNERABLE


def test_elliptic_p256_as_ecdsa_arg_emits_both_findings() -> None:
    # elliptic.P256() nested inside ecdsa.GenerateKey(...) is still its own
    # call_expression node, so it is visited (and emits) independently of
    # the outer ECDSA finding that also captures the curve via its first arg.
    fs = _findings(
        'package m\nimport (\n "crypto/ecdsa"\n "crypto/elliptic"\n "crypto/rand"\n)\n'
        "func f() { ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }\n"
    )
    assert sorted(f.algorithm for f in fs) == ["ECC", "ECDSA"]


def test_elliptic_p384_and_p521_resolve() -> None:
    fs = _findings(
        'package m\nimport "crypto/elliptic"\n'
        "func f() { elliptic.P384(); elliptic.P521() }\n"
    )
    assert [(f.algorithm, f.curve) for f in fs] == [
        ("ECC", "P-384"),
        ("ECC", "P-521"),
    ]


def test_curve25519_x25519_resolves() -> None:
    fs = _findings(
        'package m\nimport "golang.org/x/crypto/curve25519"\n'
        "func f() { curve25519.X25519(scalar, point) }\n"
    )
    assert [f.algorithm for f in fs] == ["X25519"]
    assert fs[0].family == AlgorithmFamily.KEY_AGREEMENT
    assert fs[0].quantum_risk == QuantumRisk.VULNERABLE


def test_curve25519_scalar_base_mult_resolves() -> None:
    fs = _findings(
        'package m\nimport "golang.org/x/crypto/curve25519"\n'
        "func f() { curve25519.ScalarBaseMult(dst, scalar) }\n"
    )
    assert [f.algorithm for f in fs] == ["X25519"]


def test_crypto_rand_int_and_prime_resolve_as_csprng() -> None:
    fs = _findings(
        'package m\nimport "crypto/rand"\n'
        "func f() { rand.Int(rand.Reader, max); rand.Prime(rand.Reader, 2048) }\n"
    )
    assert [f.algorithm for f in fs] == ["CSPRNG", "CSPRNG"]
    assert all(f.quantum_risk == QuantumRisk.SAFE for f in fs)


def test_aes_has_no_key_size() -> None:
    fs = _findings(
        'package m\nimport "crypto/aes"\nfunc f() { aes.NewCipher(key) }\n'
    )
    aes = [f for f in fs if f.algorithm == "AES"]
    assert len(aes) == 1
    assert aes[0].key_size is None
    assert aes[0].mode is None


def test_aliased_import_resolves() -> None:
    fs = _findings(
        'package m\nimport sha "crypto/sha256"\nfunc f() { sha.New() }\n'
    )
    assert [f.algorithm for f in fs] == ["SHA-256"]


def test_dot_import_resolves_at_reduced_confidence() -> None:
    fs = _findings(
        'package m\nimport . "crypto/md5"\nfunc f() { New() }\n'
    )
    assert len(fs) == 1
    assert fs[0].algorithm == "MD5"
    assert fs[0].confidence == 0.7


def test_dot_import_ambiguous_call_lowers_confidence() -> None:
    fs = _findings(
        'package m\nimport (\n . "crypto/md5"\n . "crypto/sha1"\n)\nfunc f() { New() }\n'
    )
    assert len(fs) == 1
    assert fs[0].algorithm in {"MD5", "SHA-1"}
    assert fs[0].confidence == 0.4


def test_unrelated_calls_emit_nothing() -> None:
    fs = _findings(
        'package m\nimport "fmt"\nfunc f() { fmt.Println("hi") }\n'
    )
    assert fs == []


def test_evidence_and_location_populated() -> None:
    fs = _findings(
        'package m\nimport "crypto/md5"\nfunc f() { md5.New() }\n'
    )
    assert fs[0].evidence == "func f() { md5.New() }"
    assert fs[0].location.line == 3
    assert fs[0].location.column >= 0


def test_detect_go_file_missing_returns_empty(tmp_path: Path) -> None:
    assert detect_go_file(tmp_path / "nope.go") == []


def test_detect_go_file_reads_and_detects(tmp_path: Path) -> None:
    f = tmp_path / "x.go"
    f.write_text('package m\nimport "crypto/md5"\nfunc f() { md5.New() }\n')
    fs = detect_go_file(f)
    assert [x.algorithm for x in fs] == ["MD5"]


def test_detect_go_file_broken_source_without_crypto_returns_empty(tmp_path: Path) -> None:
    f = tmp_path / "broken.go"
    f.write_text("package m\nfunc f( { @@@ not valid %%% }\n")
    assert detect_go_file(f) == []


def test_detect_go_file_broken_source_still_emits_crypto_finding(tmp_path: Path) -> None:
    # tree-sitter builds a partial tree from broken input: a well-formed
    # call_expression that survives inside the ERROR region is still matched, so
    # a crypto call in otherwise-invalid Go is reported (never-raise, not
    # never-detect). Guards the docstring contract against a vacuous fixture.
    f = tmp_path / "broken.go"
    f.write_text('package m\nimport "crypto/md5"\nfunc f( { @@@ md5.New() %%% }\n')
    assert [x.algorithm for x in detect_go_file(f)] == ["MD5"]


def test_backtick_import_binds_last_segment() -> None:
    r = _resolver("package m\nimport `crypto/rsa`\n")
    assert r.resolve("rsa") == "crypto/rsa"


def test_backtick_import_path_resolves() -> None:
    fs = _findings("package m\nimport `crypto/md5`\nfunc f() { md5.New() }\n")
    assert [f.algorithm for f in fs] == ["MD5"]


def test_rsa_key_size_absurd_literal_is_dropped() -> None:
    fs = _findings(
        'package m\nimport "crypto/rsa"\n'
        "func f() { rsa.GenerateKey(nil, 0x" + "f" * 5000 + ") }\n"
    )
    rsa = [f for f in fs if f.algorithm == "RSA"]
    assert len(rsa) == 1
    assert rsa[0].key_size is None
    repr(rsa[0])  # an unbounded int here would raise on stringify


def test_node_count_guard_skips_oversized_tree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("pqcheck.detectors.go_detector._MAX_PARSE_NODES", 5)
    fs = _findings('package m\nimport "crypto/md5"\nfunc f() { md5.New() }\n')
    assert fs == []


def test_evidence_aligns_across_unicode_line_separator() -> None:
    # U+2028 in a raw string splits str.splitlines() but not tree-sitter rows;
    # the evidence line must still match the call's actual source line.
    fs = _findings(
        "package m\n"
        'import "crypto/rsa"\n'
        "var x = `a\u2028b`\n"
        "func f() { rsa.GenerateKey(nil, 2048) }\n"
    )
    rsa = next(f for f in fs if f.algorithm == "RSA")
    assert rsa.evidence == "func f() { rsa.GenerateKey(nil, 2048) }"


def test_detect_go_file_catalog_file_not_found_returns_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A broken install where data/crypto-catalog.json is missing raises
    # FileNotFoundError (an OSError subclass) from load_go_catalog(). Because
    # functools.cache does not cache exceptions, every call re-raises. The
    # never-raise contract requires that OSError is caught at the detect_go_file
    # boundary so callers always receive [] rather than an unhandled exception.
    f = tmp_path / "x.go"
    f.write_text('package m\nimport "crypto/md5"\nfunc f() { md5.New() }\n')

    monkeypatch.setattr(_go_det, "lookup_go_symbol", _raise_file_not_found)
    assert detect_go_file(f) == []


def _raise_file_not_found(*_: object, **__: object) -> None:
    raise FileNotFoundError("data/crypto-catalog.json not found")


# ---- Method-call detection (no type info; import-gated) ----


def test_ecdh_method_on_bare_identifier_resolves() -> None:
    fs = _findings(
        'package m\nimport "crypto/ecdsa"\n'
        "func f(pub *ecdsa.PublicKey) { pub.ECDH() }\n"
    )
    assert [f.algorithm for f in fs] == ["ECDH"]
    assert fs[0].family == AlgorithmFamily.KEY_AGREEMENT
    assert fs[0].confidence == 0.5
    assert fs[0].quantum_risk == QuantumRisk.VULNERABLE


def test_ecdh_method_on_field_selector_resolves() -> None:
    # k.PublicKey.ECDH(): the receiver is a field-access chain, not a bare
    # identifier — pemutil/ssh.go's actual shape.
    fs = _findings(
        'package m\nimport "crypto/ecdsa"\n'
        "func f(k *ecdsa.PrivateKey) { k.PublicKey.ECDH() }\n"
    )
    assert [f.algorithm for f in fs] == ["ECDH"]


def test_ecdh_method_gated_on_ecdh_import_too() -> None:
    fs = _findings(
        'package m\nimport "crypto/ecdh"\n'
        "func f(k *ecdh.PrivateKey, pub *ecdh.PublicKey) { k.ECDH(pub) }\n"
    )
    assert [f.algorithm for f in fs] == ["ECDH"]


def test_ecdh_method_without_import_does_not_emit() -> None:
    # Same method name, unrelated receiver, and crucially no crypto/ecdsa or
    # crypto/ecdh import — must not false-positive on a same-named method.
    fs = _findings(
        "package m\n"
        "type Foo struct{}\n"
        "func (f *Foo) ECDH() (int, error) { return 0, nil }\n"
        "func g(f *Foo) { f.ECDH() }\n"
    )
    assert fs == []


def test_yubikey_generatekey_gated_on_piv_import() -> None:
    fs = _findings(
        'package m\nimport "github.com/go-piv/piv-go/v2/piv"\n'
        "func f(yk *piv.YubiKey) { yk.GenerateKey(nil, piv.Slot{}, piv.Key{}) }\n"
    )
    assert [f.algorithm for f in fs] == ["KEYGEN"]
    assert fs[0].family == AlgorithmFamily.SIGNATURE
    assert fs[0].confidence == 0.5
    # Opaque algorithm (a runtime piv.Key value) — never claimed post-quantum
    # safe or vulnerable from static analysis alone.
    assert fs[0].quantum_risk == QuantumRisk.UNKNOWN


def test_generatekey_without_piv_import_does_not_emit() -> None:
    fs = _findings(
        "package m\n"
        "type Thing struct{}\n"
        "func (t *Thing) GenerateKey() {}\n"
        "func f(t *Thing) { t.GenerateKey() }\n"
    )
    assert fs == []


def test_hpke_hybrid_chain_resolves() -> None:
    fs = _findings(
        'package m\nimport "filippo.io/hpke"\n'
        "func f() { hpke.MLKEM768X25519().GenerateKey() }\n"
    )
    assert [f.algorithm for f in fs] == ["X25519MLKEM768"]
    assert fs[0].family == AlgorithmFamily.KEM
    assert fs[0].confidence == 0.5
    assert fs[0].quantum_risk == QuantumRisk.HYBRID


def test_hpke_hybrid_chain_gated_on_hpke_import() -> None:
    # Same textual chain shape, but the package is not actually filippo.io/hpke.
    fs = _findings(
        "package m\n"
        "type hpke struct{}\n"
        "func MLKEM768X25519() hpke { return hpke{} }\n"
        "func (hpke) GenerateKey() {}\n"
        "func f() { MLKEM768X25519().GenerateKey() }\n"
    )
    assert fs == []


def test_ecdh_method_on_locally_constructed_receiver_does_not_emit() -> None:
    # Regression: a package that both imports crypto/ecdh/ecdsa AND declares
    # its own `type ECDH struct{...}` with its own `ECDH()` method (real
    # shape in smallstep/crypto's kms/mackms) must not have every call
    # through that local type false-positive as the stdlib method just
    # because the file also has genuine crypto/ecdsa.PublicKey.ECDH() sites.
    fs = _findings(
        'package m\nimport "crypto/ecdh"\n'
        "type ECDH struct{}\n"
        "func (e *ECDH) ECDH(pub *ecdh.PublicKey) ([]byte, error) { return nil, nil }\n"
        "func f() {\n"
        "    e := &ECDH{}\n"
        "    e.ECDH(nil)\n"
        "}\n"
    )
    assert fs == []


def test_ecdh_p256_generatekey_chain_still_does_not_double_count() -> None:
    # Regression guard: the chained-method path must not start matching
    # unrelated `X().GenerateKey()` shapes just because the field name lines
    # up with the yubikey/hpke cases.
    fs = _findings(
        'package m\nimport (\n "crypto/ecdh"\n "crypto/rand"\n)\n'
        "func f() { ecdh.P256().GenerateKey(rand.Reader) }\n"
    )
    assert [f.algorithm for f in fs] == ["ECDH"]
