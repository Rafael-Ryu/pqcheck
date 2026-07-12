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
    # The v2 import path's last segment ("v2") is the bound identifier.
    fs = _findings(
        'package m\nimport "math/rand/v2"\nfunc f() { v2.IntN(10) }\n'
    )
    assert [f.algorithm for f in fs] == ["MATH-RAND"]


def test_crypto_rand_is_not_flagged_as_math_rand() -> None:
    fs = _findings(
        'package m\nimport "crypto/rand"\nfunc f() { rand.Read(nil) }\n'
    )
    assert fs == []


def test_ecdh_curve_does_not_double_count() -> None:
    fs = _findings(
        'package m\nimport (\n "crypto/ecdh"\n "crypto/rand"\n)\n'
        "func f() { ecdh.P256().GenerateKey(rand.Reader) }\n"
    )
    assert [f.algorithm for f in fs] == ["ECDH"]
    assert fs[0].curve == "P-256"


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
