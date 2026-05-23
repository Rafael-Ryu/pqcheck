import ast

from pqcheck.detectors.python_detector import ImportResolver


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
