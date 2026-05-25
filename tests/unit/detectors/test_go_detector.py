from tree_sitter import Language, Node, Parser

from pqcheck.detectors.go_detector import GoImportResolver
from pqcheck.detectors.tree_sitter_loader import go_language


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
