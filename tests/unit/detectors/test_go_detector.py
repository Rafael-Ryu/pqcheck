from tree_sitter import Language

from pqcheck.detectors.tree_sitter_loader import go_language


def test_go_language_returns_a_language() -> None:
    assert isinstance(go_language(), Language)


def test_go_language_is_cached() -> None:
    assert go_language() is go_language()
