"""Go source detector — emits CryptoFinding per detected primitive use.

Two passes over a tree-sitter Go parse tree:
  1. GoImportResolver maps each in-source package identifier to its full
     import path (handling aliases, dot imports, and blank imports).
  2. GoDetector visits every call_expression of the form pkg.Func(...),
     resolves it against pqcheck.detectors.algorithms, and emits findings.

tree-sitter never raises on invalid syntax — ERROR nodes simply match no
selectors. detect_go_file therefore returns [] for unparseable input rather
than crashing, matching the Python detector's never-raise contract.
"""

from __future__ import annotations

from collections.abc import Iterator

from tree_sitter import Node


def _walk(root: Node) -> Iterator[Node]:
    # Iterative preorder (document order). Avoids RecursionError on a
    # pathologically deep tree from untrusted source.
    stack: list[Node] = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _node_text(node: Node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _string_literal_path(node: Node, source: bytes) -> str | None:
    # node is an interpreted_string_literal; its content child is the text
    # between the quotes. Empty import ("") has no content child -> None.
    for child in node.children:
        if child.type == "interpreted_string_literal_content":
            return _node_text(child, source)
    return None


class GoImportResolver:
    """First pass: map in-source package identifier -> full import path.

    Plain `import "crypto/rsa"` binds the path's last segment (`rsa`) — the
    standard-library convention every targeted package follows. Dot imports
    are recorded separately (their symbols are unqualified at the call site
    and resolve at reduced confidence). Blank imports are dropped: they have
    no call site to attach a finding to.
    """

    def __init__(self) -> None:
        self._names: dict[str, str] = {}
        self._dot_imports: set[str] = set()

    def resolve(self, identifier: str) -> str | None:
        return self._names.get(identifier)

    def dot_imports(self) -> tuple[str, ...]:
        return tuple(sorted(self._dot_imports))

    def visit_root(self, root: Node, source: bytes) -> None:
        for node in _walk(root):
            if node.type == "import_spec":
                self._add_spec(node, source)

    def _add_spec(self, spec: Node, source: bytes) -> None:
        path_node = spec.child_by_field_name("path")
        if path_node is None:
            return
        path = _string_literal_path(path_node, source)
        if path is None:
            return
        name_node = spec.child_by_field_name("name")
        if name_node is None:
            self._names[path.rsplit("/", 1)[-1]] = path
        elif name_node.type == "dot":
            self._dot_imports.add(path)
        elif name_node.type == "package_identifier":
            self._names[_node_text(name_node, source)] = path
        # blank_identifier ("_") -> intentionally ignored.
