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
from pathlib import Path

from tree_sitter import Node, Parser

from pqcheck.detectors._source_read import read_source_bytes
from pqcheck.detectors.algorithms import AlgorithmHit, lookup_go_symbol, normalize_curve
from pqcheck.detectors.tree_sitter_loader import go_language
from pqcheck.models import CryptoFinding, SourceLocation

_DETECTOR_ID = "go-tree-sitter"

# The 2 MiB byte cap bounds input size but not node count: a small blob of
# deeply nested expressions can explode into millions of nodes, and walking
# them costs memory/CPU proportional to that count. Bail on such trees — any
# real-world Go file stays far below this, and oversized generated blobs are
# already out of scope (the byte cap drops them too).
_MAX_PARSE_NODES = 1_000_000

# RSA key sizes are small integers; a literal beyond this is not a real key.
# Bounding it also keeps an attacker-supplied huge literal (e.g. 0xfff…f) from
# building an unbounded int that would crash downstream stringify of a finding.
_MAX_KEY_SIZE = 1 << 20


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
    # node is an interpreted or raw string literal; its content child is the
    # text between the quotes. Empty import ("") has no content child -> None.
    for child in node.children:
        if child.type in _STRING_CONTENT:
            return _node_text(child, source)
    return None


# Both forms a Go import path can take: "crypto/md5" and `crypto/md5`. Raw
# (backtick) strings have no escapes, so their content node is the literal path.
_STRING_CONTENT = (
    "interpreted_string_literal_content",
    "raw_string_literal_content",
)


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


def _int_literal(node: Node, source: bytes) -> int | None:
    if node.type != "int_literal":
        return None
    text = _node_text(node, source).replace("_", "")
    try:
        value = int(text, 0)  # base 0: handles 0x/0o/0b and decimal
    except ValueError:  # pragma: no cover - grammar guarantees a valid literal
        return None
    return value if value <= _MAX_KEY_SIZE else None


class GoDetector:
    """Second pass: emit CryptoFinding per detected primitive use."""

    def __init__(self, path: Path, source: bytes) -> None:
        self._path = path
        self._source = source
        # Split on "\n" only — tree-sitter counts rows by \n / \r\n, while
        # str.splitlines() also breaks on U+2028/U+2029/NEL/FF/VT and lone CR,
        # which would desync evidence lines from node.start_point.row. A
        # trailing \r from \r\n is removed by _evidence's strip().
        self._lines = source.decode("utf-8", "replace").split("\n")
        self._imports = GoImportResolver()
        self.findings: list[CryptoFinding] = []

    def run(self, root: Node) -> None:
        if root.descendant_count > _MAX_PARSE_NODES:
            return
        self._imports.visit_root(root, self._source)
        for node in _walk(root):
            if node.type == "call_expression":
                self._visit_call(node)

    def _visit_call(self, node: Node) -> None:
        func = node.child_by_field_name("function")
        if func is None:
            return
        if func.type == "selector_expression":
            operand = func.child_by_field_name("operand")
            field = func.child_by_field_name("field")
            # operand must be a bare package identifier. When it is itself a
            # call/selector (e.g. ecdh.P256().GenerateKey), it does not resolve
            # to a catalog key, so the outer call is skipped and only the inner
            # ecdh.P256() emits — no double count.
            if operand is None or field is None or operand.type != "identifier":
                return
            import_path = self._imports.resolve(_node_text(operand, self._source))
            if import_path is None:
                return
            hit = lookup_go_symbol(f"{import_path}.{_node_text(field, self._source)}")
            if hit is not None:
                self._emit(node, hit, confidence=1.0)
        elif func.type == "identifier":
            self._emit_dot_import(node, func)

    def _emit_dot_import(self, node: Node, func: Node) -> None:
        name = _node_text(func, self._source)
        for path in self._imports.dot_imports():
            hit = lookup_go_symbol(f"{path}.{name}")
            if hit is not None:
                self._emit(node, hit, confidence=0.7)
                return

    def _emit(self, node: Node, hit: AlgorithmHit, *, confidence: float) -> None:
        key_size: int | None = None
        curve = hit.curve
        if hit.canonical == "RSA":
            key_size = self._second_arg_int(node)
        elif hit.canonical == "ECDSA":
            curve = self._first_arg_curve(node)
        location = SourceLocation(
            path=self._path,
            line=node.start_point.row + 1,
            column=node.start_point.column,
            end_line=node.end_point.row + 1,
            end_column=node.end_point.column,
        )
        self.findings.append(
            CryptoFinding(
                algorithm=hit.canonical,
                family=hit.family,
                key_size=key_size,
                curve=curve,
                mode=None,
                padding=None,
                location=location,
                evidence=self._evidence(node),
                detector_id=_DETECTOR_ID,
                confidence=confidence,
            )
        )

    def _named_args(self, call: Node) -> list[Node]:
        arglist = call.child_by_field_name("arguments")
        if arglist is None:  # pragma: no cover - call_expression always has arguments
            return []
        return list(arglist.named_children)

    def _second_arg_int(self, call: Node) -> int | None:
        # RSA key size is rsa.GenerateKey(rand, bits)'s second positional arg.
        _MIN_ARGS_FOR_BITS = 2
        args = self._named_args(call)
        if len(args) < _MIN_ARGS_FOR_BITS:
            return None
        return _int_literal(args[1], self._source)

    def _first_arg_curve(self, call: Node) -> str | None:
        # ecdsa.GenerateKey(elliptic.P256(), ...): arg 0 is a call_expression
        # whose function is a selector_expression; the curve is its field name.
        args = self._named_args(call)
        if not args or args[0].type != "call_expression":
            return None
        inner = args[0].child_by_field_name("function")
        if inner is None or inner.type != "selector_expression":
            return None
        field = inner.child_by_field_name("field")
        if field is None:  # pragma: no cover - a selector always has a field
            return None
        return normalize_curve(_node_text(field, self._source))

    def _evidence(self, node: Node) -> str:
        idx = node.start_point.row
        if 0 <= idx < len(self._lines):
            return self._lines[idx].strip()
        return ""  # pragma: no cover - every call node has a source line


def detect_go_file(path: Path) -> list[CryptoFinding]:
    """Detect Go crypto primitive usage in `path`. Never raises.

    Returns [] for: missing file, symlink, non-regular file, file > 2 MiB,
    unreadable bytes, or an unexpected internal failure. tree-sitter tolerates
    invalid syntax (ERROR nodes match nothing), so malformed Go yields [].
    """
    raw = read_source_bytes(path)
    if raw is None:
        return []
    try:
        tree = Parser(go_language()).parse(raw)
        detector = GoDetector(path, raw)
        detector.run(tree.root_node)
        return detector.findings
    # OSError covers a missing/unreadable catalog (regression-tested); the
    # others guard pathological parse trees. detect_go_file must never raise.
    except (RecursionError, MemoryError, ValueError, OSError):
        return []
