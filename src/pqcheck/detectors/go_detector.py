"""Go source detector — emits CryptoFinding per detected primitive use.

Two passes over a tree-sitter Go parse tree:
  1. GoImportResolver maps each in-source package identifier to its full
     import path (handling aliases, dot imports, and blank imports).
  2. GoDetector visits every call_expression of the form pkg.Func(...),
     resolves it against pqcheck.detectors.algorithms, and emits findings.

tree-sitter never raises on invalid syntax: it builds a partial tree where the
broken span becomes ERROR nodes. The walk descends through them, so a well-formed
`pkg.Func(...)` call surviving inside otherwise-invalid Go is still resolved and
reported — malformed input degrades coverage, it does not crash. detect_go_file
honours the Python detector's never-raise contract.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from tree_sitter import Node, Parser

from pqcheck.detectors._source_read import read_source_bytes
from pqcheck.detectors.algorithms import AlgorithmHit, lookup_go_symbol, normalize_curve
from pqcheck.detectors.tree_sitter_loader import go_language
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation

_DETECTOR_ID = "go-tree-sitter"

# Go's semantic import versioning (SIV) only applies to major version >= 2
# (https://go.dev/ref/mod#major-version-suffixes) -- v0/v1 are never version
# suffixes, so a trailing "/v1" segment is a real, literal package name (e.g.
# go-containerregistry's pkg/v1, whose package clause is `package v1`). For
# v2+, the package's declared short name conventionally matches the segment
# *before* the suffix (stdlib's math/rand/v2 declares `package rand`), and an
# unaliased import binds that short name at call sites -- not the literal
# "v2" trailing path segment. This mirrors the oracle's own /vN handling in
# tests/corpus/run_recall_v2.py.
_SIV_SUFFIX_RE = re.compile(r"v(\d+)")
_MIN_SIV_MAJOR_VERSION = 2


def _unaliased_import_identifier(path: str) -> str:
    """Package identifier an unaliased `import "path"` binds at call sites."""
    segments = path.rsplit("/", 2)
    if len(segments) >= _MIN_SIV_MAJOR_VERSION:
        match = _SIV_SUFFIX_RE.fullmatch(segments[-1])
        if match is not None and int(match.group(1)) >= _MIN_SIV_MAJOR_VERSION:
            return segments[-2]
    return segments[-1]

# Method calls on a typed receiver (`pub.ECDH()`, `k.yk.GenerateKey(...)`) have
# no package-qualified callee for lookup_go_symbol, and tree-sitter carries no
# type info to resolve the receiver the way go/types does. Instead of a bare
# name match on `.ECDH(`/`.GenerateKey(` -- which would fire on any type with a
# same-named method -- each is gated on the file importing the package that
# declares the real receiver, at reduced confidence (mirrors the dot-import
# and dataflow-opaque precedents elsewhere in this detector/python_detector).
# Any of the crypto/ecdsa.*.ECDH / crypto/ecdh.*.ECDH catalog entries carries
# the same canonical+family, so one representative key is enough here.
_ECDH_METHOD_CATALOG_KEY = "crypto/ecdsa.PublicKey.ECDH"
_ECDH_IMPORT_GATES = ("crypto/ecdsa", "crypto/ecdh")
_YUBIKEY_IMPORT_PATH = "github.com/go-piv/piv-go/v2/piv"
# go-piv's YubiKey.GenerateKey takes an opaque `piv.Key{Algorithm: ...}` whose
# concrete algorithm is a runtime value (a variable, not a literal) at every
# corpus call site -- the construction is real but the algorithm is dataflow-
# opaque, so this stays out of the catalog (which requires every entry to
# classify through _QUANTUM_MAP) and mirrors python_detector's CIPHER marker:
# a generic canonical that resolves to QuantumRisk.UNKNOWN by design.
_YUBIKEY_KEYGEN_HIT = AlgorithmHit("KEYGEN", AlgorithmFamily.SIGNATURE)
_HPKE_IMPORT_PATH = "filippo.io/hpke"
_HPKE_HYBRID_CATALOG_KEY = "filippo.io/hpke.MLKEM768X25519.GenerateKey"
_METHOD_CONFIDENCE = 0.5

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

    def imports_path(self, path: str) -> bool:
        """True when the file imports `path`, under any alias (or dot)."""
        return path in self._names.values() or path in self._dot_imports

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
            self._names[_unaliased_import_identifier(path)] = path
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


def _composite_literal_type(expr: Node) -> Node | None:
    # `&X{...}` is a unary_expression wrapping the composite_literal; unwrap it
    # so both `X{...}` and `&X{...}` resolve to the same type node.
    if expr.type == "unary_expression":
        operand = expr.child_by_field_name("operand")
        if operand is not None:
            expr = operand
    if expr.type != "composite_literal":
        return None
    return expr.child_by_field_name("type")


def _collect_locally_constructed(root: Node, source: bytes) -> set[str]:
    """Identifiers bound to a composite literal of an unqualified, package-local
    type — `e := &ECDH{...}` or `e = SomeType{...}`.

    Such an identifier can never hold a crypto/ecdsa or crypto/ecdh stdlib
    value: those types are always package-qualified from outside their own
    package (`ecdsa.PublicKey{}`), never a bare `type_identifier`. Excluding
    these from the import-gated method match below closes a real false
    positive (smallstep/crypto's own `type ECDH struct{...}` with its own
    `ECDH()` method, unrelated to crypto/ecdsa's) without tracking dataflow in
    general — this only follows the single literal an identifier is directly
    constructed from, not values threaded through further assignments.
    """
    idents: set[str] = set()
    for node in _walk(root):
        if node.type not in ("short_var_declaration", "assignment_statement"):
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if left is None or right is None:
            continue
        lhs = [c for c in left.named_children if c.type == "identifier"]
        rhs = right.named_children
        for ident, expr in zip(lhs, rhs, strict=False):
            type_node = _composite_literal_type(expr)
            if type_node is not None and type_node.type == "type_identifier":
                idents.add(_node_text(ident, source))
    return idents


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
        self._locally_constructed: set[str] = set()
        self.findings: list[CryptoFinding] = []

    def run(self, root: Node) -> None:
        if root.descendant_count > _MAX_PARSE_NODES:
            return
        self._imports.visit_root(root, self._source)
        self._locally_constructed = _collect_locally_constructed(root, self._source)
        for node in _walk(root):
            if node.type == "call_expression":
                self._visit_call(node)

    def _visit_call(self, node: Node) -> None:
        func = node.child_by_field_name("function")
        if func is None:
            return
        if func.type == "selector_expression":
            self._visit_selector_call(node, func)
        elif func.type == "identifier":
            self._emit_dot_import(node, func)

    def _visit_selector_call(self, node: Node, func: Node) -> None:
        operand = func.child_by_field_name("operand")
        field = func.child_by_field_name("field")
        if operand is None or field is None:
            return
        field_name = _node_text(field, self._source)
        if operand.type == "identifier":
            operand_name = _node_text(operand, self._source)
            import_path = self._imports.resolve(operand_name)
            if import_path is not None:
                hit = lookup_go_symbol(f"{import_path}.{field_name}")
                if hit is not None:
                    self._emit(node, hit, confidence=1.0)
                    return
            # Not a package-qualified call (or no catalog hit): may be a
            # method call on a variable of a catalogued receiver type --
            # unless the variable was directly constructed from a
            # package-local composite literal, which rules out a stdlib
            # receiver type outright (see _collect_locally_constructed).
            if operand_name not in self._locally_constructed:
                self._visit_method_call(node, field_name)
        elif operand.type == "selector_expression":
            # A field-access chain (`k.PublicKey.ECDH()`, `k.yk.GenerateKey(...)`)
            # is never a package-qualified call -- Go package identifiers are
            # always bare, so this can only be a method call on the field's
            # value. Same import-gated match as the identifier case.
            self._visit_method_call(node, field_name)
        elif operand.type == "call_expression":
            # e.g. `ecdh.P256().GenerateKey(...)` or the hpke hybrid chain
            # below. The general case (operand is a plain package/constructor
            # call unrelated to a catalogued method) does not resolve to a
            # catalog key -- the outer call is skipped and only the inner
            # call, if catalogued, emits on its own. No double count.
            self._visit_chained_method_call(node, operand, field_name)

    def _visit_method_call(self, node: Node, field_name: str) -> None:
        if field_name == "ECDH" and any(
            self._imports.imports_path(pkg) for pkg in _ECDH_IMPORT_GATES
        ):
            hit = lookup_go_symbol(_ECDH_METHOD_CATALOG_KEY)
            if hit is not None:
                self._emit(node, hit, confidence=_METHOD_CONFIDENCE)
        elif field_name == "GenerateKey" and self._imports.imports_path(_YUBIKEY_IMPORT_PATH):
            self._emit(node, _YUBIKEY_KEYGEN_HIT, confidence=_METHOD_CONFIDENCE)

    def _visit_chained_method_call(self, node: Node, operand_call: Node, field_name: str) -> None:
        # hpke.MLKEM768X25519().GenerateKey(): the receiver is itself a call,
        # so the identifier-based path above never sees it. Matched textually
        # against the exact chain (tree-sitter has no type for operand_call's
        # result) and import-gated so an unrelated `X().GenerateKey()` cannot
        # false-positive.
        if field_name != "GenerateKey":
            return
        inner_func = operand_call.child_by_field_name("function")
        if inner_func is None or inner_func.type != "selector_expression":
            return
        inner_operand = inner_func.child_by_field_name("operand")
        inner_field = inner_func.child_by_field_name("field")
        if inner_operand is None or inner_field is None or inner_operand.type != "identifier":
            return
        if _node_text(inner_field, self._source) != "MLKEM768X25519":
            return
        import_path = self._imports.resolve(_node_text(inner_operand, self._source))
        if import_path != _HPKE_IMPORT_PATH:
            return
        hit = lookup_go_symbol(_HPKE_HYBRID_CATALOG_KEY)
        if hit is not None:
            self._emit(node, hit, confidence=_METHOD_CONFIDENCE)

    def _emit_dot_import(self, node: Node, func: Node) -> None:
        name = _node_text(func, self._source)
        for path in self._imports.dot_imports():
            hit = lookup_go_symbol(f"{path}.{name}")
            if hit is not None:
                self._emit(node, hit, confidence=0.7)
                return

    def _emit(self, node: Node, hit: AlgorithmHit, *, confidence: float) -> None:
        key_size = hit.key_size
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
        args = self._named_args(call)
        if len(args) < 2:  # need at least (rand, bits)  # noqa: PLR2004
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
    invalid syntax by parsing a partial tree, so a crypto call surviving inside
    malformed Go is still reported; only input with no resolvable call yields [].
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
