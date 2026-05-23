"""Python AST detector — emits CryptoFinding per detected primitive use.

Two passes over the file's AST:
  1. ImportResolver records local_name → fully_qualified_dotted_name.
  2. PythonDetector visits every Call and resolves its callee against
     the catalog in pqcheck.detectors.algorithms.

Both passes are stdlib-only (ast module). No third-party deps beyond
pydantic, which the project already uses for CryptoFinding.
"""

from __future__ import annotations

import ast
from pathlib import Path

from pqcheck.detectors.algorithms import lookup_python_symbol
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation


class ImportResolver(ast.NodeVisitor):
    """First pass: build local-name → qualified-name map.

    Star imports are recorded but not expanded — there is no way to know
    which names a `from X import *` binds without importing X. Files
    using star imports for crypto modules are flagged via has_star_import.
    """

    def __init__(self) -> None:
        self._names: dict[str, str] = {}
        self._star_imports: set[str] = set()

    # ---- public API used by PythonDetector and tests ----

    def add_module(self, local: str, qualified: str) -> None:
        self._names[local] = qualified

    def resolve_name(self, local: str) -> str | None:
        return self._names.get(local)

    def has_star_import(self, module: str) -> bool:
        return module in self._star_imports

    def resolve_attribute(self, node: ast.expr) -> str | None:
        """Resolve a Name or Attribute chain to its fully-qualified name.

        Examples (with `hashlib` recorded as itself, `h` as alias for hashlib,
        and `hashes` as alias for cryptography.hazmat.primitives.hashes):
          ast.parse("hashlib.md5").body[0].value           -> "hashlib.md5"
          ast.parse("h.md5").body[0].value                 -> "hashlib.md5"
          ast.parse("hashes.MD5").body[0].value            ->
              "cryptography.hazmat.primitives.hashes.MD5"
        """
        parts: list[str] = []
        current: ast.expr | None = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None
        base = self._names.get(current.id)
        if base is None:
            return None
        parts.reverse()
        return ".".join([base, *parts]) if parts else base

    # ---- ast.NodeVisitor hooks ----

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            local = alias.asname or root
            qualified = alias.name if alias.asname else root
            self._names[local] = qualified

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        # Skip relative imports — we cannot resolve them to a project-
        # independent qualified name, and crypto libs are never relative.
        if node.level:
            return
        for alias in node.names:
            if alias.name == "*":
                self._star_imports.add(module)
                continue
            local = alias.asname or alias.name
            qualified = f"{module}.{alias.name}" if module else alias.name
            self._names[local] = qualified


_DETECTOR_ID = "python-ast"

# Lower-cased argument values accepted by hashlib.new("...") that map
# directly to canonical algorithm names. Confidence is demoted because
# the string argument could be runtime-computed (we only see literals).
_HASHLIB_NEW_NAMES: dict[str, tuple[str, AlgorithmFamily]] = {
    "md5": ("MD5", AlgorithmFamily.HASH),
    "sha1": ("SHA-1", AlgorithmFamily.HASH),
    "sha224": ("SHA-224", AlgorithmFamily.HASH),
    "sha256": ("SHA-256", AlgorithmFamily.HASH),
    "sha384": ("SHA-384", AlgorithmFamily.HASH),
    "sha512": ("SHA-512", AlgorithmFamily.HASH),
    "sha3_256": ("SHA3-256", AlgorithmFamily.HASH),
    "sha3_384": ("SHA3-384", AlgorithmFamily.HASH),
    "sha3_512": ("SHA3-512", AlgorithmFamily.HASH),
    "blake2b": ("BLAKE2B", AlgorithmFamily.HASH),
    "blake2s": ("BLAKE2S", AlgorithmFamily.HASH),
}


class PythonDetector(ast.NodeVisitor):
    """Second pass: emit CryptoFinding per detected primitive use."""

    def __init__(self, source_path: Path, source: str) -> None:
        self._path = source_path
        self._source_lines = source.splitlines()
        self._imports = ImportResolver()
        self.findings: list[CryptoFinding] = []

    def visit(self, node: ast.AST) -> None:
        # Pass 1: collect imports before walking calls.
        if isinstance(node, ast.Module):
            self._imports.visit(node)
        super().visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qualified = self._imports.resolve_attribute(node.func)
        if qualified is not None:
            hit = lookup_python_symbol(qualified)
            if hit is not None and hit.canonical != "CIPHER-WRAPPER":
                self._emit(node, hit.canonical, hit.family, confidence=1.0)
        # hashlib.new("md5") — string-based dispatch, demoted confidence.
        if qualified == "hashlib.new":
            self._emit_hashlib_new(node)
        self.generic_visit(node)

    def _emit_hashlib_new(self, node: ast.Call) -> None:
        if not node.args:
            return
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return
        key = first.value.lower()
        mapping = _HASHLIB_NEW_NAMES.get(key)
        if mapping is None:
            return
        canonical, family = mapping
        self._emit(node, canonical, family, confidence=0.7)

    def _emit(
        self,
        node: ast.Call,
        canonical: str,
        family: AlgorithmFamily,
        *,
        confidence: float,
        key_size: int | None = None,
        curve: str | None = None,
        mode: str | None = None,
        padding: str | None = None,
    ) -> None:
        location = SourceLocation(
            path=self._path,
            line=node.lineno,
            column=node.col_offset,
            end_line=node.end_lineno,
            end_column=node.end_col_offset,
        )
        self.findings.append(
            CryptoFinding(
                algorithm=canonical,
                family=family,
                key_size=key_size,
                curve=curve,
                mode=mode,
                padding=padding,
                location=location,
                evidence=self._evidence(node),
                detector_id=_DETECTOR_ID,
                confidence=confidence,
            )
        )

    def _evidence(self, node: ast.Call) -> str:
        line_idx = node.lineno - 1
        if 0 <= line_idx < len(self._source_lines):
            return self._source_lines[line_idx].strip()
        return ""  # pragma: no cover - empty file has no Call nodes to visit
