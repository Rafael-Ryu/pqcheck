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
