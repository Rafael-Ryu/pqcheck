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
import io
import os
import stat
import tokenize
from pathlib import Path

from pqcheck.detectors.algorithms import AlgorithmHit, lookup_cipher_mode, lookup_python_symbol
from pqcheck.models import AlgorithmFamily, CryptoFinding, SourceLocation


class ImportResolver(ast.NodeVisitor):
    """First pass: build local-name → qualified-name map.

    Star imports are recorded but not expanded — there is no way to know
    which names a `from X import *` binds without importing X. Files
    using star imports for crypto modules are flagged via has_star_import.

    Bindings inside `def`/`class` blocks are still recorded (the visitor
    has no per-scope name table) but are tagged `scoped` so PythonDetector
    can demote confidence when the call site is at file level.
    """

    def __init__(self) -> None:
        self._names: dict[str, str] = {}
        self._star_imports: set[str] = set()
        self._scoped_names: set[str] = set()
        self._scope_depth = 0

    # ---- public API used by PythonDetector and tests ----

    def add_module(self, local: str, qualified: str) -> None:
        self._names[local] = qualified

    def resolve_name(self, local: str) -> str | None:
        return self._names.get(local)

    def has_star_import(self, module: str) -> bool:
        return module in self._star_imports

    def iter_star_imports(self) -> list[str]:
        return list(self._star_imports)

    def is_scoped_binding(self, local: str) -> bool:
        return local in self._scoped_names

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

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_scope(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_scope(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._enter_scope(node)

    def _enter_scope(self, node: ast.AST) -> None:
        self._scope_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self._scope_depth -= 1

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            local = alias.asname or root
            qualified = alias.name if alias.asname else root
            self._names[local] = qualified
            if self._scope_depth > 0:
                self._scoped_names.add(local)

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
            if self._scope_depth > 0:
                self._scoped_names.add(local)


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
        self._suppressed_call_ids: set[int] = set()
        self._scope_depth = 0

    def visit(self, node: ast.AST) -> None:
        # Pass 1: collect imports before walking calls.
        if isinstance(node, ast.Module):
            self._imports.visit(node)
        super().visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._scope_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self._scope_depth -= 1

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._scope_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self._scope_depth -= 1

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_depth += 1
        try:
            self.generic_visit(node)
        finally:
            self._scope_depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if id(node) in self._suppressed_call_ids:
            self.generic_visit(node)
            return
        qualified = self._imports.resolve_attribute(node.func)
        emitted = False
        if qualified is not None:
            hit = lookup_python_symbol(qualified)
            if hit is not None:
                if hit.canonical == "CIPHER-WRAPPER":
                    self._emit_cipher_wrapper(node)
                    emitted = True
                else:
                    self._emit(
                        node,
                        hit.canonical,
                        hit.family,
                        confidence=self._scope_adjusted_confidence(node, 1.0),
                        key_size=self._extract_key_size(node, qualified),
                        curve=self._extract_curve(node) if hit.canonical == "ECDSA" else None,
                        mode=self._extract_pycrypto_mode(node, qualified),
                    )
                    emitted = True
        # hashlib.new("md5") — string-based dispatch. Only runs when the
        # catalog has no direct entry; prevents double-emit if hashlib.new
        # is ever added to _PYTHON_SYMBOLS.
        if not emitted and qualified == "hashlib.new":
            self._emit_hashlib_new(node)
            emitted = True
        # Star-import fallback: `from <module> import *; MD5()` — the
        # callee is an ast.Name with no resolved binding, but a star
        # import in scope makes a catalog match plausible. Confidence is
        # demoted: at static-analysis time we cannot prove the name
        # actually binds to the catalogued symbol.
        if not emitted and qualified is None and isinstance(node.func, ast.Name):
            self._emit_via_star_import(node, node.func.id)
        self.generic_visit(node)

    def _emit_via_star_import(self, node: ast.Call, short_name: str) -> None:
        """Emit if `short_name` matches a catalog entry under any module
        present in `from <module> import *`. Skips CIPHER-WRAPPER because
        the wrapper unwrap logic depends on resolving `algorithms.X` /
        `modes.Y`, which star imports do not expose qualified.
        """
        for module in self._imports.iter_star_imports():
            hit = lookup_python_symbol(f"{module}.{short_name}")
            if hit is None or hit.canonical == "CIPHER-WRAPPER":
                continue
            self._emit(node, hit.canonical, hit.family, confidence=0.7)
            return

    def _scope_adjusted_confidence(self, node: ast.Call, base: float) -> float:
        """Demote `base` when the binding was imported inside a function or
        class but the call site is at file level. We only flag the
        scope-mismatch direction (binding scoped, call at module top): the
        opposite case is the common idiom (`import hashlib` at file level,
        used inside functions) and must stay at full confidence.
        """
        if self._scope_depth > 0:
            return base
        base_name = self._base_name(node.func)
        if base_name is not None and self._imports.is_scoped_binding(base_name):
            return min(base, 0.7)
        return base

    @staticmethod
    def _base_name(expr: ast.expr) -> str | None:
        current: ast.expr = expr
        while isinstance(current, ast.Attribute):
            current = current.value
        if isinstance(current, ast.Name):
            return current.id
        # Subscripted/dynamic callees short-circuit earlier in visit_Call.
        return None  # pragma: no cover

    def _emit_hashlib_new(self, node: ast.Call) -> None:
        if not node.args:
            return  # pragma: no cover - hashlib.new() with no args is a runtime TypeError
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return  # pragma: no cover - only string Constant literals reach this from valid source
        key = first.value.lower()
        mapping = _HASHLIB_NEW_NAMES.get(key)
        if mapping is None:
            return  # pragma: no cover - unknown alias; table covers known keys
        canonical, family = mapping
        self._emit(node, canonical, family, confidence=0.7)

    def _emit_cipher_wrapper(self, node: ast.Call) -> None:
        algorithm_arg = self._cipher_arg(node, position=0, keyword="algorithm")
        mode_arg = self._cipher_arg(node, position=1, keyword="mode")
        algo_hit = self._resolve_call_target(algorithm_arg)
        if algo_hit is None:
            return
        if algo_hit.canonical == "CIPHER-WRAPPER":  # pragma: no cover - catalog has no nested
            return
        # Suppress the nested algorithm and mode Calls so generic_visit
        # doesn't re-emit them as flat findings.
        if isinstance(algorithm_arg, ast.Call):  # pragma: no branch
            self._suppressed_call_ids.add(id(algorithm_arg))
        if isinstance(mode_arg, ast.Call):
            self._suppressed_call_ids.add(id(mode_arg))
        mode_name = self._resolve_mode_target(mode_arg)
        self._emit(
            node,
            algo_hit.canonical,
            algo_hit.family,
            confidence=1.0,
            mode=mode_name,
        )

    @staticmethod
    def _cipher_arg(
        node: ast.Call, *, position: int, keyword: str
    ) -> ast.expr | None:
        if position < len(node.args):
            return node.args[position]
        for kw in node.keywords:
            if kw.arg == keyword:
                return kw.value
        return None

    def _resolve_call_target(self, expr: ast.expr | None) -> AlgorithmHit | None:
        if not isinstance(expr, ast.Call):
            return None
        qualified = self._imports.resolve_attribute(expr.func)
        if qualified is None:
            return None
        return lookup_python_symbol(qualified)

    def _resolve_mode_target(self, expr: ast.expr | None) -> str | None:
        if not isinstance(expr, ast.Call):
            return None
        qualified = self._imports.resolve_attribute(expr.func)
        if qualified is None:
            return None
        return lookup_cipher_mode(qualified)

    @staticmethod
    def _extract_key_size(node: ast.Call, qualified: str | None) -> int | None:
        # pycryptodome takes the bit length as `bits=` (keyword) or as the
        # first positional arg. cryptography uses `key_size=`.
        pycryptodome_keygens = {
            "Crypto.PublicKey.RSA.generate",
            "Crypto.PublicKey.DSA.generate",
        }
        keywords = {"key_size"}
        if qualified in pycryptodome_keygens:
            keywords.add("bits")
        for kw in node.keywords:
            if kw.arg in keywords and isinstance(kw.value, ast.Constant):
                value = kw.value.value
                # bool is an int subclass — exclude it explicitly so key_size=True
                # doesn't surface as key_size=1 in a security-sensitive field.
                if type(value) is int:
                    return value
        if (
            qualified in pycryptodome_keygens
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            value = node.args[0].value
            if type(value) is int:
                return value
        return None

    def _extract_pycrypto_mode(self, node: ast.Call, qualified: str) -> str | None:
        """Return the mode for `Crypto.Cipher.<X>.new(key, X.MODE_Y, ...)`.

        Only fires for the pycryptodome cipher `new` callees; other call
        sites pass through with mode=None. The mode arg is the second
        positional or the `mode=` keyword; the value must resolve to an
        Attribute like `AES.MODE_ECB` whose qualified form is in the
        catalog.
        """
        if not (qualified.startswith("Crypto.Cipher.") and qualified.endswith(".new")):
            return None
        # pycryptodome's <Cipher>.new(key, mode, ...) — mode is the second
        # positional or the `mode=` keyword.
        mode_position = 1
        candidate: ast.expr | None = None
        if len(node.args) > mode_position:
            candidate = node.args[mode_position]
        for kw in node.keywords:
            if kw.arg == "mode":
                candidate = kw.value
                break
        if not isinstance(candidate, ast.Attribute):
            return None
        mode_qualified = self._imports.resolve_attribute(candidate)
        if mode_qualified is None:
            return None
        return lookup_cipher_mode(mode_qualified)

    @staticmethod
    def _extract_curve(node: ast.Call) -> str | None:
        # Positional first arg or keyword `curve=`. Expected: an instance
        # construction like `ec.SECP256R1()` whose callee's last segment
        # is the curve name.
        candidate: ast.expr | None = None
        if node.args:
            candidate = node.args[0]
        for kw in node.keywords:
            if kw.arg == "curve":
                candidate = kw.value
                break
        if not isinstance(candidate, ast.Call):
            return None
        if isinstance(candidate.func, ast.Attribute):
            return candidate.func.attr
        if isinstance(candidate.func, ast.Name):
            return candidate.func.id
        return None

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


_MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MiB cap — skip generated/oversized files.
_READ_CHUNK = 64 * 1024


def detect_python_file(path: Path) -> list[CryptoFinding]:
    """Detect Python crypto primitive usage in `path`.

    Returns an empty list (never raises) for: missing file, symlink,
    non-regular file (device, FIFO, socket, directory), file > 2 MiB,
    encoding failure on both the PEP 263 declared codec (or UTF-8
    default) and Latin-1, or a SyntaxError during parsing.

    The path is opened with O_NOFOLLOW and the size/regular-file check
    runs against the open fd; this rejects symlinks (a previously fatal
    case: a symlink to /dev/zero blocked the read forever) and closes
    the TOCTOU between size check and read. The read is itself capped
    so a file that grows between fstat and read cannot exceed the limit.
    Encoding is resolved via tokenize.detect_encoding so PEP 263
    cookies like `# coding: cp1252` are honored before falling back to
    Latin-1.
    """
    raw = _read_capped(path)
    if raw is None:
        return []
    source = _decode_python_source(raw)
    if source is None:  # pragma: no cover - latin-1 (last fallback) is total over bytes
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []
    detector = PythonDetector(source_path=path, source=source)
    detector.visit(tree)
    return detector.findings


def _read_capped(path: Path) -> bytes | None:
    # O_NONBLOCK ensures opening a FIFO (or any path whose target would
    # otherwise block on open) returns immediately; the S_ISREG guard
    # below then rejects it. For regular files O_NONBLOCK is inert.
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None
        if info.st_size > _MAX_FILE_BYTES:
            return None
        chunks: list[bytes] = []
        budget = _MAX_FILE_BYTES + 1
        while budget > 0:
            chunk = os.read(fd, min(budget, _READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            budget -= len(chunk)
        if budget == 0:
            return None
    except OSError:  # pragma: no cover - fstat/read on an open fd is well-defined
        return None
    finally:
        os.close(fd)
    return b"".join(chunks)


def _decode_python_source(raw: bytes) -> str | None:
    """Decode `raw` to text honoring a PEP 263 encoding cookie.

    `tokenize.detect_encoding` reads the first one or two lines, returns
    the cookie-declared codec (or 'utf-8' as the documented default) and
    handles the UTF-8 BOM. We try that codec first; latin-1 is the final
    fallback for files that neither declare a cookie nor parse as UTF-8.
    """
    try:
        detected, _bom_lines = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except SyntaxError:
        detected = "utf-8"
    for encoding in (detected, "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return None  # pragma: no cover - latin-1 (last fallback) is total over bytes
