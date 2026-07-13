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
from typing import ClassVar

from pqcheck.detectors._source_read import read_source_bytes
from pqcheck.detectors.algorithms import (
    AlgorithmHit,
    hashlib_new_table,
    lookup_cipher_mode,
    lookup_python_symbol,
    normalize_curve,
)
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

    def iter_star_imports(self) -> tuple[str, ...]:
        return tuple(self._star_imports)

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

# hashlib.new("name") string argument -> AlgorithmHit. Derived from the
# catalog's hashlib.* entries (single source of truth) rather than a parallel
# hand-maintained table. Confidence is demoted at emit time because the string
# argument could be runtime-computed; we only resolve literals.
_HASHLIB_NEW_NAMES: dict[str, AlgorithmHit] = hashlib_new_table()

# B1 (TLS config analysis): legacy ssl protocol constants, referenced as a
# plain attribute/attribute-chain rather than called. Matched against this
# small explicit allowlist rather than the whole catalog -- an Attribute node
# that is itself a Call's callee (e.g. `hashlib.md5` in `hashlib.md5()`) is
# also visited here via generic_visit, and matching the full catalog would
# double-emit every ordinary call finding visit_Call already produces.
# Mirrors go_detector.py's _GO_CONSTANT_CATALOG_KEYS.
_SSL_CONSTANT_ALLOWLIST = frozenset(
    (
        "ssl.PROTOCOL_TLSv1",
        "ssl.PROTOCOL_TLSv1_1",
        "ssl.PROTOCOL_SSLv3",
        "ssl.TLSVersion.TLSv1",
        "ssl.TLSVersion.TLSv1_1",
        "ssl.TLSVersion.SSLv3",
    )
)


class PythonDetector(ast.NodeVisitor):
    """Second pass: emit CryptoFinding per detected primitive use."""

    def __init__(self, source_path: Path, source: str) -> None:
        self._path = source_path
        self._source_lines = source.splitlines()
        self._imports = ImportResolver()
        self.findings: list[CryptoFinding] = []
        self._suppressed_call_ids: set[int] = set()

    def visit(self, node: ast.AST) -> None:
        # Pass 1: collect imports before walking calls.
        if isinstance(node, ast.Module):
            self._imports.visit(node)
        super().visit(node)

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
                elif hit.padding == "OAEP":
                    self._emit_oaep(node)
                    emitted = True
                else:
                    self._emit(
                        node,
                        hit.canonical,
                        hit.family,
                        confidence=1.0,
                        key_size=(
                            self._extract_key_size(node, qualified)
                            or self._extract_kdf_param(node, qualified)
                            or hit.key_size
                        ),
                        curve=hit.curve
                        or (self._extract_curve(node) if hit.canonical == "ECDSA" else None),
                        mode=self._extract_pycrypto_mode(node, qualified),
                        padding=hit.padding,
                    )
                    emitted = True
        # hashlib.new("md5") — string-based dispatch. Only runs when the
        # catalog has no direct entry; prevents double-emit if hashlib.new
        # is ever added to _PYTHON_SYMBOLS.
        if not emitted and qualified == "hashlib.new":
            self._emit_hashlib_new(node)
            emitted = True
        # Star-import fallback: `from <module> import *; md5()` leaves
        # the callee unresolved, but a catalog match under the star-imported
        # module is plausible. Confidence is demoted because static analysis
        # cannot prove the runtime binding without importing the module.
        if not emitted and qualified is None and isinstance(node.func, ast.Name):
            self._emit_via_star_import(node, node.func.id)
        if not emitted:
            self._emit_chained_digest(node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Legacy ssl protocol constants (`ssl.PROTOCOL_TLSv1`,
        # `ssl.TLSVersion.TLSv1_1`) — a bare reference, never called. Every
        # Attribute node in the file reaches here via generic_visit,
        # including a Call's own callee (`hashlib.md5` in `hashlib.md5()`),
        # so this only fires for the small explicit allowlist rather than
        # the whole catalog (see _SSL_CONSTANT_ALLOWLIST).
        qualified = self._imports.resolve_attribute(node)
        if qualified in _SSL_CONSTANT_ALLOWLIST:
            hit = lookup_python_symbol(qualified)
            if hit is not None:
                self._emit(node, hit.canonical, hit.family, confidence=1.0)
        self.generic_visit(node)

    def _emit_chained_digest(self, node: ast.Call) -> None:
        """`hashlib.sha256(...).digest()` spanning multiple lines: also emit a
        finding at the .digest()/.hexdigest() token's own line, mirroring
        _emit_cipher_wrapper's sub-call emission (#224) — a line-level SARIF
        consumer expects a finding at the chained-call token line, not just
        the hash constructor's opening line. The hash call itself still gets
        emitted separately (at its own line) via the normal visit_Call path.

        The Call node's own lineno/col_offset track the *start* of the whole
        expression (the receiver's start), same as node.func's — the ".digest"
        token position only shows up in node.func.end_lineno/end_col_offset,
        so that is what we report a location override for.
        """
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in ("digest", "hexdigest")):
            return
        receiver = func.value
        if not isinstance(receiver, ast.Call) or func.end_lineno == node.lineno:
            return
        qualified = self._imports.resolve_attribute(receiver.func)
        hit = lookup_python_symbol(qualified) if qualified is not None else None
        if hit is None or hit.family != AlgorithmFamily.HASH:
            return
        assert func.end_lineno is not None and func.end_col_offset is not None
        self._emit(
            node,
            hit.canonical,
            hit.family,
            confidence=1.0,
            line=func.end_lineno,
            column=func.end_col_offset - len(func.attr),
        )

    def _emit_via_star_import(self, node: ast.Call, short_name: str) -> None:
        for module in self._imports.iter_star_imports():
            hit = lookup_python_symbol(f"{module}.{short_name}")
            if hit is None or hit.canonical == "CIPHER-WRAPPER":
                continue
            self._emit(node, hit.canonical, hit.family, confidence=0.7)
            return

    def _emit_hashlib_new(self, node: ast.Call) -> None:
        if not node.args:
            return  # pragma: no cover - hashlib.new() with no args is a runtime TypeError
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return  # pragma: no cover - only string Constant literals reach this from valid source
        key = _normalize_hashlib_new_name(first.value)
        hit = _HASHLIB_NEW_NAMES.get(key)
        if hit is None:
            return  # pragma: no cover - unknown alias; table covers known keys
        self._emit(node, hit.canonical, hit.family, confidence=0.7)

    def _emit_cipher_wrapper(self, node: ast.Call) -> None:
        algorithm_arg = self._cipher_arg(node, position=0, keyword="algorithm")
        mode_arg = self._cipher_arg(node, position=1, keyword="mode")
        algo_hit = self._resolve_call_target(algorithm_arg)
        if algo_hit is None:
            # The algorithm is dataflow-opaque (a variable/subscript, not a
            # literal `algorithms.AES(...)` call) — e.g. paramiko picks the
            # cipher class from a lookup table before constructing it. We
            # cannot name the concrete algorithm, but a Cipher() is still
            # being built, so surface that fact at low confidence rather than
            # silently dropping a real construction site. `algorithm_arg is
            # None` means Cipher() was called with no algorithm at all
            # (a runtime TypeError), which is not worth flagging.
            if algorithm_arg is not None:
                self._emit(node, "CIPHER", AlgorithmFamily.SYMMETRIC_CIPHER, confidence=0.5)
            return
        if algo_hit.canonical == "CIPHER-WRAPPER":  # pragma: no cover - catalog has no nested
            return
        # Suppress the nested algorithm and mode Calls so generic_visit
        # doesn't re-emit them as flat findings.
        key_size: int | None = None
        if isinstance(algorithm_arg, ast.Call):  # pragma: no branch
            self._suppressed_call_ids.add(id(algorithm_arg))
            key_size = self._aes_key_size(
                algorithm_arg, self._imports.resolve_attribute(algorithm_arg.func)
            )
        if isinstance(mode_arg, ast.Call):
            self._suppressed_call_ids.add(id(mode_arg))
        mode_name = self._resolve_mode_target(mode_arg)
        self._emit(
            node,
            algo_hit.canonical,
            algo_hit.family,
            confidence=1.0,
            key_size=key_size,
            mode=mode_name,
        )
        # When the algorithm construction sits on its own line (a Cipher(
        # call spanning multiple lines), also emit a finding at that line —
        # a line-level scanner/SARIF consumer expects the algorithm token
        # itself to carry a finding, not just the wrapper's opening line.
        # Same-line constructions already get exactly one finding above.
        if isinstance(algorithm_arg, ast.Call) and algorithm_arg.lineno != node.lineno:
            self._emit(
                algorithm_arg,
                algo_hit.canonical,
                algo_hit.family,
                confidence=1.0,
                key_size=key_size,
            )

    def _emit_oaep(self, node: ast.Call) -> None:
        """padding.OAEP(mgf=..., algorithm=hashes.X(), label=...) — resolve the
        top-level `algorithm=` hash literal so only RSA-OAEP-SHA1 (§3-banned)
        gets that specific padding token; other hashes still emit as "OAEP-<hash>"
        for the CBOM, just without matching the SHA1-scoped policy rule.
        """
        hash_name = self._oaep_hash(node)
        padding = f"OAEP-{hash_name.replace('-', '')}" if hash_name else "OAEP"
        self._emit(node, "RSA", AlgorithmFamily.ASYMMETRIC_ENCRYPTION, confidence=1.0,
                    padding=padding)

    def _oaep_hash(self, node: ast.Call) -> str | None:
        for kw in node.keywords:
            # Only the top-level `algorithm=` kwarg — not the `mgf=MGF1(algorithm=...)`
            # one nested inside it, which describes the mask-generation hash, not
            # the OAEP hash itself.
            if kw.arg == "algorithm" and isinstance(kw.value, ast.Call):
                qualified = self._imports.resolve_attribute(kw.value.func)
                if qualified is None:
                    return None
                hit = lookup_python_symbol(qualified)
                if hit is not None and hit.family == AlgorithmFamily.HASH:
                    return hit.canonical
        return None

    @staticmethod
    def _cipher_arg(node: ast.Call, *, position: int, keyword: str) -> ast.expr | None:
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
    def _aes_key_size(call: ast.Call, qualified: str | None) -> int | None:
        # AES128 / AES256 declare the key length in the class name; the key
        # argument is irrelevant. Callers only reach here with a resolved
        # qualified name, but the guard keeps the .endswith calls type-safe.
        if qualified is not None:  # pragma: no branch
            if qualified.endswith(".AES128"):
                return 128
            if qualified.endswith(".AES256"):
                return 256
        if qualified in _AES_CONSTRUCTORS:
            key_arg: ast.expr | None = call.args[0] if call.args else None
            if key_arg is None:
                for kw in call.keywords:
                    if kw.arg == "key":
                        key_arg = kw.value
                        break
            if key_arg is not None:
                return _bytes_literal_bits(key_arg)
        return None

    @staticmethod
    def _extract_key_size(node: ast.Call, qualified: str | None) -> int | None:
        aes_bits = PythonDetector._aes_key_size(node, qualified)
        if aes_bits is not None:
            return aes_bits
        for kw in node.keywords:
            if kw.arg == "key_size" and isinstance(kw.value, ast.Constant):
                value = kw.value.value
                # bool is an int subclass — exclude it explicitly so key_size=True
                # doesn't surface as key_size=1 in a security-sensitive field.
                if type(value) is int:
                    return value
        # pycryptodome takes the bit length as the first positional arg.
        pycryptodome_keygens = {
            "Crypto.PublicKey.RSA.generate",
            "Crypto.PublicKey.DSA.generate",
        }
        if (
            qualified in pycryptodome_keygens
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            value = node.args[0].value
            if type(value) is int:
                return value
        return None

    @staticmethod
    def _positional_or_kw_int(node: ast.Call, *, position: int, keyword: str) -> int | None:
        """Literal int at `position` (skipped when negative — keyword-only
        params like hashlib.scrypt's `n=`) or the `keyword` kwarg. bool is an
        int subclass — excluded so a stray True/False never reads as 1/0.
        """
        candidate: ast.expr | None = None
        if position >= 0 and position < len(node.args):
            candidate = node.args[position]
        for kw in node.keywords:
            if kw.arg == keyword:
                candidate = kw.value
                break
        if isinstance(candidate, ast.Constant) and type(candidate.value) is int:
            return candidate.value
        return None

    # KDF cost-parameter arg position (or -1 for keyword-only) + keyword name,
    # per B2 (OWASP-threshold policy gating). Variable/computed arguments (a
    # name, a `2**14` BinOp, ...) are not ast.Constant and yield None by
    # design — "literals only" per the policy engine's parameter-sets-below
    # contract; the finding itself still fires, just without a gateable value.
    _KDF_PARAM_SPECS: ClassVar[dict[str, tuple[int, str]]] = {
        "hashlib.pbkdf2_hmac": (3, "iterations"),
        "cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC": (3, "iterations"),
        "Crypto.Protocol.KDF.PBKDF2": (3, "count"),
        "hashlib.scrypt": (-1, "n"),
        "cryptography.hazmat.primitives.kdf.scrypt.Scrypt": (2, "n"),
        "Crypto.Protocol.KDF.scrypt": (3, "N"),
        "bcrypt.gensalt": (0, "rounds"),
    }

    @staticmethod
    def _extract_kdf_param(node: ast.Call, qualified: str | None) -> int | None:
        if qualified is None:
            return None
        spec = PythonDetector._KDF_PARAM_SPECS.get(qualified)
        if spec is None:
            return None
        position, keyword = spec
        return PythonDetector._positional_or_kw_int(node, position=position, keyword=keyword)

    def _extract_pycrypto_mode(self, node: ast.Call, qualified: str) -> str | None:
        """Return the mode for `Crypto.Cipher.<X>.new(key, X.MODE_Y, ...)`.

        Only fires for pycryptodome cipher `new` callees. The mode argument
        is the second positional argument or the `mode=` keyword, and must
        resolve to an attribute like `AES.MODE_ECB`.
        """
        if not (qualified.startswith("Crypto.Cipher.") and qualified.endswith(".new")):
            return None
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
        # pycryptodome passes the curve as a string literal (curve="p256").
        if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
            return normalize_curve(candidate.value)
        if not isinstance(candidate, ast.Call):
            return None
        if isinstance(candidate.func, ast.Attribute):
            return normalize_curve(candidate.func.attr)
        if isinstance(candidate.func, ast.Name):
            return normalize_curve(candidate.func.id)
        return None

    def _emit(
        self,
        # ast.Call for every ordinary catalog hit; ast.Attribute for the
        # constant-reference path (visit_Attribute) -- both carry lineno/
        # col_offset/end_lineno/end_col_offset, all this method touches.
        node: ast.Call | ast.Attribute,
        canonical: str,
        family: AlgorithmFamily,
        *,
        confidence: float,
        key_size: int | str | None = None,
        curve: str | None = None,
        mode: str | None = None,
        padding: str | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        # line/column override: used only for the chained-digest sub-finding,
        # where the reportable token (.digest()/.hexdigest()) sits on a
        # different line than node itself (see _emit_chained_digest).
        location = SourceLocation(
            path=self._path,
            line=line if line is not None else node.lineno,
            column=column if column is not None else node.col_offset,
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
                evidence=self._evidence(node, line=line),
                detector_id=_DETECTOR_ID,
                confidence=confidence,
            )
        )

    def _evidence(self, node: ast.Call | ast.Attribute, *, line: int | None = None) -> str:
        line_idx = (line if line is not None else node.lineno) - 1
        if 0 <= line_idx < len(self._source_lines):
            return self._source_lines[line_idx].strip()
        return ""  # pragma: no cover - empty file has no Call nodes to visit


def _normalize_hashlib_new_name(name: str) -> str:
    key = name.lower()
    if key.startswith("sha3-"):
        return key.replace("-", "_", 1)
    if key.startswith("sha-"):
        return key.replace("-", "", 1)
    return key


# AES constructors whose first positional argument is the key. The string key
# size comes from the key length; gated to these names so a non-key bytes
# argument (e.g. hash input in md5(b"...")) is never misread as a key length.
_AES_CONSTRUCTORS = frozenset(
    {
        "cryptography.hazmat.primitives.ciphers.algorithms.AES",
        "Crypto.Cipher.AES.new",
    }
)


def _bytes_literal_bits(expr: ast.expr) -> int | None:
    """Bit length of a bytes-literal key, or None if not a decidable literal.

    Handles a bytes constant and the constant-folded repeat ``b"..." * n``.
    Non-literal keys (a variable, a function call) stay undecidable by design.
    """
    if isinstance(expr, ast.Constant) and isinstance(expr.value, bytes):
        return len(expr.value) * 8
    if (
        isinstance(expr, ast.BinOp)
        and isinstance(expr.op, ast.Mult)
        and isinstance(expr.left, ast.Constant)
        and isinstance(expr.left.value, bytes)
        and isinstance(expr.right, ast.Constant)
        and type(expr.right.value) is int
        and expr.right.value >= 0
    ):
        return len(expr.left.value) * expr.right.value * 8
    return None


def detect_python_file(path: Path) -> list[CryptoFinding]:
    """Detect Python crypto primitive usage in `path`.

    Returns an empty list (never raises) for: any condition that makes
    read_source_bytes return None (missing/symlink/non-regular/oversized
    file — see that function for the file-IO hardening), encoding failure on
    both UTF-8 and Latin-1, a parse that fails with SyntaxError, ValueError,
    RecursionError, or MemoryError, or a visit pass that raises
    RecursionError/MemoryError.
    """
    raw = read_source_bytes(path)
    if raw is None:
        return []
    source: str | None = None
    for encoding in ("utf-8-sig", "latin-1"):
        try:
            source = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if source is None:  # pragma: no cover - latin-1 (last fallback) is total over bytes
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        # SyntaxError: unparseable source. ValueError: source with null bytes.
        # RecursionError: a deeply nested expression that recurses the parser
        # past the limit. MemoryError: a pathological tree that allocates
        # instead of recursing. All are untrusted-input cases that must not
        # abort the scan.
        return []
    detector = PythonDetector(source_path=path, source=source)
    try:
        detector.visit(tree)
    except (RecursionError, MemoryError):
        # Same latent-risk rationale as the ast.parse guard above: a
        # deep-but-parseable tree should degrade to empty findings, not
        # abort the scan. Not reachable on current CPython (parsing
        # recurses first) but cheap insurance against future parser changes.
        return []
    return detector.findings
