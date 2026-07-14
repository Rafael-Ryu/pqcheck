"""Parser for go.mod dependency manifests.

Emits one CryptoDependency per unique (module_path, version) pair found in
`require` directives — both the single-line form and the block `require (...)`
form.

Every *known* directive (module, go, toolchain, require, exclude, replace,
retract) is validated against go.mod's grammar even when it does not feed the
require inventory: a malformed known directive means `go` itself would refuse
the file, so whatever we parsed is a partial inventory — raise instead of
passing off the prefix as complete. Syntactically valid unknown/future
directives (tool, godebug, ...) stay ignored.

Out-of-scope for v0.1 (deliberate omissions, not oversights):
  - resolving `replace` directives: that requires knowing the full module
    graph (replace chains can point at VCS paths or local dirs). Emitting the
    *declared* path without replacement is safe-by-default for crypto scanning
    because we'd only miss a replace that swaps in a different crypto library
    — an edge case the Go crypto-analyzer binary handles authoritatively.
  - resolving `retract` directives: these mark versions as retracted in a
    module's *own* go.mod; they don't affect which version a downstream
    consumer imports.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

from pqcheck.deps.base import ManifestError, golang_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

# A require entry's version token: go requires `v...` (v1.2.3, v0.0.0-pre,
# v2.0.0+incompatible). Kept as loose as the historical regex (`v\S+`).
_VERSION_RE = re.compile(r"^v\S+$")

# GoVersion: `1.21`, `1.21.0`, `1.21rc1`, `1.21beta1`.
_GO_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?([a-z]+\d+)?$")

# RetractSpec versions cannot carry the interval punctuation; the loose
# `v\S+` would swallow a stray `,` or `]` and accept junk like `[v1.0.0,]`.
_RETRACT_VERSION = r"v[^\s,\[\]]+"
_RETRACT_SINGLE_RE = re.compile(rf"^{_RETRACT_VERSION}$")
_RETRACT_INTERVAL_RE = re.compile(rf"^\[{_RETRACT_VERSION},{_RETRACT_VERSION}\]$")

_REQUIRE_ENTRY_TOKENS = 2  # module path + version, nothing else
_MODULE_VERSION_TOKENS = 2  # `module/path v1.2.3` — one side of a replace


def _require_entry(tokens: list[str]) -> tuple[str, str] | None:
    """(module, version) when tokens match the require-entry grammar exactly."""
    if (
        len(tokens) == _REQUIRE_ENTRY_TOKENS
        and tokens[0]
        and _VERSION_RE.match(tokens[1])
    ):
        return tokens[0], tokens[1]
    return None


def lex_go_mod_line(line: str) -> list[str] | None:
    """Tokens of one go.mod line, or None when it cannot be lexed safely.

    A minimal fail-closed lexer for the token shapes go.mod's own lexer
    produces: bare tokens, interpreted strings (`"..."`, honoring only the
    `\\\\` and `\\"` escapes), raw strings (backticks), `//` comments, and
    `(`/`)` as standalone punctuation. Anything it cannot decide —
    unterminated string, unsupported escape, a raw string that would span
    lines — returns None so callers treat the file as hostile instead of
    guessing. A naive whitespace split turned a quoted path containing a
    space into two RHS tokens, which read as a module+version replacement.
    """
    tokens: list[str] = []
    i, size = 0, len(line)
    while i < size:
        ch = line[i]
        if ch in " \t":
            i += 1
        elif line.startswith("//", i):
            break
        elif ch in "()":
            tokens.append(ch)
            i += 1
        elif ch == '"':
            lexed = _lex_interpreted_string(line, i)
            if lexed is None:
                return None  # unterminated string or an escape we do not model
            token, i = lexed
            tokens.append(token)
        elif ch == "`":
            end = line.find("`", i + 1)
            if end == -1:
                return None  # unterminated raw string (could span lines)
            tokens.append(line[i + 1 : end])
            i = end + 1
        else:
            j = i
            while j < size and line[j] not in ' \t"`()' and not line.startswith("//", j):
                j += 1
            tokens.append(line[i:j])
            i = j
    return tokens


def _lex_interpreted_string(line: str, start: int) -> tuple[str, int] | None:
    """Decode the `"..."` string opening at line[start]; (value, next_index),
    or None (fail closed) on an unterminated string or unmodelled escape."""
    i = start + 1
    size = len(line)
    buf: list[str] = []
    while i < size and line[i] != '"':
        if line[i] == "\\":
            if i + 1 >= size or line[i + 1] not in '\\"':
                return None
            buf.append(line[i + 1])
            i += 2
        else:
            buf.append(line[i])
            i += 1
    if i >= size:
        return None
    return "".join(buf), i + 1


def dir_shaped(token: str) -> bool:
    """True when `token` is a filesystem-path replacement target per go.mod's
    grammar: rooted, or starting with `./` / `../` (go rejects anything else
    as a versionless replacement)."""
    if token in (".", "..") or token.startswith(("./", "../")):
        return True
    if sys.platform == "win32" and token.startswith((".\\", "..\\")):  # pragma: no cover
        return True
    return Path(token).is_absolute()


def _module_entry_ok(tokens: list[str]) -> bool:
    return len(tokens) == 1


def _go_entry_ok(tokens: list[str]) -> bool:
    return len(tokens) == 1 and _GO_VERSION_RE.match(tokens[0]) is not None


def _toolchain_entry_ok(tokens: list[str]) -> bool:
    # ToolchainName = "default" | "go" GoVersion [suffix]
    return len(tokens) == 1 and (tokens[0] == "default" or tokens[0].startswith("go"))


def _exclude_entry_ok(tokens: list[str]) -> bool:
    return _require_entry(tokens) is not None


def _replace_entry_ok(tokens: list[str]) -> bool:
    """ReplaceSpec: `mod [ver] => mod ver` or `mod [ver] => dir` — the same
    two safe shapes the boundary check in go_module_detector enforces."""
    if tokens.count("=>") != 1:
        return False
    split = tokens.index("=>")
    lhs, rhs = tokens[:split], tokens[split + 1 :]
    if len(lhs) not in (1, _MODULE_VERSION_TOKENS) or dir_shaped(lhs[0]):
        return False
    if len(lhs) == _MODULE_VERSION_TOKENS and not _VERSION_RE.match(lhs[1]):
        return False
    if len(rhs) == _MODULE_VERSION_TOKENS:
        return bool(_VERSION_RE.match(rhs[1])) and not dir_shaped(rhs[0])
    return len(rhs) == 1 and dir_shaped(rhs[0])


def _retract_entry_ok(tokens: list[str]) -> bool:
    # RetractSpec = Version | "[" Version "," Version "]". The lexer does not
    # split on `[`/`,`/`]`, so an interval arrives as 1..N tokens depending on
    # spacing — joining normalizes that before matching.
    joined = "".join(tokens)
    if len(tokens) == 1 and _RETRACT_SINGLE_RE.match(joined):
        return True
    return _RETRACT_INTERVAL_RE.match(joined) is not None


# require is handled inline (its entries feed the inventory); everything else
# is validate-and-discard.
_ENTRY_VALIDATORS: dict[str, Callable[[list[str]], bool]] = {
    "module": _module_entry_ok,
    "go": _go_entry_ok,
    "toolchain": _toolchain_entry_ok,
    "exclude": _exclude_entry_ok,
    "replace": _replace_entry_ok,
    "retract": _retract_entry_ok,
}
_KNOWN_DIRECTIVES = frozenset({"require", *_ENTRY_VALIDATORS})
# Per go.mod's grammar, go and toolchain are single-line only.
_BLOCK_FORM_DIRECTIVES = frozenset({"module", "require", "exclude", "replace", "retract"})


def _entry_ok(directive: str, tokens: list[str]) -> bool:
    if "(" in tokens or ")" in tokens or not all(tokens):
        return False
    return _ENTRY_VALIDATORS[directive](tokens)


# A go.sum line is `module version hash` (3 whitespace-separated fields).
_GO_SUM_MIN_FIELDS = 3


def parse(path: Path, errors: list[str] | None = None) -> list[CryptoDependency]:
    """Parse `path` into CryptoDependency entries.

    `errors` (when provided) collects non-fatal diagnostics — currently a
    go.sum companion that exists but could not be used for integrity
    cross-referencing. Those must not discard the require inventory, but a
    scan that silently dropped integrity analysis would conflate "skipped by
    a resource cap" with "no checksum companion exists".
    """
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"malformed go.mod: {exc}") from exc

    seen: set[tuple[str, str]] = set()
    deps: list[CryptoDependency] = []
    summed = _load_go_sum(path, errors)

    def _add(module_path: str, version: str) -> None:
        key = (module_path, version)
        if key in seen:
            return
        seen.add(key)
        purl = golang_purl(module_path, version)
        if purl is None:
            return
        deps.append(
            CryptoDependency(
                purl=purl,
                name=module_path,
                version=version,
                ecosystem="golang",
                declared_in=path,
                introduces_algorithms=lookup_introduces("golang", module_path),
                # No go.sum to consult => no claim at all (None), not a
                # positive "verified" the CBOM would then publish.
                integrity_verified=None if summed is None else key in summed,
            )
        )

    _parse_directives(text, _add)
    return deps


def _parse_directives(text: str, add: Callable[[str, str], None]) -> None:
    """Validate every known directive and feed require entries to `add`.

    Single linear pass with a directive-block state machine. Earlier this
    used a lazy DOTALL regex to capture each `require ( ... )` body, which
    backtracked to EOF from every opener when the closing paren was missing
    (~O(n^2) on hostile input). Line-oriented scanning stays linear.
    Split on the Go line terminator only. str.splitlines() also breaks on
    form-feed, vertical-tab, NEL, and the Unicode line/paragraph separators,
    none of which terminate a line in go.mod's lexer — splitting on them lets
    a control char inside one physical line forge a second `require`.
    """
    in_block: str | None = None
    for lineno, raw_line in enumerate(text.split("\n"), start=1):
        tokens = lex_go_mod_line(raw_line.rstrip("\r"))
        if tokens is None:
            raise ManifestError(f"malformed go.mod: line {lineno} cannot be lexed")
        if not tokens:
            continue
        if in_block is not None:
            in_block = _block_line(in_block, tokens, lineno, add)
        else:
            in_block = _directive_line(tokens, lineno, add)
    if in_block is not None:
        # An unclosed block: `go` itself refuses the file, so whatever we
        # parsed is a partial inventory, not a complete one.
        raise ManifestError(f"malformed go.mod: unclosed {in_block} block")


def _block_line(
    directive: str, tokens: list[str], lineno: int, add: Callable[[str, str], None]
) -> str | None:
    """One line inside a `directive ( ... )` block; the still-open directive
    (or None once the block closes)."""
    if tokens == [")"]:
        return None
    if directive == "require":
        entry = _require_entry(tokens)
        if entry is None:
            raise ManifestError(f"malformed go.mod: invalid require entry at line {lineno}")
        add(*entry)
    elif not _entry_ok(directive, tokens):
        raise ManifestError(f"malformed go.mod: invalid {directive} entry at line {lineno}")
    return directive


def _directive_line(
    tokens: list[str], lineno: int, add: Callable[[str, str], None]
) -> str | None:
    """One top-level line; the directive whose block it opens, if any."""
    directive = tokens[0]
    if directive not in _KNOWN_DIRECTIVES:
        # Syntactically valid unknown/future directives (tool, godebug, ...)
        # are not validated: they do not feed this inventory and rejecting
        # them would break on every new go release.
        return None
    rest = tokens[1:]
    if rest == ["("]:
        if directive not in _BLOCK_FORM_DIRECTIVES:
            raise ManifestError(
                f"malformed go.mod: invalid {directive} directive at line {lineno}"
            )
        return directive
    if directive == "require":
        entry = _require_entry(rest)
        if entry is None:
            raise ManifestError(
                f"malformed go.mod: invalid require directive at line {lineno}"
            )
        add(*entry)
    elif not _entry_ok(directive, rest):
        raise ManifestError(
            f"malformed go.mod: invalid {directive} directive at line {lineno}"
        )
    return None


def _load_go_sum(
    go_mod_path: Path, errors: list[str] | None
) -> set[tuple[str, str]] | None:
    """Index the (module, version) pairs checksummed in the sibling go.sum.

    Returns None when there is nothing trustworthy to cross-reference, so
    callers make no integrity claim (integrity_verified=None, never a
    positive "verified"). When a go.sum exists but was skipped (oversized,
    not UTF-8), that is NOT the same as "no checksum companion" — the skip is
    recorded in `errors` so the scan reports its inventory as incomplete
    instead of silently dropping integrity analysis. go.sum lines are
    `module version hash` and `module version/go.mod hash`; the `/go.mod`
    suffix is stripped so both forms collapse to the same (module, version)
    key the require block uses.
    """
    go_sum = go_mod_path.with_name("go.sum")
    try:
        raw = safe_read_bytes(go_sum)
    except ManifestError as exc:
        # Oversized go.sum must not discard the whole require inventory, but
        # the suppressed integrity analysis must not pass as a clean scan.
        if errors is not None:
            errors.append(f"{go_sum}: ManifestError: {exc}")
        return None
    if raw is None:
        return None  # no companion exists: legitimately no claim to make
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        if errors is not None:
            errors.append(f"{go_sum}: ManifestError: malformed go.sum: {exc}")
        return None
    summed: set[tuple[str, str]] = set()
    for raw_line in text.split("\n"):
        parts = raw_line.split()
        if len(parts) < _GO_SUM_MIN_FIELDS:
            continue
        module, version = parts[0], parts[1].removesuffix("/go.mod")
        summed.add((module, version))
    return summed
