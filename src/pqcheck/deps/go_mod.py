"""Parser for go.mod dependency manifests.

Emits one CryptoDependency per unique (module_path, version) pair found in
`require` directives — both the single-line form and the block `require (...)`
form.

Out-of-scope for v0.1 (deliberate omissions, not oversights):
  - `replace` directives: resolving replacements requires knowing the full
    module graph (which replace chains can point at VCS paths or local dirs).
    Emitting the *declared* path without replacement is safe-by-default for
    crypto scanning because we'd only miss a replace that swaps in a
    different crypto library — an edge case that the Go crypto-analyzer
    binary (Phase 2) handles authoritatively.
  - `retract` directives: these mark versions as retracted in a module's
    *own* go.mod; they don't affect which version a downstream consumer
    imports.
"""

from __future__ import annotations

import re
from pathlib import Path

from pqcheck.deps.base import ManifestError, golang_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

# A require entry's version token: go requires `v...` (v1.2.3, v0.0.0-pre,
# v2.0.0+incompatible). Kept as loose as the historical regex (`v\S+`).
_VERSION_RE = re.compile(r"^v\S+$")

_REQUIRE_ENTRY_TOKENS = 2  # module path + version, nothing else


def _require_entry(tokens: list[str]) -> tuple[str, str] | None:
    """(module, version) when tokens match the require-entry grammar exactly."""
    if len(tokens) == _REQUIRE_ENTRY_TOKENS and _VERSION_RE.match(tokens[1]):
        return tokens[0], tokens[1]
    return None

# A go.sum line is `module version hash` (3 whitespace-separated fields).
_GO_SUM_MIN_FIELDS = 3


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"malformed go.mod: {exc}") from exc

    seen: set[tuple[str, str]] = set()
    deps: list[CryptoDependency] = []
    summed = _load_go_sum(path)

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

    # Single linear pass with a require-block state machine. Earlier this used a
    # lazy DOTALL regex to capture each `require ( ... )` body, which backtracked
    # to EOF from every opener when the closing paren was missing (~O(n^2) on
    # hostile input). Line-oriented scanning stays linear and never backtracks.
    # Split on the Go line terminator only. str.splitlines() also breaks on
    # form-feed, vertical-tab, NEL, and the Unicode line/paragraph separators,
    # none of which terminate a line in go.mod's lexer — splitting on them lets
    # a control char inside one physical line forge a second `require`.
    #
    # Tokens are matched exactly against the require grammar. A line that names
    # the require directive but fails its shape (missing/invalid version, extra
    # tokens) means `go` itself would refuse the file, so whatever we parsed is
    # a partial inventory — raise instead of passing off the prefix as complete.
    # Unknown or out-of-scope directives (module, go, replace, ...) stay ignored:
    # they do not feed the require inventory this parser reports.
    in_block = False
    for lineno, raw_line in enumerate(text.split("\n"), start=1):
        # `//` starts a comment in go.mod and cannot occur inside a module path
        # (import paths use single slashes), so a plain prefix split is safe.
        # Parens are their own tokens in go.mod's lexer (`require(` opens a
        # block); module paths cannot contain them, so padding is lossless.
        code = raw_line.rstrip("\r").split("//", 1)[0]
        tokens = code.replace("(", " ( ").replace(")", " ) ").split()
        if in_block:
            if not tokens:
                continue
            if tokens == [")"]:
                in_block = False
                continue
            entry = _require_entry(tokens)
            if entry is None:
                raise ManifestError(f"malformed go.mod: invalid require entry at line {lineno}")
            _add(*entry)
        elif tokens[:1] == ["require"]:
            rest = tokens[1:]
            if rest == ["("]:
                in_block = True
                continue
            entry = _require_entry(rest)
            if entry is None:
                raise ManifestError(
                    f"malformed go.mod: invalid require directive at line {lineno}"
                )
            _add(*entry)

    if in_block:
        # `require (` with no closing paren: `go` itself refuses the file, so
        # whatever we parsed out of it is a partial inventory, not a complete
        # one. Report it rather than passing off the prefix as the whole thing.
        raise ManifestError("malformed go.mod: unclosed require block")

    return deps


def _load_go_sum(go_mod_path: Path) -> set[tuple[str, str]] | None:
    """Index the (module, version) pairs checksummed in the sibling go.sum.

    Returns None when no go.sum sits next to go.mod, or when it is oversized
    (nothing trustworthy to cross-reference, so callers make no integrity
    claim — integrity_verified=None, never a positive "verified"). go.sum
    lines are `module version hash` and `module version/go.mod hash`; the
    `/go.mod` suffix is stripped so both forms collapse to the same
    (module, version) key the require block uses.
    """
    try:
        raw = safe_read_bytes(go_mod_path.with_name("go.sum"))
    except ManifestError:
        # An oversized go.sum must not discard the whole require inventory;
        # degrading to "no integrity claim" is honest (no positive assertion).
        return None
    if raw is None:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    summed: set[tuple[str, str]] = set()
    for raw_line in text.split("\n"):
        parts = raw_line.split()
        if len(parts) < _GO_SUM_MIN_FIELDS:
            continue
        module, version = parts[0], parts[1].removesuffix("/go.mod")
        summed.add((module, version))
    return summed
