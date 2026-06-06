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

from pqcheck.deps.base import golang_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

# Matches a single-line require: require module/path v1.2.3 [// ...]
_SINGLE_RE = re.compile(r"^\s*require\s+(\S+)\s+(v\S+)")

# Opens a block require ( ... ). A trailing line comment (`require ( // pinned`)
# is valid go.mod, so anything after the paren is tolerated.
_BLOCK_OPEN_RE = re.compile(r"^\s*require\s*\(")

# Closes a block: a line that is just `)` (optionally indented / commented).
_BLOCK_CLOSE_RE = re.compile(r"^\s*\)")

# Matches a module line inside a block: module path, version. A trailing
# `// indirect` or any comment is ignored by taking only groups 1+2.
_BLOCK_LINE_RE = re.compile(r"^\s*(\S+)\s+(v\S+)")


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []

    seen: set[tuple[str, str]] = set()
    deps: list[CryptoDependency] = []

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
    in_block = False
    for raw_line in text.split("\n"):
        line = raw_line.rstrip("\r")
        if in_block:
            if _BLOCK_CLOSE_RE.match(line):
                in_block = False
                continue
            line_m = _BLOCK_LINE_RE.match(line)
            if line_m:
                _add(line_m.group(1), line_m.group(2))
            continue
        if _BLOCK_OPEN_RE.match(line):
            in_block = True
            continue
        single_m = _SINGLE_RE.match(line)
        if single_m:
            _add(single_m.group(1), single_m.group(2))

    return deps
