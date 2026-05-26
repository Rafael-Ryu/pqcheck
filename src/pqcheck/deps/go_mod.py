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
_SINGLE_RE = re.compile(
    r"^\s*require\s+(\S+)\s+(v\S+)",
    re.MULTILINE,
)

# Matches a block require ( ... ) — captures the inner content. `[^\n]*` after
# the paren tolerates a trailing line comment (`require ( // pinned deps`), which
# is valid go.mod and would otherwise make the whole block fail to match.
_BLOCK_RE = re.compile(
    r"^\s*require\s*\([^\n]*\n(.*?)\n\s*\)",
    re.MULTILINE | re.DOTALL,
)

# Matches a module line inside a block: leading whitespace, module path, version.
# The trailing `// indirect` or any comment is ignored by taking only groups 1+2.
_BLOCK_LINE_RE = re.compile(r"^\s*(\S+)\s+(v\S+)", re.MULTILINE)


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
        deps.append(
            CryptoDependency(
                purl=golang_purl(module_path, version),
                name=module_path,
                version=version,
                ecosystem="golang",
                declared_in=path,
                introduces_algorithms=lookup_introduces("golang", module_path),
            )
        )

    for m in _BLOCK_RE.finditer(text):
        block_body = m.group(1)
        for line_m in _BLOCK_LINE_RE.finditer(block_body):
            _add(line_m.group(1), line_m.group(2))

    # Remove block regions before scanning for single-line requires so we
    # don't double-count anything that looks like a single-line require
    # inside a block (shouldn't happen in valid go.mod but be defensive).
    stripped = _BLOCK_RE.sub("", text)
    for m in _SINGLE_RE.finditer(stripped):
        _add(m.group(1), m.group(2))

    return deps
