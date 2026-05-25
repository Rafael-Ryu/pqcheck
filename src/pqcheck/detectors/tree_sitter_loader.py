"""Lazily-built, cached tree-sitter Language objects.

Go is the only grammar in v0.1. A Java accessor lands when the Java detector
does — no registry abstraction until a second grammar actually exists.
"""

from __future__ import annotations

from functools import cache

import tree_sitter_go
from tree_sitter import Language


@cache
def go_language() -> Language:
    return Language(tree_sitter_go.language())
