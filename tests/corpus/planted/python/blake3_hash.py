"""Planted fixture: blake3 (oconnor663/blake3-py official bindings).

Not real code — do not import. See tests/corpus/planted/expected.yaml.
Mirrors the borgbackup usage style that surfaced this catalog gap
(held-out benchmark, 2026-07-13): `from blake3 import blake3`, plain and
keyed hashing.
"""

from blake3 import blake3

plain_digest = blake3(b"x").digest()
keyed_digest = blake3(b"x", key=b"k" * 32).digest()
