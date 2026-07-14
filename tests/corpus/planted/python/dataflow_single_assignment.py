"""Planted fixture: single-assignment dataflow (Task C2).

`h = hashlib.sha256()` / `signature = hmac.new(...)` single-assigned once in
a function, then `.digest()`/`.hexdigest()` called on the variable a few
lines later -- the constructor call site and the method-call site are both
expected findings. See tests/corpus/planted/expected.yaml and README.md.

Not real code — do not import.
"""

import hashlib
import hmac


def checksum(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def sign(key: bytes, text: bytes) -> bytes:
    signature = hmac.new(key, text, hashlib.sha1)
    return signature.digest()
