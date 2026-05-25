## Summary

`hashlib.new()` only recognizes a narrow set of literal names. Valid dashed/OpenSSL-style aliases such as `"sha-1"` and `"SHA-256"` are accepted by Python but ignored by the detector.

## Evidence

Python accepts these names:

```python
import hashlib
hashlib.new("sha-1")
hashlib.new("SHA-256")
```

Targeted detector reproduction:

```python
import ast
from pathlib import Path
from pqcheck.detectors.python_detector import PythonDetector

src = (
    "import hashlib\n"
    "hashlib.new('sha-1')\n"
    "hashlib.new('SHA-256')\n"
    "hashlib.new('sha1')\n"
)
tree = ast.parse(src)
detector = PythonDetector(Path("hashlib_aliases.py"), src)
detector.visit(tree)
print([(f.algorithm, f.evidence) for f in detector.findings])
```

Observed result:

```text
[('SHA-1', "hashlib.new('sha1')")]
```

## Impact

Broken or policy-relevant hashes can be missed when code uses valid aliases. In particular, `hashlib.new("sha-1")` should produce a broken-hash finding but currently produces none.

## Expected Fix

Normalize `hashlib.new()` literal names before lookup, or expand `_HASHLIB_NEW_NAMES` to include aliases accepted by the runtime/OpenSSL backend. Add regression tests for at least:

- `"sha-1"` -> `SHA-1`
- `"SHA-256"` -> `SHA-256`
- Existing names such as `"sha1"` and `"md5"`
