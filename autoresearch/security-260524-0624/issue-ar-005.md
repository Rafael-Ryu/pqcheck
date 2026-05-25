## Summary

`ImportResolver` records star imports from crypto modules, but `PythonDetector` never surfaces that sentinel. Code such as `from hashlib import *; md5(...)` produces no finding.

## Evidence

The comment in `src/pqcheck/detectors/python_detector.py:25` says files using star imports for crypto modules are flagged via `has_star_import()`. The sentinel is recorded at `src/pqcheck/detectors/python_detector.py:84`, but no detector path emits a finding or skip warning from it.

Targeted reproduction:

```python
import ast
from pathlib import Path
from pqcheck.detectors.python_detector import PythonDetector

samples = {
    "star_hashlib": "from hashlib import *\nmd5(b'x')\n",
    "direct_hashlib": "from hashlib import md5\nmd5(b'x')\n",
}

for name, src in samples.items():
    tree = ast.parse(src)
    detector = PythonDetector(Path(f"{name}.py"), src)
    detector.visit(tree)
    print(name, [(f.algorithm, f.evidence) for f in detector.findings])
```

Observed result:

```text
star_hashlib []
direct_hashlib [('MD5', "md5(b'x')")]
```

## Impact

Crypto use hidden behind star imports is silently missed. That is a false-negative risk for legacy Python codebases where `from hashlib import *` or `from Crypto.Hash.MD5 import *` patterns can appear.

## Expected Fix

Either expand known star-import modules conservatively for common crypto APIs, or emit an explicit low-confidence/unknown finding or skipped-file diagnostic when a crypto module star import is present.

Add tests for at least `from hashlib import *` and one PyCryptodome star-import pattern.
