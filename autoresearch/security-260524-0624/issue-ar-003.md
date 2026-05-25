## Summary

PyCryptodome mode constants such as `AES.MODE_ECB` and `AES.MODE_GCM` are not emitted in findings. The detector reports the algorithm but leaves `mode=None`, so weak modes like ECB are not visible to downstream policy.

## Evidence

The catalog contains PyCryptodome mode mappings:

- `src/pqcheck/detectors/algorithms.py:117` maps `Crypto.Cipher.AES.MODE_GCM`, `MODE_CBC`, `MODE_ECB`, etc.

But `PythonDetector._resolve_mode_target()` only accepts `ast.Call` nodes:

- `src/pqcheck/detectors/python_detector.py:151`

PyCryptodome passes the mode as an attribute constant, not a call.

Targeted reproduction:

```python
import ast
from pathlib import Path
from pqcheck.detectors.python_detector import PythonDetector

src = (
    "from Crypto.Cipher import AES\n"
    "AES.new(key, AES.MODE_ECB)\n"
    "AES.new(key, mode=AES.MODE_GCM)\n"
)
tree = ast.parse(src)
detector = PythonDetector(Path("demo.py"), src)
detector.visit(tree)
for finding in detector.findings:
    print(finding.algorithm, finding.mode, finding.evidence)
```

Observed result:

```text
AES None AES.new(key, AES.MODE_ECB)
AES None AES.new(key, mode=AES.MODE_GCM)
```

## Impact

The scanner cannot distinguish AES-GCM from AES-ECB for PyCryptodome call sites. That hides an important cryptographic weakness from severity scoring and remediation guidance.

## Expected Fix

Teach the PyCryptodome direct-call path (`Crypto.Cipher.AES.new`, `DES.new`, `DES3.new`, etc.) to inspect the mode argument by position and by `mode=` keyword, resolve `ast.Attribute` constants via `ImportResolver.resolve_attribute()`, and pass the resolved mode into `_emit()`.

Add unit and integration tests asserting `AES.MODE_ECB` yields `mode="ECB"` and `AES.MODE_GCM` yields `mode="GCM"`.
