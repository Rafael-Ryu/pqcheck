## Summary

`detect_python_file()` uses `path.stat()` followed by `path.read_bytes()`. Because both follow symlinks, a repository containing a symlink such as `z.py -> /dev/zero` can make the scanner block indefinitely or consume unbounded memory.

## Evidence

Relevant code:

- `src/pqcheck/detectors/python_detector.py:316` checks `path.stat().st_size`.
- `src/pqcheck/detectors/python_detector.py:322` then calls `path.read_bytes()`.

Targeted reproduction:

```bash
timeout 2s bash -lc 'tmp=$(mktemp -d); ln -s /dev/zero "$tmp/z.py"; PYTHONPATH=src python - <<PY
from pathlib import Path
from pqcheck.detectors.python_detector import detect_python_file
print(detect_python_file(Path("$tmp/z.py")))
PY'
echo $?
```

Observed result:

```text
124
```

`124` is `timeout` killing the process after two seconds.

## Impact

Scanning an untrusted repository can hang on a committed symlink to a non-regular file. This is a denial-of-service risk for local scans and any future CI/service workflow that scans user-controlled repositories.

The dependency parsers already avoid this class of bug through `safe_read_bytes()` in `src/pqcheck/deps/base.py`, which uses `O_NOFOLLOW`, rejects non-regular files, and caps reads.

## Expected Fix

Use a shared safe reader for Python source files as well, or implement equivalent protections:

- Reject symlinks.
- Reject non-regular files.
- Enforce the byte cap against the opened file descriptor.
- Avoid `Path.read_bytes()` for untrusted repository paths.

Add tests for a symlink to `/dev/zero` and a FIFO/non-regular file, matching the existing dependency parser hardening tests.
