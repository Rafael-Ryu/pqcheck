"""Release smoke: drive the *bundled* crypto-analyzer through its real pin.

Run against an installed wheel, not the source tree. It locates the packaged
binary, verifies it against the build-time SHA-256 pin, and runs the bridge over
a tiny real module — so the exec bit, the pin (computed the same way hatch_build
writes it and the bridge verifies it), and the go-types path are all exercised on
this platform before publish. Exits non-zero on any failure so a CI step gates on
it. Needs a `go` toolchain on PATH (the binary shells out to `go list`).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from pqcheck.detectors import go_module_detector as gmd
from pqcheck.detectors.go_module_detector import detect_go_module


def main() -> int:
    located = gmd._locate_binary()
    if located is None:
        print("FAIL: no bundled crypto-analyzer in the installed wheel", file=sys.stderr)
        return 1
    binary, trusted = located
    if trusted:
        print("FAIL: located via env override, not the bundled path", file=sys.stderr)
        return 1
    if not gmd._verify_sha256(binary, trusted=False):
        print("FAIL: bundled binary does not match its SHA-256 pin", file=sys.stderr)
        return 1

    module = Path(tempfile.mkdtemp())
    (module / "go.mod").write_text("module smoke\n\ngo 1.24\n", encoding="utf-8")
    (module / "main.go").write_text(
        'package main\nimport "crypto/md5"\nfunc main() { md5.New() }\n', encoding="utf-8"
    )
    findings = detect_go_module(module)
    # Union semantics (ADR 0005): tree-sitter findings may legitimately
    # coexist; what this smoke must prove is that the BUNDLED analyzer ran
    # through its pin and resolved the call semantically.
    if not any(f.detector_id == "go-types" and f.algorithm == "MD5" for f in findings):
        got = sorted((f.detector_id, f.algorithm) for f in findings)
        print(f"FAIL: no go-types MD5 finding from the bundled analyzer (got {got})",
              file=sys.stderr)
        return 1
    sites = {(str(f.location.path), f.location.line, f.algorithm) for f in findings}
    if len(sites) != len(findings):
        got = sorted((f.detector_id, str(f.location.path), f.location.line) for f in findings)
        print(f"FAIL: union dedup missed — duplicate call sites in {got}", file=sys.stderr)
        return 1
    algos = {f.algorithm for f in findings}
    print(f"OK: bundled analyzer verified its pin and resolved {sorted(algos)} via go-types")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
