"""Scan orchestrator: walk, detect, parse dependencies, evaluate policy.

The contract mirrors the parsers' never-raise rule at scan scope: one
hostile or unreadable file never aborts the scan. Failures are recorded in
`ScanResult.errors` ("path: ExcName: message") and the walk continues.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from pqcheck import __version__
from pqcheck.deps import (
    go_mod,
    package_lock_json,
    pom_xml,
    pyproject_toml,
    requirements_txt,
    uv_lock,
)
from pqcheck.detectors.go_detector import detect_go_file
from pqcheck.detectors.go_module_detector import (
    claimed_go_files,
    detect_go_module,
    group_go_files_by_module,
)
from pqcheck.detectors.python_detector import detect_python_file
from pqcheck.discover.walker import discover
from pqcheck.models import CryptoDependency, CryptoFinding, ScanResult
from pqcheck.policy.engine import evaluate
from pqcheck.policy.schema import CryptoPolicy

_MANIFEST_PARSERS: dict[str, Callable[[Path], list[CryptoDependency]]] = {
    "pyproject.toml": pyproject_toml.parse,
    "uv.lock": uv_lock.parse,
    "requirements.txt": requirements_txt.parse,
    "pom.xml": pom_xml.parse,
    "go.mod": go_mod.parse,
    "package-lock.json": package_lock_json.parse,
}

def _swallow[T](
    fn: Callable[[Path], list[T]], target: Path, sink: list[T], errors: list[str]
) -> None:
    try:
        sink.extend(fn(target))
    except Exception as exc:  # one bad input must never abort the scan
        errors.append(f"{target}: {exc.__class__.__name__}: {exc}")


def scan(root: Path, policy: CryptoPolicy | None = None) -> ScanResult:
    root = root.resolve()
    discovery = discover(root)
    errors = list(discovery.errors)
    findings: list[CryptoFinding] = []
    dependencies: list[CryptoDependency] = []

    for py_file in discovery.python_files:
        _swallow(detect_python_file, py_file, findings, errors)

    grouping = group_go_files_by_module(discovery.go_files, scan_root=root)
    claimed = claimed_go_files(grouping)
    for module_root in sorted(r for r in grouping if r is not None):
        _swallow(detect_go_module, module_root, findings, errors)
    for go_file in discovery.go_files:
        if go_file not in claimed:
            _swallow(detect_go_file, go_file, findings, errors)

    for manifest in discovery.manifests:
        parser = _MANIFEST_PARSERS.get(manifest.name)
        if parser is not None:
            _swallow(parser, manifest, dependencies, errors)

    findings.sort(
        key=lambda f: (str(f.location.path), f.location.line, f.location.column, f.algorithm)
    )
    dependencies.sort(key=lambda d: (str(d.declared_in), d.purl))

    decisions = tuple(evaluate(findings, policy)) if policy is not None else ()
    policy_id = (
        f"{policy.metadata.name}-{policy.metadata.version}" if policy is not None else None
    )
    return ScanResult(
        target=root,
        scanner_version=__version__,
        findings=tuple(findings),
        dependencies=tuple(dependencies),
        policy_decisions=decisions,
        policy_id=policy_id,
        errors=tuple(errors),
    )
