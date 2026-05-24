"""Parser for Maven pom.xml — hardened against XXE and billion-laughs.

We use lxml.etree with the following parser config:
  - resolve_entities=False  -> entity refs (incl. external) are not expanded
  - no_network=True         -> no network fetches for DTDs / schemas
  - huge_tree=False         -> reject documents with insane depth / breadth
  - dtd_validation=False    -> no DTD validation
  - load_dtd=False          -> no DTD loading at all
  - recover=False           -> fail fast on malformed XML

Property interpolation is in-file only: <properties><foo>1.2</foo></properties>
substitutes ${foo} in <version> text. Parent-POM walking and effective-pom
expansion are Phase 3 per spec 03:422.

Namespace handling: Maven 4 POMs use xmlns="http://maven.apache.org/POM/4.0.0"
but the literal namespace is sometimes absent. We match elements by local
name only via etree.QName(...).localname.
"""

from __future__ import annotations

import re
from pathlib import Path

from lxml import etree

from pqcheck.deps.base import maven_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

_PROPERTY_REF_RE = re.compile(r"\$\{([^}]+)\}")


def _build_parser() -> etree.XMLParser[etree._Element]:
    # Hardening flags passed explicitly (not via dict-unpack) so mypy can
    # match the XMLParser overload. resolve_entities=False is the
    # load-bearing flag: flipping it to True causes the XXE test to leak
    # /etc/passwd into the PURL. The other flags are defense-in-depth.
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        huge_tree=False,
        dtd_validation=False,
        load_dtd=False,
        recover=False,
    )


def parse(path: Path) -> list[CryptoDependency]:
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        root = etree.fromstring(raw, parser=_build_parser())
    except etree.XMLSyntaxError:
        return []
    if root is None:  # pragma: no cover - lxml raises rather than returning None
        return []

    properties = _collect_properties(root)
    seen: set[tuple[str, str, str | None]] = set()
    deps: list[CryptoDependency] = []
    for dep_el in _iter_dependency_elements(root):
        group_id = _child_text(dep_el, "groupId")
        artifact_id = _child_text(dep_el, "artifactId")
        version_raw = _child_text(dep_el, "version")
        if not group_id or not artifact_id:
            continue
        version = _resolve_version(version_raw, properties)
        key = (group_id, artifact_id, version)
        if key in seen:
            continue
        seen.add(key)
        deps.append(
            CryptoDependency(
                purl=maven_purl(group_id, artifact_id, version),
                name=artifact_id,
                version=version,
                ecosystem="maven",
                declared_in=path,
                introduces_algorithms=lookup_introduces("maven", artifact_id),
            )
        )
    return deps


def _local(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return etree.QName(tag).localname


def _child_text(element: etree._Element, local_name: str) -> str | None:
    for child in element:
        if _local(child.tag) == local_name:
            text = child.text
            if isinstance(text, str):
                stripped = text.strip()
                return stripped or None
    return None


def _collect_properties(root: etree._Element) -> dict[str, str]:
    """Return name -> value for entries in the top-level <properties> block.

    Nested property blocks inside profiles or build configs are ignored
    for v0.1 — covering them requires profile activation logic that
    belongs in the Phase 3 effective-pom resolver.
    """
    properties: dict[str, str] = {}
    for child in root:
        if _local(child.tag) != "properties":
            continue
        for prop in child:
            name = _local(prop.tag)
            text = prop.text
            if name and isinstance(text, str):
                stripped = text.strip()
                if stripped:
                    properties[name] = stripped
    return properties


def _iter_dependency_elements(root: etree._Element) -> list[etree._Element]:
    """Yield every <dependency> element under <dependencies> or
    <dependencyManagement>/<dependencies>, regardless of namespace."""
    deps: list[etree._Element] = []
    for child in root:
        tag = _local(child.tag)
        if tag == "dependencies":
            deps.extend(_direct_dependency_children(child))
        elif tag == "dependencyManagement":
            for grand in child:
                if _local(grand.tag) == "dependencies":
                    deps.extend(_direct_dependency_children(grand))
    return deps


def _direct_dependency_children(parent: etree._Element) -> list[etree._Element]:
    return [child for child in parent if _local(child.tag) == "dependency"]


def _resolve_version(version_raw: str | None, properties: dict[str, str]) -> str | None:
    """Substitute every ${name} token in `version_raw` using `properties`.

    Returns None if any referenced property is missing — fail closed
    rather than emit a half-substituted version. A version without any
    ${...} token is returned as-is.
    """
    if version_raw is None:
        return None
    unresolved = False

    def _sub(match: re.Match[str]) -> str:
        nonlocal unresolved
        value = properties.get(match.group(1))
        if value is None:
            unresolved = True
            return match.group(0)
        return value

    result = _PROPERTY_REF_RE.sub(_sub, version_raw)
    if unresolved:
        return None
    return result
