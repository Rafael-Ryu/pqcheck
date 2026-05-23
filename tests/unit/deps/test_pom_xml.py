import time
from pathlib import Path

from pqcheck.deps.base import MAX_FILE_BYTES
from pqcheck.deps.pom_xml import parse


def _write(tmp_path: Path, content: str) -> Path:
    f = tmp_path / "pom.xml"
    f.write_text(content, encoding="utf-8")
    return f


def test_parse_basic_pom(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    by_artifact = {d.name: d for d in deps}
    assert by_artifact["bcprov-jdk18on"].version == "1.78"
    assert by_artifact["bcprov-jdk18on"].purl == (
        "pkg:maven/org.bouncycastle/bcprov-jdk18on@1.78"
    )
    assert by_artifact["tink"].version == "1.14.0"
    assert all(d.ecosystem == "maven" for d in deps)


def test_parse_populates_introduces_algorithms(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert "RSA" in deps[0].introduces_algorithms
    assert "DES" in deps[0].introduces_algorithms


def test_parse_resolves_in_file_property_interpolation(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <properties>
    <bc.version>1.78</bc.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${bc.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "1.78"
    assert deps[0].purl.endswith("@1.78")


def test_parse_unresolvable_property_emits_none_version(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${missing.property}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version is None
    assert deps[0].purl == "pkg:maven/org.bouncycastle/bcprov-jdk18on"


def test_parse_skips_dependency_with_missing_artifact_id(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["tink"]


def test_parse_skips_dependency_with_missing_group_id(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    assert parse(f) == []


def test_parse_includes_dependency_management_section(tmp_path: Path) -> None:
    # dependencyManagement declares versions for downstream modules but
    # the artifacts are real coordinates and may introduce crypto. We
    # emit them; downstream policy decides whether to demote severity.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.78</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
""")
    deps = parse(f)
    assert [d.name for d in deps] == ["bcprov-jdk18on"]


def test_parse_deduplicates_coordinates(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
""")
    assert len(parse(f)) == 1


def test_parse_pom_without_namespace(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>com.google.crypto.tink</groupId>
      <artifactId>tink</artifactId>
      <version>1.14.0</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].name == "tink"


def test_parse_invalid_xml_returns_empty_list(tmp_path: Path) -> None:
    f = _write(tmp_path, "<project><dependencies><dependency></project>")
    assert parse(f) == []


def test_parse_missing_file_returns_empty_list(tmp_path: Path) -> None:
    assert parse(tmp_path / "no-pom.xml") == []


def test_parse_rejects_external_entity_payload(tmp_path: Path) -> None:
    # /etc/passwd is the canonical XXE target. If the parser resolves the
    # entity, &xxe; expands and ends up as the groupId text. We assert
    # the parser does NOT expand it: either the parse fails (returns [])
    # OR the dependency is emitted with the raw &xxe; reference preserved
    # / blanked. We accept either failure mode but FORBID the expanded
    # payload showing up.
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<project>
  <dependencies>
    <dependency>
      <groupId>&xxe;</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
"""
    f = _write(tmp_path, payload)
    deps = parse(f)
    for dep in deps:
        # No file contents leaked into the dep tree.
        assert "root:" not in dep.purl
        assert "root:" not in dep.name
        # group_id either stays empty (entity not resolved) or contains
        # the raw entity ref text. We do not allow /etc/passwd contents.
        assert "/etc/passwd" not in dep.purl


def test_parse_rejects_billion_laughs_payload(tmp_path: Path) -> None:
    # Classic billion-laughs: 10 nested entities each expanding 10x.
    # With resolve_entities=False, the parser never expands lol9, so the
    # whole document either parses cheaply (entity refs untouched) or
    # fails fast. EITHER way it must complete quickly without OOMing.
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
]>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>&lol5;</artifactId>
      <version>1.78</version>
    </dependency>
  </dependencies>
</project>
"""
    f = _write(tmp_path, payload)
    start = time.perf_counter()
    deps = parse(f)
    elapsed = time.perf_counter() - start
    # Hard cap: should finish in well under 1 second on any laptop. If
    # expansion ran, this hits multi-seconds and gigabytes of RAM.
    assert elapsed < 1.0
    for dep in deps:
        # No expansion: the artifactId never blooms into 100k "lol"s.
        assert len(dep.name) < 100


def test_parse_oversized_file_returns_empty_list(tmp_path: Path) -> None:
    f = tmp_path / "huge.xml"
    # Build a payload that is just over the cap. The body doesn't need to
    # parse — safe_read_bytes rejects before lxml sees it.
    f.write_bytes(b"<project/>" + b" " * MAX_FILE_BYTES)
    assert parse(f) == []
