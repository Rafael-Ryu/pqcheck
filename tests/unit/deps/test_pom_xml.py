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


def test_parse_resolves_embedded_property_in_version(tmp_path: Path) -> None:
    # Maven supports ${prop} embedded inside a larger version string, e.g.
    # "${jackson.version}-RELEASE". The detector must substitute, not return None.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <properties>
    <jackson.version>2.15.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson</groupId>
      <artifactId>jackson-core</artifactId>
      <version>${jackson.version}-RELEASE</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "2.15.0-RELEASE"
    assert deps[0].purl.endswith("@2.15.0-RELEASE")


def test_parse_unresolvable_embedded_property_emits_none(tmp_path: Path) -> None:
    # Fail-closed: any unresolved ${name} in the version forces version=None.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <properties>
    <jackson.version>2.15.0</jackson.version>
  </properties>
  <dependencies>
    <dependency>
      <groupId>com.fasterxml.jackson</groupId>
      <artifactId>jackson-core</artifactId>
      <version>${jackson.version}-${missing.suffix}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version is None


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


def test_parse_resolves_nested_property_reference(tmp_path: Path) -> None:
    # Maven resolves properties recursively: ${a} where a=${b} and b=1.2
    # must yield 1.2, not the literal token ${b}.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <properties>
    <a>${b}</a>
    <b>1.2</b>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${a}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "1.2"
    assert deps[0].purl.endswith("@1.2")


def test_parse_cyclic_property_reference_emits_none(tmp_path: Path) -> None:
    # a -> b -> a never resolves; fail closed rather than loop or leak a token.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <properties>
    <a>${b}</a>
    <b>${a}</b>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${a}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version is None
    assert deps[0].purl == "pkg:maven/org.bouncycastle/bcprov-jdk18on"


def test_parse_entity_bearing_version_emits_none(tmp_path: Path) -> None:
    # An internal entity inside <version> is not expanded (XXE hardening).
    # The value must NOT be silently truncated to the leading text "1.0-";
    # fail closed to version=None instead.
    f = _write(tmp_path, """<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY ver "9.9">]>
<project>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>1.0-&ver;-end</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version is None
    assert "1.0-" not in deps[0].purl


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
    # /etc/passwd is the canonical XXE target. Two failure modes the parser
    # must NOT exhibit:
    #   1. Silent expansion: groupId becomes the file contents and a dep is
    #      emitted with /etc/passwd lines smuggled into the PURL/name.
    #   2. Crashing.
    # The acceptable behavior is: parser returns either [] (entity skipped,
    # group_id empty -> dep filtered by guard) OR a list whose entries
    # contain no expanded-payload markers.
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
    # Sanity: confirm the fixture actually contains the entity declaration,
    # otherwise this test is vacuous because the corpus was tampered with.
    assert "<!ENTITY xxe SYSTEM" in f.read_text()
    deps = parse(f)
    # Whether or not a dep is emitted, no expanded-payload markers may appear
    # anywhere in the output. /etc/passwd on Linux always starts with "root:".
    for dep in deps:
        assert "root:" not in dep.purl
        assert "root:" not in dep.name
        assert "root:" not in (dep.version or "")


def test_parse_rejects_billion_laughs_payload(tmp_path: Path) -> None:
    # Classic billion-laughs: 5 nested entities each expanding 10x. If the
    # parser expands lol5, the document blows up to ~100KB of "lol" and
    # would inflate further with deeper nesting; in the secure path, lol5 is
    # left as a literal entity reference (or skipped). We assert both that
    # the work finishes promptly AND that no exploded payload reached output.
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
    # Sanity: the fixture must actually contain nested entity definitions,
    # otherwise this test would be vacuous if a future edit removed them.
    assert "<!ENTITY lol5" in f.read_text()
    start = time.perf_counter()
    deps = parse(f)
    elapsed = time.perf_counter() - start
    # Hard cap: should finish in well under 1 second. If expansion ran, this
    # hits multi-seconds and gigabytes of RAM.
    assert elapsed < 1.0
    # If a dep was emitted, no entry's text may carry a bloomed payload.
    # 100 chars is a comfortable upper bound for any legitimate Maven artifact
    # ID; full expansion would be at least 10,000 chars.
    for dep in deps:
        assert len(dep.name) < 100
        assert "lol" * 50 not in dep.name


def test_parse_resolves_project_version_builtin(tmp_path: Path) -> None:
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>3.4.5</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "3.4.5"


def test_parse_resolves_project_version_from_parent(tmp_path: Path) -> None:
    # A module POM without its own <version> inherits from <parent>, per
    # standard Maven inheritance.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>demo-parent</artifactId>
    <version>7.0.0</version>
  </parent>
  <artifactId>demo-module</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "7.0.0"


def test_parse_resolves_project_group_id_builtin(tmp_path: Path) -> None:
    # Only <version> text goes through property substitution (pre-existing
    # scope); this confirms project.groupId is available in that map.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${project.groupId}-1.78</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version == "com.example-1.78"


def test_parse_unresolvable_builtin_property_emits_none(tmp_path: Path) -> None:
    # No <version> anywhere (own or parent) means ${project.version} stays
    # unresolvable; fail closed rather than guess.
    f = _write(tmp_path, """<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.bouncycastle</groupId>
      <artifactId>bcprov-jdk18on</artifactId>
      <version>${project.version}</version>
    </dependency>
  </dependencies>
</project>
""")
    deps = parse(f)
    assert deps[0].version is None


def test_parse_oversized_file_returns_empty_list(tmp_path: Path) -> None:
    f = tmp_path / "huge.xml"
    # Build a payload that is just over the cap. The body doesn't need to
    # parse — safe_read_bytes rejects before lxml sees it.
    f.write_bytes(b"<project/>" + b" " * MAX_FILE_BYTES)
    assert parse(f) == []


def test_parse_property_expansion_bomb_fails_closed_fast(tmp_path: Path) -> None:
    # A ~1 KB pom whose properties each fan out to ten references grows the
    # resolved version string 10x per pass. The depth cap alone would let it
    # reach hundreds of MB before giving up; the length cap must abort within a
    # pass or two so the parser stays fast and returns no bogus version.
    props = "".join(f"<p{n}>" + f"${{p{n - 1}}}" * 10 + f"</p{n}>" for n in range(1, 16))
    body = (
        '<?xml version="1.0"?><project><properties><p0>AAAA</p0>'
        f"{props}</properties><dependencies><dependency>"
        "<groupId>g</groupId><artifactId>a</artifactId>"
        "<version>${p15}</version></dependency></dependencies></project>"
    )
    f = _write(tmp_path, body)
    start = time.monotonic()
    deps = parse(f)
    elapsed = time.monotonic() - start
    assert elapsed < 1.0
    assert deps[0].version is None
