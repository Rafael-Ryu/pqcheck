"""Parser for go.mod dependency manifests.

Emits one CryptoDependency per unique (module_path, version) pair found in
`require` directives — both the single-line form and the block `require (...)`
form.

Every *known* directive (module, go, toolchain, require, exclude, replace,
retract) is validated against go.mod's grammar even when it does not feed the
require inventory: a malformed known directive means `go` itself would refuse
the file, so whatever we parsed is a partial inventory — raise instead of
passing off the prefix as complete. Syntactically valid unknown/future
directives (tool, godebug, ...) stay ignored.

Out-of-scope for v0.1 (deliberate omissions, not oversights):
  - resolving `replace` directives: that requires knowing the full module
    graph (replace chains can point at VCS paths or local dirs). Emitting the
    *declared* path without replacement is safe-by-default for crypto scanning
    because we'd only miss a replace that swaps in a different crypto library
    — an edge case the Go crypto-analyzer binary handles authoritatively.
  - resolving `retract` directives: these mark versions as retracted in a
    module's *own* go.mod; they don't affect which version a downstream
    consumer imports.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

from pqcheck.deps.base import ManifestError, golang_purl, safe_read_bytes
from pqcheck.deps.packages import lookup_introduces
from pqcheck.models import CryptoDependency

# Module versions per x/mod/semver's lax grammar: `v` MAJOR[.MINOR[.PATCH]],
# numeric parts without leading zeros, numeric prerelease identifiers
# likewise — and prerelease/build suffixes only after the FULL vX.Y.Z form
# (x/mod rejects `v7-rc.1`). The historical `v\S+` accepted `vbanana` and
# even forged it into the inventory.
_SEMVER_NUM = r"(?:0|[1-9]\d*)"
_SEMVER_IDENT = r"(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
_SEMVER = (
    rf"v{_SEMVER_NUM}(?:\.{_SEMVER_NUM}(?:\.{_SEMVER_NUM}"
    rf"(?:-{_SEMVER_IDENT}(?:\.{_SEMVER_IDENT})*)?"
    rf"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    rf")?)?"
)
_VERSION_RE = re.compile(rf"^{_SEMVER}$")


# GoVersionRE from x/mod/modfile: `1.21`, `1.21.0`, `1.21rc1` — no leading
# zeros, minor required.
_GO_VERSION_RE = re.compile(r"^([1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?([a-z]+[0-9]+)?$")

# ToolchainRE from x/mod/modfile: `default`, or a go1 release name.
_TOOLCHAIN_RE = re.compile(r"^default$|^go1($|\.)")

# RetractSpec structure only: modfile parses retract with dontFixRetract —
# the VALUES are deliberately not semver-validated at parse time (the module
# path needed to fix them may appear later), so `go` accepts `retract
# vquasar` and even a quoted string with spaces. Only the singleton /
# bracket-comma interval STRUCTURE is enforced (round-9 differential).
_RETRACT_INTERVAL_RE = re.compile(r"^\[[^\[\],]+,[^\[\],]+\]$")

_REQUIRE_ENTRY_TOKENS = 2  # module path + version, nothing else
_MODULE_VERSION_TOKENS = 2  # `module/path v1.2.3` — one side of a replace


def _require_entry(tokens: list[str]) -> tuple[str, str] | None:
    """(module, canonical_version) when tokens match the require-entry
    grammar exactly and the version agrees with the path's major suffix.
    The version is canonicalized the way modfile's CanonicalVersion does, so
    downstream consumers (PURL, dedup, go.sum matching) see the same value
    the go toolchain records (`v0` and `v0.0.0` are one version)."""
    if len(tokens) != _REQUIRE_ENTRY_TOKENS or not tokens[0]:
        return None
    if not _VERSION_RE.match(tokens[1]):
        return None
    path_major, ok = _split_path_version(tokens[0])
    if not ok:
        return None  # invalid /vN or gopkg.in suffix: "invalid module path" to go
    canonical = _canonical_version(tokens[1])
    if not _path_major_ok(path_major, canonical):
        return None
    return tokens[0], canonical


def _canonical_version(version: str) -> str:
    """modfile's CanonicalVersion over an already-validated token: pad the
    missing minor/patch with zeros and drop build metadata, keeping only the
    special `+incompatible` marker."""
    build = ""
    if "+" in version:
        version, metadata = version.split("+", 1)
        if metadata == "incompatible":
            build = "+incompatible"
    base, dash, prerelease = version.partition("-")
    parts = base[1:].split(".")
    parts.extend("0" for _ in range(3 - len(parts)))
    return "v" + ".".join(parts) + dash + prerelease + build


def _split_path_version(path: str) -> tuple[str, bool]:
    """(path_major, ok) — a straight port of module.SplitPathVersion.

    path_major is the `/vN` (or gopkg.in `.vN[-unstable]`) suffix, "" when
    the path has none. ok=False means the suffix itself is invalid (`/v1`,
    `/v0`, a leading zero, a dotted `/v1.2`, or a gopkg.in path without its
    mandatory `.vN`) — an invalid module path to go, not merely a mismatch.
    """
    if path.startswith("gopkg.in/"):
        return _split_gopkg_in(path)
    i = len(path)
    dot = False
    while i > 0 and (path[i - 1].isdigit() or path[i - 1] == "."):
        if path[i - 1] == ".":
            dot = True
        i -= 1
    if i <= 1 or i == len(path) or path[i - 1] != "v" or path[i - 2] != "/":
        return "", True  # no version suffix at all
    path_major = path[i - 2 :]
    min_suffix_len = 3  # "/v" plus at least one digit
    if dot or len(path_major) < min_suffix_len or path_major[2] == "0" or path_major == "/v1":
        return "", False
    return path_major, True


def _split_gopkg_in(path: str) -> tuple[str, bool]:
    """module.splitGopkgIn: gopkg.in paths must end in .vN (any N, no leading
    zero except .v0 itself), optionally followed by -unstable."""
    i = len(path)
    if path.endswith("-unstable"):
        i -= len("-unstable")
    while i > 0 and path[i - 1].isdigit():
        i -= 1
    if i <= 1 or path[i - 1] != "v" or path[i - 2] != ".":
        return "", False  # all gopkg.in paths must end in .vN
    path_major = path[i - 2 :]  # keeps the -unstable suffix, like x/mod
    min_suffix_len = 3
    if len(path_major) < min_suffix_len or (path_major[2] == "0" and path_major != ".v0"):
        return "", False
    return path_major, True


def _path_major_ok(path_major: str, canonical: str) -> bool:
    """module.CheckPathMajor: the suffix's major must equal the version's;
    without a suffix the major must be 0/1 or the version +incompatible.
    A matching suffix accepts regardless of build metadata — +incompatible
    is an extra exemption for unsuffixed high majors, not a veto (go accepts
    `example.com/lib/v2 v2.4.0+incompatible`)."""
    if path_major.startswith(".v") and path_major.endswith("-unstable"):
        path_major = path_major.removesuffix("-unstable")
    if canonical.startswith("v0.0.0-") and path_major == ".v1":
        return True  # legacy gopkg.in .v1 pseudo-version exception
    major = canonical[1:].split(".", 1)[0].split("-", 1)[0].split("+", 1)[0]
    if not path_major:
        return major in ("0", "1") or canonical.endswith("+incompatible")
    return major == path_major[2:]


def lex_go_mod_line(line: str) -> list[str] | None:
    """Tokens of one go.mod line, or None when it cannot be lexed safely.

    A minimal fail-closed lexer for the token shapes go.mod's own lexer
    accepts in directives: bare tokens, interpreted strings (`"..."` with the
    strconv.Unquote escape set), `//` comments, and `(`/`)` as standalone
    punctuation. Anything it cannot decide — unterminated string, unsupported
    escape, a raw backtick string (which modfile lexes but refuses as a
    directive argument) — returns None so callers treat the file as hostile
    instead of guessing. A naive whitespace split turned a quoted path
    containing a space into two RHS tokens, which read as a module+version
    replacement.
    """
    tokens: list[str] = []
    i, size = 0, len(line)
    while i < size:
        ch = line[i]
        if ch in " \t":
            i += 1
        elif line.startswith("//", i):
            break
        elif ch in "()":
            tokens.append(ch)
            i += 1
        elif ch == '"':
            lexed = _lex_interpreted_string(line, i)
            if lexed is None:
                return None  # unterminated string or an escape we do not model
            token, i = lexed
            tokens.append(token)
        elif ch == "`":
            # Raw strings are lexed but rejected as directive arguments by
            # modfile's parseString (`go` errors with "unquoted string cannot
            # contain quote"), so accepting one here would pass a file the
            # toolchain refuses. Fail closed.
            return None
        else:
            j = i
            while j < size and line[j] not in ' \t"`()' and not line.startswith("//", j):
                j += 1
            tokens.append(line[i:j])
            i = j
    return tokens


def _lex_interpreted_string(line: str, start: int) -> tuple[str, int] | None:
    """Decode the `"..."` string opening at line[start]; (value, next_index),
    or None (fail closed) on an unterminated string or invalid escape.

    Handles the Go interpreted-string escape set (strconv.Unquote, which is
    what go.mod's own lexer applies): the single-char escapes, `\\xHH` and
    exactly-3-digit octal for ASCII bytes only (Go treats those as raw bytes;
    above 0x7F no faithful str mapping exists — see _MAX_ASCII_BYTE — so they
    fail closed), and `\\uHHHH`/`\\UHHHHHHHH` code points rejecting surrogates
    and out-of-range values. Modelling only `\\\\` and `\\"` made the lexer
    refuse go.mod files Go itself accepts (e.g. a replace target of
    "./vendor\\x20dir").
    """
    i = start + 1
    size = len(line)
    buf: list[str] = []
    while i < size and line[i] != '"':
        if line[i] == "\\":
            if i + 1 >= size:
                return None
            decoded = _decode_escape(line, i + 1)
            if decoded is None:
                return None
            text, i = decoded
            buf.append(text)
        else:
            buf.append(line[i])
            i += 1
    if i >= size:
        return None
    return "".join(buf), i + 1


_SIMPLE_ESCAPES = {
    "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t",
    "v": "\v", "\\": "\\", '"': '"',
}
_OCTAL_ESCAPE_DIGITS = 3
_HEX_ESCAPE_DIGITS = 2
_UNICODE4_DIGITS = 4
_UNICODE8_DIGITS = 8
# \xHH and octal escapes are RAW BYTES to strconv.Unquote, not code points.
# Below 0x80 byte and code point coincide, so decoding to chr() is faithful;
# at or above it they diverge (a Go path of bytes C3 A9 is not the Python
# string chr(0xC3)+chr(0xA9) once fsencoded), and a boundary check would
# resolve a different filesystem name than the Go toolchain follows. No safe
# str mapping exists, so those escapes fail closed instead of guessing.
_MAX_ASCII_BYTE = 0x7F
_MAX_CODE_POINT = 0x10FFFF
_SURROGATE_LO, _SURROGATE_HI = 0xD800, 0xDFFF


def _decode_escape(line: str, i: int) -> tuple[str, int] | None:
    """Decode one escape whose introducing backslash sits at line[i - 1];
    (decoded_text, next_index), or None on any form Go's lexer rejects."""
    ch = line[i]
    simple = _SIMPLE_ESCAPES.get(ch)
    if simple is not None:
        return simple, i + 1
    if ch == "x":
        return _hex_escape(line, i + 1, _HEX_ESCAPE_DIGITS)
    if ch == "u":
        return _unicode_escape(line, i + 1, _UNICODE4_DIGITS)
    if ch == "U":
        return _unicode_escape(line, i + 1, _UNICODE8_DIGITS)
    digits = line[i : i + _OCTAL_ESCAPE_DIGITS]
    if len(digits) == _OCTAL_ESCAPE_DIGITS and all(c in "01234567" for c in digits):
        value = int(digits, 8)
        if value <= _MAX_ASCII_BYTE:
            return chr(value), i + _OCTAL_ESCAPE_DIGITS
    return None


def _hex_digits_value(line: str, i: int, count: int) -> int | None:
    digits = line[i : i + count]
    if len(digits) == count and all(c in "0123456789abcdefABCDEF" for c in digits):
        return int(digits, 16)
    return None


def _hex_escape(line: str, i: int, count: int) -> tuple[str, int] | None:
    value = _hex_digits_value(line, i, count)
    if value is None or value > _MAX_ASCII_BYTE:
        return None  # non-ASCII byte escape: see _MAX_ASCII_BYTE
    return chr(value), i + count


def _unicode_escape(line: str, i: int, count: int) -> tuple[str, int] | None:
    value = _hex_digits_value(line, i, count)
    if value is None or value > _MAX_CODE_POINT or _SURROGATE_LO <= value <= _SURROGATE_HI:
        return None  # invalid code point: Go's lexer rejects it too
    return chr(value), i + count


def dir_shaped(token: str) -> bool:
    """True when `token` is a filesystem-path replacement target per go.mod's
    grammar: rooted, or starting with `./` / `../` (go rejects anything else
    as a versionless replacement)."""
    if token in (".", "..") or token.startswith(("./", "../")):
        return True
    if sys.platform == "win32" and token.startswith((".\\", "..\\")):  # pragma: no cover
        return True
    return Path(token).is_absolute()


def _module_entry_ok(tokens: list[str]) -> bool:
    return len(tokens) == 1


def _go_entry_ok(tokens: list[str]) -> bool:
    return len(tokens) == 1 and _GO_VERSION_RE.match(tokens[0]) is not None


def _toolchain_entry_ok(tokens: list[str]) -> bool:
    return len(tokens) == 1 and _TOOLCHAIN_RE.match(tokens[0]) is not None


def _exclude_entry_ok(tokens: list[str]) -> bool:
    return _require_entry(tokens) is not None


def _replace_entry_ok(tokens: list[str]) -> bool:
    """ReplaceSpec: `mod [ver] => mod ver` or `mod [ver] => dir` — the same
    two safe shapes the boundary check in go_module_detector enforces."""
    if tokens.count("=>") != 1:
        return False
    split = tokens.index("=>")
    lhs, rhs = tokens[:split], tokens[split + 1 :]
    if len(lhs) not in (1, _MODULE_VERSION_TOKENS) or dir_shaped(lhs[0]):
        return False
    if not lhs[0] or not _split_path_version(lhs[0])[1]:
        return False
    if len(lhs) == _MODULE_VERSION_TOKENS and _require_entry(lhs) is None:
        return False
    if len(rhs) == _MODULE_VERSION_TOKENS:
        # modfile's parseReplace validates the OLD side only: the
        # replacement's version is parsed but never matched against its
        # path's major, and the RHS path is not even suffix-checked —
        # `go mod edit -json` accepts an RHS of `/v1`, `/v01`, a dotted
        # suffix, or a gopkg.in path without `.vN` (round-8 differential).
        return bool(rhs[0]) and not dir_shaped(rhs[0]) and _VERSION_RE.match(rhs[1]) is not None
    return len(rhs) == 1 and dir_shaped(rhs[0])


def _retract_entry_ok(tokens: list[str]) -> bool:
    # RetractSpec = Version | "[" Version "," Version "]". The lexer does not
    # split on `[`/`,`/`]`, so an interval arrives as 1..N tokens depending on
    # spacing — joining normalizes that before matching. Values themselves
    # are unvalidated, matching dontFixRetract (see _RETRACT_INTERVAL_RE).
    joined = "".join(tokens)
    if joined.startswith("["):
        return _RETRACT_INTERVAL_RE.match(joined) is not None
    return len(tokens) == 1


# require is handled inline (its entries feed the inventory); everything else
# is validate-and-discard.
_ENTRY_VALIDATORS: dict[str, Callable[[list[str]], bool]] = {
    "module": _module_entry_ok,
    "go": _go_entry_ok,
    "toolchain": _toolchain_entry_ok,
    "exclude": _exclude_entry_ok,
    "replace": _replace_entry_ok,
    "retract": _retract_entry_ok,
}
_KNOWN_DIRECTIVES = frozenset({"require", *_ENTRY_VALIDATORS})
# Per go.mod's grammar, go and toolchain are single-line only.
_BLOCK_FORM_DIRECTIVES = frozenset({"module", "require", "exclude", "replace", "retract"})
# Directives go.mod admits at most once ("repeated module statement").
_SINGLETON_DIRECTIVES = frozenset({"module", "go", "toolchain"})


def _entry_ok(directive: str, tokens: list[str]) -> bool:
    if "(" in tokens or ")" in tokens:
        return False
    # retract values are unvalidated (dontFixRetract) — even an empty quoted
    # token is accepted by go, so the non-empty guard must not apply there.
    if directive != "retract" and not all(tokens):
        return False
    return _ENTRY_VALIDATORS[directive](tokens)


# A go.sum line is `module version hash` (3 whitespace-separated fields).
_GO_SUM_MIN_FIELDS = 3


def parse(path: Path, errors: list[str] | None = None) -> list[CryptoDependency]:
    """Parse `path` into CryptoDependency entries.

    `errors` (when provided) collects non-fatal diagnostics — currently a
    go.sum companion that exists but could not be used for integrity
    cross-referencing. Those must not discard the require inventory, but a
    scan that silently dropped integrity analysis would conflate "skipped by
    a resource cap" with "no checksum companion exists".
    """
    raw = safe_read_bytes(path)
    if raw is None:
        return []
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestError(f"malformed go.mod: {exc}") from exc

    seen: set[tuple[str, str]] = set()
    deps: list[CryptoDependency] = []
    summed = _load_go_sum(path, errors)

    def _add(module_path: str, version: str) -> None:
        key = (module_path, version)
        if key in seen:
            return
        seen.add(key)
        purl = golang_purl(module_path, version)
        if purl is None:
            return
        deps.append(
            CryptoDependency(
                purl=purl,
                name=module_path,
                version=version,
                ecosystem="golang",
                declared_in=path,
                introduces_algorithms=lookup_introduces("golang", module_path),
                # No go.sum to consult => no claim at all (None), not a
                # positive "verified" the CBOM would then publish.
                integrity_verified=None if summed is None else key in summed,
            )
        )

    _parse_directives(text, _add)
    return deps


def _parse_directives(text: str, add: Callable[[str, str], None]) -> None:
    """Validate every known directive and feed require entries to `add`.

    Single linear pass with a directive-block state machine. Earlier this
    used a lazy DOTALL regex to capture each `require ( ... )` body, which
    backtracked to EOF from every opener when the closing paren was missing
    (~O(n^2) on hostile input). Line-oriented scanning stays linear.
    Split on the Go line terminator only. str.splitlines() also breaks on
    form-feed, vertical-tab, NEL, and the Unicode line/paragraph separators,
    none of which terminate a line in go.mod's lexer — splitting on them lets
    a control char inside one physical line forge a second `require`.
    """
    in_block: str | None = None
    seen_singletons: set[str] = set()
    for lineno, raw_line in enumerate(text.split("\n"), start=1):
        tokens = lex_go_mod_line(raw_line.rstrip("\r"))
        if tokens is None:
            raise ManifestError(f"malformed go.mod: line {lineno} cannot be lexed")
        if not tokens:
            continue
        if in_block is not None:
            in_block = _block_line(in_block, tokens, lineno, add, seen_singletons)
        else:
            in_block = _directive_line(tokens, lineno, add, seen_singletons)
    if in_block is not None:
        # An unclosed block: `go` itself refuses the file, so whatever we
        # parsed is a partial inventory, not a complete one.
        raise ManifestError(f"malformed go.mod: unclosed {in_block} block")


def _register_singleton(seen: set[str], directive: str, lineno: int) -> None:
    if directive in seen:
        # go refuses a second occurrence ("repeated module statement").
        raise ManifestError(f"malformed go.mod: repeated {directive} directive at line {lineno}")
    seen.add(directive)


def _block_line(
    directive: str,
    tokens: list[str],
    lineno: int,
    add: Callable[[str, str], None],
    seen_singletons: set[str],
) -> str | None:
    """One line inside a `directive ( ... )` block; the still-open directive
    (or None once the block closes)."""
    if tokens == [")"]:
        return None
    if directive in _SINGLETON_DIRECTIVES:
        _register_singleton(seen_singletons, directive, lineno)
    if directive == "require":
        entry = _require_entry(tokens)
        if entry is None:
            raise ManifestError(f"malformed go.mod: invalid require entry at line {lineno}")
        add(*entry)
    elif not _entry_ok(directive, tokens):
        raise ManifestError(f"malformed go.mod: invalid {directive} entry at line {lineno}")
    return directive


def _directive_line(
    tokens: list[str],
    lineno: int,
    add: Callable[[str, str], None],
    seen_singletons: set[str],
) -> str | None:
    """One top-level line; the directive whose block it opens, if any."""
    directive = tokens[0]
    if directive not in _KNOWN_DIRECTIVES:
        # Syntactically valid unknown/future directives (tool, godebug, ...)
        # are not validated: they do not feed this inventory and rejecting
        # them would break on every new go release.
        return None
    rest = tokens[1:]
    if rest == ["("]:
        if directive not in _BLOCK_FORM_DIRECTIVES:
            raise ManifestError(
                f"malformed go.mod: invalid {directive} directive at line {lineno}"
            )
        return directive
    if directive in _SINGLETON_DIRECTIVES:
        _register_singleton(seen_singletons, directive, lineno)
    if directive == "require":
        entry = _require_entry(rest)
        if entry is None:
            raise ManifestError(
                f"malformed go.mod: invalid require directive at line {lineno}"
            )
        add(*entry)
    elif not _entry_ok(directive, rest):
        raise ManifestError(
            f"malformed go.mod: invalid {directive} directive at line {lineno}"
        )
    return None


def _load_go_sum(
    go_mod_path: Path, errors: list[str] | None
) -> set[tuple[str, str]] | None:
    """Index the (module, version) pairs checksummed in the sibling go.sum.

    Returns None when there is nothing trustworthy to cross-reference, so
    callers make no integrity claim (integrity_verified=None, never a
    positive "verified"). When a go.sum exists but was skipped (oversized,
    not UTF-8), that is NOT the same as "no checksum companion" — the skip is
    recorded in `errors` so the scan reports its inventory as incomplete
    instead of silently dropping integrity analysis. go.sum lines are
    `module version hash` and `module version/go.mod hash`; the `/go.mod`
    suffix is stripped so both forms collapse to the same (module, version)
    key the require block uses.
    """
    go_sum = go_mod_path.with_name("go.sum")
    try:
        raw = safe_read_bytes(go_sum)
    except ManifestError as exc:
        # Oversized go.sum must not discard the whole require inventory, but
        # the suppressed integrity analysis must not pass as a clean scan.
        if errors is not None:
            errors.append(f"{go_sum}: ManifestError: {exc}")
        return None
    if raw is None:
        return None  # no companion exists: legitimately no claim to make
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        if errors is not None:
            errors.append(f"{go_sum}: ManifestError: malformed go.sum: {exc}")
        return None
    summed: set[tuple[str, str]] = set()
    for raw_line in text.split("\n"):
        parts = raw_line.split()
        if len(parts) < _GO_SUM_MIN_FIELDS:
            continue
        module, version = parts[0], parts[1].removesuffix("/go.mod")
        summed.add((module, version))
    return summed
