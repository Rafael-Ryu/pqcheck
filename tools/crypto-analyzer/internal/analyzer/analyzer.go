// Package analyzer loads a Go module with full type information and emits a
// crypto Finding per call to a catalogued primitive. Type resolution (not text
// matching) means aliases, dot imports, and re-exports resolve to the real
// callee identity, and third-party libraries match when their deps are present.
package analyzer

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/Rafael-Ryu/pqcheck/tools/crypto-analyzer/internal/catalog"
	"golang.org/x/tools/go/packages"
)

// analyzeTimeout bounds a single packages.Load so a standalone invocation —
// one that bypasses the Python bridge, which owns the real per-scan deadline —
// cannot hang forever on a pathological module. It is a var so tests can
// shorten it; the bridge stays the primary deadline.
var analyzeTimeout = 5 * time.Minute

// maxKeySize mirrors the Python detector's _MAX_KEY_SIZE: a key-size literal
// beyond this is not a real key, and bounding it stops an attacker-supplied
// huge constant from flowing downstream.
const maxKeySize = 1 << 20

// maxSourceBytes caps the second read of a source file — go/packages has already
// parsed it into an AST, and this read only serves the evidence line, so an
// attacker cannot amplify memory by re-reading a huge file in full. A var so
// tests can shrink it; mirrors the Python deps reader's MAX_FILE_BYTES.
var maxSourceBytes = 5 << 20

// maxEvidenceBytes caps a single evidence line. A crypto call's source line is
// short; a multi-megabyte "line" is minified or hostile and would otherwise flow
// into stdout unbounded. A var so tests can shrink it.
var maxEvidenceBytes = 4 << 10

// goMemLimit is the soft memory target handed to the `go list`/compiler
// grandchildren that run over attacker-controlled code. The clean-slate env
// means the Python bridge's own GOMEMLIMIT does not propagate to them, so it is
// pinned here too; it mirrors the bridge's _GOMEMLIMIT. A soft target lets the
// GC reclaim before the bridge's hard RSS kill has to fire.
const goMemLimit = "1500MiB"

// Finding is one detected crypto primitive use. JSON tags match the Python
// bridge's CryptoFinding mapping.
type Finding struct {
	Algorithm  string  `json:"algorithm"`
	Family     string  `json:"family"`
	KeySize    *int    `json:"key_size,omitempty"`
	Curve      string  `json:"curve,omitempty"`
	Mode       string  `json:"mode,omitempty"`
	Path       string  `json:"path"`
	Line       int     `json:"line"`
	Column     int     `json:"column"`
	EndLine    int     `json:"end_line"`
	EndColumn  int     `json:"end_column"`
	Evidence   string  `json:"evidence"`
	Confidence float64 `json:"confidence"`
}

const loadMode = packages.NeedName | packages.NeedFiles |
	packages.NeedCompiledGoFiles | packages.NeedImports | packages.NeedDeps |
	packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo

// hardenedEnv returns the curated environment for the `go list` driver. The
// scanned module is attacker-controlled, so every download/exec lever is
// pinned off: no toolchain switch, no cgo C-compiler, no module fetch, no
// workspace, no go env file. The env is a clean-slate allowlist rather than
// os.Environ()+overrides: overriding only the enumerated GO* vars would let any
// unlisted lever (GODEBUG, GOPRIVATE, GOINSECURE, GOFIPS140, ...) leak through
// from the host. Only PATH/HOME/TMPDIR carry over so the toolchain resolves
// (GOROOT is found from the go binary's own location, no env var needed) and
// has a writable temp dir; caches are redirected to scratch so a scanned repo
// can't read or poison the user's caches. modFlag is -mod=readonly by default,
// or -mod=vendor when the scanned module ships a vendor tree — never -mod=mod,
// which would fetch and rewrite go.mod. This mirrors the Python bridge's
// _hardened_env (go_module_detector.py).
func hardenedEnv(scratch, modFlag string) []string {
	env := make([]string, 0, 14)
	for _, key := range []string{"PATH", "HOME", "TMPDIR"} {
		if v, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+v)
		}
	}
	return append(env,
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=0",
		"GOFLAGS="+modFlag,
		"GOWORK=off",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOENV=off",
		"GOCACHE="+scratch+"/cache",
		"GOMODCACHE="+scratch+"/modcache",
		"GOPATH="+scratch+"/gopath",
		"GOMEMLIMIT="+goMemLimit,
	)
}

// modFlagFor selects the module resolution mode. A vendor/modules.txt at the
// module root means deps are vendored locally, so -mod=vendor resolves them
// with no network; otherwise -mod=readonly reads only what go.sum already has.
func modFlagFor(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "vendor", "modules.txt")); err == nil {
		return "-mod=vendor"
	}
	return "-mod=readonly"
}

// Analyze loads the module rooted at dir and returns findings. It never fails
// on the scanned code's own type errors: packages.Load records those in
// pkg.Errors and Analyze processes whatever type information did resolve. A
// returned error means the loader itself could not run (e.g. `go` missing), the
// load timed out, or analysis panicked — never a process crash, so an
// in-process or standalone caller is as safe as one behind the Python bridge.
func Analyze(dir string) ([]Finding, error) {
	return withRecover(func() ([]Finding, error) { return analyze(dir) })
}

// withRecover converts a panic during analysis into an error. go/types can
// panic on pathological input (e.g. recursive generics); the production path
// turns a non-zero exit into a fallback, but in-process callers have no such
// boundary, so the binary contains the panic itself. The stack is kept in the
// error so a standalone run (where main prints err to stderr) can diagnose the
// panic site; the "crypto-analyzer:" prefix is left to main, the single owner.
func withRecover(fn func() ([]Finding, error)) (findings []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			findings, err = nil, fmt.Errorf("recovered from panic: %v\n%s", r, debug.Stack())
		}
	}()
	return fn()
}

func analyze(dir string) ([]Finding, error) {
	scratch, err := os.MkdirTemp("", "crypto-analyzer-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)

	ctx, cancel := context.WithTimeout(context.Background(), analyzeTimeout)
	defer cancel()
	cfg := &packages.Config{
		Mode:    loadMode,
		Dir:     dir,
		Env:     hardenedEnv(scratch, modFlagFor(dir)),
		Context: ctx,
		// Test files ship crypto too: a CBOM that skips *_test.go
		// under-reports the inventory (corpus 2026-06-11: 177 of 197 Go
		// findings lived in test files). Unresolvable third-party test
		// deps degrade per-package under the -e load mode, never abort.
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}

	cat := catalog.Load()
	var findings []Finding
	src := &sourceCache{lines: map[string][]string{}}
	for _, pkg := range pkgs {
		v := &visitor{
			pkg: pkg, cat: cat, src: src,
			callVar: map[*ast.CallExpr]*types.Var{},
			assigns: map[*types.Var]int{},
		}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, v.visit)
		}
		v.resolve(&findings)
	}
	findings = withinModule(findings, dir)
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.Algorithm < b.Algorithm
	})
	return findings, nil
}

// visitor collects, in a single walk, the algorithm call sites, the mode
// constructor call sites, and which variable each algorithm call binds to.
// Findings are built afterward in resolve so a mode constructor can be linked
// back to the algorithm that produced its cipher.Block — that link needs the
// bindings, which a streaming emit could not see yet.
type visitor struct {
	pkg     *packages.Package
	cat     map[string]catalog.Hit
	src     *sourceCache
	crypto  []cryptoSite
	modes   []modeSite
	callVar map[*ast.CallExpr]*types.Var
	assigns map[*types.Var]int
}

// expr is *ast.CallExpr for every algorithm call site, or *ast.SelectorExpr for
// a package-level constant reference (crypto/tls.X25519MLKEM768, circl hpke's
// hybrid KEM identifiers -- see recordConstUse). Both implement ast.Expr, so
// resolve/build handle either uniformly; only the RSA/ECDSA arg-extraction
// switch in build cares which concrete type it has.
type cryptoSite struct {
	expr       ast.Expr
	hit        catalog.Hit
	confidence float64
}

// goOpaqueMethods maps a resolved method key (see methodKey) to a generic
// finding whose algorithm is a dataflow-opaque runtime value the analyzer
// cannot name — go-piv's YubiKey.GenerateKey takes a runtime piv.Key{Algorithm}
// value, never a literal, at every call site seen so far. Mirrors the Python
// go_detector's CIPHER marker (PR #224): the construction is real, but naming
// a concrete algorithm/quantum-risk verdict from static analysis alone would
// overclaim. Deliberately not in the shared catalog: every catalog entry must
// classify through the Python side's _QUANTUM_MAP invariant, and "opaque,
// unknown algorithm" is not a real verdict to assert there.
var goOpaqueMethods = map[string]catalog.Hit{
	"github.com/go-piv/piv-go/v2/piv.YubiKey.GenerateKey": {Canonical: "KEYGEN", Family: "signature"},
}

// opaqueMethodConfidence mirrors the Python detectors' reduced confidence for
// dataflow-opaque constructions.
const opaqueMethodConfidence = 0.5

// hpkeHybridConstructor is the qualified callee of filippo.io/hpke's hybrid
// PQC KEM constructor. GenerateKey() called on its result is matched by this
// exact call-chain shape (see chainedHPKEHit) rather than by the receiver's
// static type, because MLKEM768X25519() returns the hpke.KEM interface — the
// same interface every other hpke KEM constructor (DHKEM, MLKEM768, ...)
// returns. Resolving GenerateKey generically by receiver type would also
// claim a classical-only hpke.DHKEM(...) call as the post-quantum hybrid.
const hpkeHybridConstructor = "filippo.io/hpke.MLKEM768X25519"

// hpkeHybridCatalogKey mirrors go_detector.py's chain-specific catalog key.
const hpkeHybridCatalogKey = "filippo.io/hpke.MLKEM768X25519.GenerateKey"

// hpkeNewSuiteKey is circl hpke's suite constructor: NewSuite(kemID, kdfID,
// aeadID). Its first argument is the KEM identifier -- when that argument is
// one of hpkeHybridKEMConstants below, hasConstantKEMArg lets recordCall skip
// the generic HPKE/VULNERABLE finding in favor of the precise one
// recordConstUse emits for the argument itself.
const hpkeNewSuiteKey = "github.com/cloudflare/circl/hpke.NewSuite"

// hpkeHybridKEMConstants are circl hpke's two hybrid KEM identifiers. Unlike
// every other catalog key, these are never called -- they are referenced as
// plain package-level constants (`hpke.KEM_XWING`), resolved via
// TypesInfo.Uses to a *types.Const in recordConstUse rather than the
// *types.Func path qualifiedCallee follows for calls.
var hpkeHybridKEMConstants = map[string]bool{
	"github.com/cloudflare/circl/hpke.KEM_X25519_KYBER768_DRAFT00": true,
	"github.com/cloudflare/circl/hpke.KEM_XWING":                   true,
}

type modeSite struct {
	call *ast.CallExpr
	mode string
}

// goModeConstructors maps a crypto/cipher mode constructor to its mode name.
// These are not algorithms (absent from the catalog); they annotate the
// algorithm finding for the block cipher they wrap.
var goModeConstructors = map[string]string{
	"crypto/cipher.NewGCM":              "GCM",
	"crypto/cipher.NewGCMWithNonceSize": "GCM",
	"crypto/cipher.NewGCMWithTagSize":   "GCM",
	"crypto/cipher.NewCBCEncrypter":     "CBC",
	"crypto/cipher.NewCBCDecrypter":     "CBC",
	"crypto/cipher.NewCFBEncrypter":     "CFB",
	"crypto/cipher.NewCFBDecrypter":     "CFB",
	"crypto/cipher.NewOFB":              "OFB",
	"crypto/cipher.NewCTR":              "CTR",
}

func (v *visitor) visit(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.AssignStmt:
		v.recordBindings(node.Lhs, node.Rhs)
	case *ast.ValueSpec:
		// `var block, _ = aes.NewCipher(...)` binds a cipher.Block the same way
		// `block, _ := ...` does, but as a ValueSpec inside a GenDecl rather than
		// an AssignStmt. Both function-local and package-level var decls reach
		// here via the walk. Names hold no value (e.g. `var x cipher.Block`) are
		// skipped because there is no call to bind.
		if len(node.Values) > 0 {
			v.recordBindings(identsToExprs(node.Names), node.Values)
		}
	case *ast.CallExpr:
		v.recordCall(node)
	case *ast.SelectorExpr:
		v.recordConstUse(node)
	}
	return true
}

func identsToExprs(names []*ast.Ident) []ast.Expr {
	out := make([]ast.Expr, len(names))
	for i, n := range names {
		out[i] = n
	}
	return out
}

func (v *visitor) recordCall(call *ast.CallExpr) {
	qualified := v.qualifiedCallee(call)
	if qualified != "" {
		if mode, ok := goModeConstructors[qualified]; ok {
			v.modes = append(v.modes, modeSite{call, mode})
			return
		}
		// hpke.NewSuite(hpke.KEM_X25519_KYBER768_DRAFT00, ...): when the KEM
		// argument is a recognized hybrid constant, that argument's own
		// *ast.SelectorExpr node (visited independently, see recordConstUse)
		// already emits the precise hybrid finding -- skip the generic
		// HPKE/VULNERABLE finding here so one call site does not carry two
		// contradictory verdicts.
		if qualified == hpkeNewSuiteKey && v.hasConstantKEMArg(call) {
			return
		}
		if hit, ok := v.cat[qualified]; ok {
			v.crypto = append(v.crypto, cryptoSite{call, hit, 1.0})
			return
		}
		if hit, ok := goOpaqueMethods[qualified]; ok {
			v.crypto = append(v.crypto, cryptoSite{call, hit, opaqueMethodConfidence})
			return
		}
	}
	// Not a resolvable package-function or method call site: it may still be
	// the hpke hybrid chain, which the receiver's interface type cannot
	// disambiguate above (see hpkeHybridConstructor).
	if hit, ok := v.chainedHPKEHit(call); ok {
		v.crypto = append(v.crypto, cryptoSite{call, hit, 1.0})
	}
}

// hasConstantKEMArg reports whether call's first argument is a package-level
// constant reference resolving to one of hpkeHybridKEMConstants.
func (v *visitor) hasConstantKEMArg(call *ast.CallExpr) bool {
	if len(call.Args) == 0 {
		return false
	}
	sel, ok := call.Args[0].(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj, ok := v.pkg.TypesInfo.Uses[sel.Sel].(*types.Const)
	if !ok || obj.Pkg() == nil {
		return false
	}
	return hpkeHybridKEMConstants[obj.Pkg().Path()+"."+obj.Name()]
}

// recordConstUse matches a package-level constant reference (`tls.
// X25519MLKEM768`, `hpke.KEM_XWING`) against the catalog. Unlike
// qualifiedCallee's *types.Func resolution for calls, a constant resolves via
// TypesInfo.Uses to a *types.Const -- this is the only place that path is
// checked, so it can never double-emit against a call site qualifiedCallee
// already claimed (those resolve to *types.Func, never *types.Const).
func (v *visitor) recordConstUse(sel *ast.SelectorExpr) {
	obj, ok := v.pkg.TypesInfo.Uses[sel.Sel].(*types.Const)
	if !ok || obj.Pkg() == nil {
		return
	}
	qualified := obj.Pkg().Path() + "." + obj.Name()
	if hit, ok := v.cat[qualified]; ok {
		v.crypto = append(v.crypto, cryptoSite{sel, hit, 1.0})
	}
}

// chainedHPKEHit matches `hpke.MLKEM768X25519().GenerateKey()` (and any
// aliased-import spelling of the same call, since qualifiedCallee resolves
// through go/types rather than text) by call shape: the outer call's method
// is GenerateKey and its receiver expression is itself a call to the hybrid
// KEM constructor.
func (v *visitor) chainedHPKEHit(call *ast.CallExpr) (catalog.Hit, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "GenerateKey" {
		return catalog.Hit{}, false
	}
	inner, ok := sel.X.(*ast.CallExpr)
	if !ok || v.qualifiedCallee(inner) != hpkeHybridConstructor {
		return catalog.Hit{}, false
	}
	hit, ok := v.cat[hpkeHybridCatalogKey]
	return hit, ok
}

// recordBindings notes, for `x := <algorithm-call>(...)`, the variable x so a
// later mode constructor taking x can be linked back, and counts every
// assignment to each variable. resolve only links a mode when the variable is
// assigned exactly once: a var reassigned or set in multiple branches is
// ambiguous, so the cipher.Block it holds at the mode site is not knowable from
// a single statement and the finding is left without a mode. lhs/rhs come from
// either an AssignStmt or a var ValueSpec; the binding shape is identical.
func (v *visitor) recordBindings(lhs, rhs []ast.Expr) {
	for _, l := range lhs {
		if ident, ok := l.(*ast.Ident); ok {
			if vobj := v.varOf(ident); vobj != nil {
				v.assigns[vobj]++
			}
		}
	}
	for i, r := range rhs {
		call, ok := r.(*ast.CallExpr)
		if !ok {
			continue
		}
		if _, ok := v.cat[v.qualifiedCallee(call)]; !ok {
			continue
		}
		var target ast.Expr
		switch {
		case len(rhs) == 1 && len(lhs) >= 1:
			// Multi-value call: the catalog's mode-wrappable constructors
			// (aes/des/rc4 NewCipher) all return (cipher.Block, error), so the
			// block is lhs[0]. A future entry returning its cipher in a later
			// position would need this revisited; the single-assignment gate
			// below bounds the blast radius until then.
			target = lhs[0]
		case i < len(lhs):
			target = lhs[i]
		}
		ident, ok := target.(*ast.Ident)
		if !ok {
			continue
		}
		if vobj := v.varOf(ident); vobj != nil {
			v.callVar[call] = vobj
		}
	}
}

// qualifiedCallee resolves the call's function to its <pkg-path>.<Name> identity
// via type info, or "" if it is not a resolvable package-level function. Both
// the qualified form (`md5.New`, a *ast.SelectorExpr) and the dot-imported form
// (`New` after `import . "crypto/md5"`, a bare *ast.Ident) resolve to the same
// types.Func, so both map to the same catalog key.
func (v *visitor) qualifiedCallee(call *ast.CallExpr) string {
	var name *ast.Ident
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		name = fun.Sel
	case *ast.Ident:
		name = fun
	default:
		return ""
	}
	fn, ok := v.pkg.TypesInfo.Uses[name].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return ""
	}
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		return methodKey(sig.Recv(), fn)
	}
	return fn.Pkg().Path() + "." + fn.Name()
}

// methodKey builds the catalog lookup key for a method call:
// <pkg-path>.<ReceiverTypeName>.<Method>. Pointer and value receivers both
// normalize to the underlying named type, so `pub.ECDH()` (a pointer-receiver
// method, addressable field or var) and a value-receiver method resolve the
// same way. Only a named type resolves — a literal struct, interface literal,
// or type parameter returns "" — which covers every catalogued receiver
// (crypto/ecdsa.PublicKey, crypto/ecdh.PrivateKey, piv.YubiKey) generically,
// with no receiver type enumerated here.
func methodKey(recv *types.Var, fn *types.Func) string {
	t := recv.Type()
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	obj := named.Obj()
	if obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name() + "." + fn.Name()
}

func (v *visitor) varOf(ident *ast.Ident) *types.Var {
	obj := v.pkg.TypesInfo.Defs[ident]
	if obj == nil {
		obj = v.pkg.TypesInfo.Uses[ident]
	}
	vobj, _ := obj.(*types.Var)
	return vobj
}

// resolve builds one finding per algorithm call site, then links each mode
// constructor to the finding whose variable it consumes. No finding is emitted
// for a mode constructor itself, so AES used with GCM yields one finding
// (AES + GCM), not two.
func (v *visitor) resolve(out *[]Finding) {
	varToIdx := map[*types.Var]int{}
	producer := map[int]*types.Var{}
	for _, site := range v.crypto {
		*out = append(*out, v.build(site.expr, site.hit, site.confidence))
		// Only a real call site can bind a variable a mode constructor later
		// consumes; a constant reference (site.expr is *ast.SelectorExpr) has
		// no entry in callVar, which is keyed by *ast.CallExpr.
		if call, ok := site.expr.(*ast.CallExpr); ok {
			if vobj, ok := v.callVar[call]; ok {
				idx := len(*out) - 1
				varToIdx[vobj] = idx
				producer[idx] = vobj
			}
		}
	}
	ambiguous := map[*types.Var]bool{}
	modesFor := map[*types.Var]map[string]bool{}
	for _, m := range v.modes {
		if len(m.call.Args) < 1 {
			continue
		}
		ident, ok := m.call.Args[0].(*ast.Ident)
		if !ok {
			continue
		}
		vobj := v.varOf(ident)
		if vobj == nil {
			continue
		}
		if v.assigns[vobj] != 1 {
			ambiguous[vobj] = true // reassigned or set across branches
			continue
		}
		if modesFor[vobj] == nil {
			modesFor[vobj] = map[string]bool{}
		}
		modesFor[vobj][m.mode] = true
	}
	// A single-assignment block links its mode only when exactly one distinct mode
	// consumes it. Two or more distinct modes on the same block (e.g. GCM and CBC)
	// leave the mode at any one call site unknowable from the call graph, so the
	// block is treated like a branch-ambiguous one — reporting the first in source
	// order would mask the weak mode the policy engine most wants to gate.
	for vobj, modes := range modesFor {
		if len(modes) > 1 {
			ambiguous[vobj] = true
			continue
		}
		idx, ok := varToIdx[vobj]
		if !ok {
			continue
		}
		for mode := range modes {
			(*out)[idx].Mode = mode
		}
	}
	// A mode constructor consumed a block we could not pin to one producer: the
	// cipher resolves but its mode does not, so drop the mode and lower confidence.
	for idx, vobj := range producer {
		if ambiguous[vobj] {
			(*out)[idx].Mode = ""
			(*out)[idx].Confidence = ambiguousModeConfidence
		}
	}
}

// ambiguousModeConfidence is the project's reduced-confidence value (matches
// the Python AST and tree-sitter detectors), applied when a cipher resolves but
// its mode cannot be use-def linked to a single producer.
const ambiguousModeConfidence = 0.7

// build turns a cryptoSite into a Finding. expr is *ast.CallExpr for every
// algorithm call site, or *ast.SelectorExpr for a package-level constant
// reference (see cryptoSite) -- both implement ast.Expr, giving Pos()/End()
// uniformly; the RSA/ECDSA arg-extraction below only applies to the call form.
func (v *visitor) build(expr ast.Expr, hit catalog.Hit, confidence float64) Finding {
	fset := v.pkg.Fset
	start := fset.Position(expr.Pos())
	end := fset.Position(expr.End())
	f := Finding{
		Algorithm:  hit.Canonical,
		Family:     hit.Family,
		Curve:      hit.Curve,
		KeySize:    hit.KeySize,
		Path:       start.Filename,
		Line:       start.Line,
		Column:     zeroBasedColumn(start.Column),
		EndLine:    end.Line,
		EndColumn:  zeroBasedColumn(end.Column),
		Evidence:   v.src.line(start.Filename, start.Line),
		Confidence: confidence,
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return f
	}
	switch hit.Canonical {
	case "RSA":
		// rsa.GenerateKey(rand, bits): key size is the second argument.
		if len(call.Args) >= 2 {
			f.KeySize = v.constInt(call.Args[1])
		}
	case "ECDSA":
		// ecdsa.GenerateKey(curve, rand): curve is the first argument,
		// typically elliptic.Pxxx().
		if len(call.Args) >= 1 {
			if c := v.curveFromArg(call.Args[0]); c != "" {
				f.Curve = c
			}
		}
	}
	return f
}

// zeroBasedColumn converts a 1-based go/token column to the 0-based convention
// the tree-sitter and Python detectors emit (models.SourceLocation.column is
// Field(ge=0)). Clamped at 0 so a synthesized 0-column position never goes
// negative.
func zeroBasedColumn(c int) int {
	if c <= 1 {
		return 0
	}
	return c - 1
}

// constInt returns the folded integer value of expr when it is a compile-time
// integer constant (a literal OR a const-bound identifier — this is where
// type info beats text matching). Returns nil for non-constants (e.g. vars,
// which need use-def) and for values outside a plausible key-size range.
func (v *visitor) constInt(expr ast.Expr) *int {
	tv, ok := v.pkg.TypesInfo.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return nil
	}
	n64, ok := constant.Int64Val(tv.Value)
	if !ok {
		return nil // does not fit int64 -> absurd, treat as unknown
	}
	n := int(n64)
	if n <= 0 || n > maxKeySize {
		return nil
	}
	return &n
}

// curveFromArg resolves a curve passed as elliptic.Pxxx() to its policy
// spelling. The direct-call form is handled here; a curve held in a variable
// would need use-def resolution.
func (v *visitor) curveFromArg(expr ast.Expr) string {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return ""
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	fn, ok := v.pkg.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return ""
	}
	return normalizeCurve(fn.Name())
}

// normalizeCurve maps crypto/elliptic curve constructor names to the policy
// curve vocabulary. Unlisted names pass through unchanged.
func normalizeCurve(name string) string {
	switch name {
	case "P224":
		return "P-224"
	case "P256":
		return "P-256"
	case "P384":
		return "P-384"
	case "P521":
		return "P-521"
	default:
		return name
	}
}

// withinModule drops findings whose source file's real path escapes the module
// root. go/packages parses every .go in a package directory, including one that
// is a symlink to a target outside the module; emitting that file's source line
// as evidence would disclose attacker-chosen content from outside the scanned
// tree. The Python bridge also enforces this, but the binary contains it itself
// so a standalone run is equally safe.
func withinModule(findings []Finding, dir string) []Finding {
	root, err := filepath.Abs(dir)
	if err != nil {
		root = filepath.Clean(dir)
	} else if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	kept := findings[:0]
	for _, f := range findings {
		if pathWithin(root, f.Path) {
			kept = append(kept, f)
		}
	}
	return kept
}

// pathWithin reports whether path's real (symlink-resolved) location is inside
// root. A path that cannot be resolved is treated as outside (fail closed).
func pathWithin(root, path string) bool {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, real)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// sourceCache reads each file once and serves stripped source lines for evidence.
type sourceCache struct {
	lines map[string][]string
}

func (s *sourceCache) line(filename string, line int) string {
	ls, ok := s.lines[filename]
	if !ok {
		ls = readCappedLines(filename)
		s.lines[filename] = ls
	}
	if line < 1 || line > len(ls) {
		return ""
	}
	return boundEvidence(strings.TrimSpace(ls[line-1]))
}

// readCappedLines reads at most maxSourceBytes of filename and splits it into
// lines. A read error yields nil, so evidence degrades to "" rather than failing.
func readCappedLines(filename string) []string {
	f, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(maxSourceBytes)))
	if err != nil {
		return nil
	}
	return strings.Split(string(data), "\n")
}

// boundEvidence truncates an evidence line to maxEvidenceBytes on a valid UTF-8
// boundary, so a pathological line cannot inflate the JSON output.
func boundEvidence(s string) string {
	if len(s) <= maxEvidenceBytes {
		return s
	}
	return strings.ToValidUTF8(s[:maxEvidenceBytes], "")
}
