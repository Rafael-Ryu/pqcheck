// Package analyzer loads a Go module with full type information and emits a
// crypto Finding per call to a catalogued primitive. Type resolution (not text
// matching) means aliases, dot imports, and re-exports resolve to the real
// callee identity, and third-party libraries match when their deps are present.
package analyzer

import (
	"go/ast"
	"go/constant"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"github.com/Rafael-Ryu/pqcheck/tools/crypto-analyzer/internal/catalog"
	"golang.org/x/tools/go/packages"
)

// maxKeySize mirrors the Python detector's _MAX_KEY_SIZE: a key-size literal
// beyond this is not a real key, and bounding it stops an attacker-supplied
// huge constant from flowing downstream.
const maxKeySize = 1 << 20

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
// workspace, no go env file. Inherited GO* vars are overridden because these
// entries come last. PATH/HOME stay so the toolchain is found and functions;
// caches are redirected to scratch so a scanned repo can't read or poison the
// user's caches. modFlag is -mod=readonly by default, or -mod=vendor when the
// scanned module ships a vendor tree — never -mod=mod, which would fetch and
// rewrite go.mod.
func hardenedEnv(scratch, modFlag string) []string {
	return append(os.Environ(),
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
// returned error means the loader itself could not run (e.g. `go` missing).
func Analyze(dir string) ([]Finding, error) {
	scratch, err := os.MkdirTemp("", "crypto-analyzer-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)

	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  dir,
		Env:  hardenedEnv(scratch, modFlagFor(dir)),
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

type cryptoSite struct {
	call *ast.CallExpr
	hit  catalog.Hit
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
		v.recordBindings(node)
	case *ast.CallExpr:
		v.recordCall(node)
	}
	return true
}

func (v *visitor) recordCall(call *ast.CallExpr) {
	qualified := v.qualifiedCallee(call)
	if qualified == "" {
		return
	}
	if mode, ok := goModeConstructors[qualified]; ok {
		v.modes = append(v.modes, modeSite{call, mode})
		return
	}
	if hit, ok := v.cat[qualified]; ok {
		v.crypto = append(v.crypto, cryptoSite{call, hit})
	}
}

// recordBindings notes, for `x := <algorithm-call>(...)`, the variable x so a
// later mode constructor taking x can be linked back, and counts every
// assignment to each variable. resolve only links a mode when the variable is
// assigned exactly once: a var reassigned or set in multiple branches is
// ambiguous, so the cipher.Block it holds at the mode site is not knowable from
// a single statement and the finding is left without a mode.
func (v *visitor) recordBindings(assign *ast.AssignStmt) {
	for _, lhs := range assign.Lhs {
		if ident, ok := lhs.(*ast.Ident); ok {
			if vobj := v.varOf(ident); vobj != nil {
				v.assigns[vobj]++
			}
		}
	}
	for i, rhs := range assign.Rhs {
		call, ok := rhs.(*ast.CallExpr)
		if !ok {
			continue
		}
		if _, ok := v.cat[v.qualifiedCallee(call)]; !ok {
			continue
		}
		var lhs ast.Expr
		switch {
		case len(assign.Rhs) == 1 && len(assign.Lhs) >= 1:
			lhs = assign.Lhs[0] // multi-value call: block is the first result
		case i < len(assign.Lhs):
			lhs = assign.Lhs[i]
		}
		ident, ok := lhs.(*ast.Ident)
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
	return fn.Pkg().Path() + "." + fn.Name()
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
	for _, site := range v.crypto {
		*out = append(*out, v.build(site.call, site.hit))
		if vobj, ok := v.callVar[site.call]; ok {
			varToIdx[vobj] = len(*out) - 1
		}
	}
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
			continue // ambiguous: reassigned or set across branches
		}
		if idx, ok := varToIdx[vobj]; ok && (*out)[idx].Mode == "" {
			(*out)[idx].Mode = m.mode
		}
	}
}

func (v *visitor) build(call *ast.CallExpr, hit catalog.Hit) Finding {
	fset := v.pkg.Fset
	start := fset.Position(call.Pos())
	end := fset.Position(call.End())
	f := Finding{
		Algorithm:  hit.Canonical,
		Family:     hit.Family,
		Curve:      hit.Curve,
		Path:       start.Filename,
		Line:       start.Line,
		Column:     start.Column,
		EndLine:    end.Line,
		EndColumn:  end.Column,
		Evidence:   v.src.line(start.Filename, start.Line),
		Confidence: 1.0,
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

// sourceCache reads each file once and serves stripped source lines for evidence.
type sourceCache struct {
	lines map[string][]string
}

func (s *sourceCache) line(filename string, line int) string {
	ls, ok := s.lines[filename]
	if !ok {
		data, err := os.ReadFile(filename)
		if err != nil {
			s.lines[filename] = nil
			return ""
		}
		ls = strings.Split(string(data), "\n")
		s.lines[filename] = ls
	}
	if line < 1 || line > len(ls) {
		return ""
	}
	return strings.TrimSpace(ls[line-1])
}
