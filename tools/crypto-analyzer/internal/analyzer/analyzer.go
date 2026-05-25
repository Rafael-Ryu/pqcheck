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
// user's caches.
func hardenedEnv(scratch string) []string {
	return append(os.Environ(),
		"GOTOOLCHAIN=local",
		"CGO_ENABLED=0",
		"GOFLAGS=-mod=readonly",
		"GOWORK=off",
		"GOPROXY=off",
		"GOSUMDB=off",
		"GOENV=off",
		"GOCACHE="+scratch+"/cache",
		"GOMODCACHE="+scratch+"/modcache",
		"GOPATH="+scratch+"/gopath",
	)
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
		Env:  hardenedEnv(scratch),
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, err
	}

	cat := catalog.Load()
	var findings []Finding
	src := &sourceCache{lines: map[string][]string{}}
	for _, pkg := range pkgs {
		v := &visitor{pkg: pkg, cat: cat, src: src, out: &findings}
		for _, file := range pkg.Syntax {
			ast.Inspect(file, v.visit)
		}
	}
	return findings, nil
}

type visitor struct {
	pkg *packages.Package
	cat map[string]catalog.Hit
	src *sourceCache
	out *[]Finding
}

func (v *visitor) visit(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok {
		return true
	}
	hit, qualified := v.lookupCallee(call)
	if qualified == "" {
		return true
	}
	if h, ok := v.cat[qualified]; ok {
		hit = h
		v.emit(call, hit)
	}
	return true
}

// lookupCallee resolves the call's function to its <pkg-path>.<Name> identity
// via type info. Returns the qualified name (empty if it is not a resolvable
// package-level function selector). The hit return is unused here but kept for
// the const-fold/use-def passes layered on later.
func (v *visitor) lookupCallee(call *ast.CallExpr) (catalog.Hit, string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return catalog.Hit{}, ""
	}
	obj := v.pkg.TypesInfo.Uses[sel.Sel]
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return catalog.Hit{}, ""
	}
	return catalog.Hit{}, fn.Pkg().Path() + "." + fn.Name()
}

func (v *visitor) emit(call *ast.CallExpr, hit catalog.Hit) {
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
	*v.out = append(*v.out, f)
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
