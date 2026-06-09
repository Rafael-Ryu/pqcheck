package analyzer

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// hasCCompiler reports whether a C compiler is reachable, so cgo-dependent
// assertions can be skipped on hosts (e.g. minimal CI) that lack one.
func hasCCompiler() bool {
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err == nil {
		return true
	}
	_, err := exec.LookPath("gcc")
	return err == nil
}

// The scanned module is attacker-controlled. These tests pin the envelope's
// behaviour on hostile inputs: tolerate type errors, ignore a workspace file,
// exclude cgo packages without invoking a C compiler, and refuse a toolchain
// upgrade — never crash, hang, fetch, or execute attacker build steps.

// writeTree writes files (relative paths) under a fresh temp dir and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestAnalyzeToleratesNonCompilingModule(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport \"crypto/md5\"\n" +
			"func main(){ md5.New(); undefinedThing() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze aborted on a type error: %v", err)
	}
	if _, ok := findingsByAlgo(fs)["MD5"]; !ok {
		t.Fatalf("expected MD5 resolved despite the type error, got %+v", fs)
	}
}

func TestAnalyzeIgnoresHostileGoWork(t *testing.T) {
	root := writeTree(t, map[string]string{
		"main/go.mod":  "module ws/main\n\ngo 1.24\n",
		"main/main.go": "package main\nimport \"crypto/md5\"\nfunc main(){ md5.New() }\n",
		"main/go.work": "go 1.24\n\nuse .\nuse ../evil\n",
		"evil/go.mod":  "module ws/evil\n\ngo 1.24\n",
		"evil/evil.go": "package evil\nimport \"crypto/sha1\"\nfunc F(){ sha1.New() }\n",
	})
	fs, err := Analyze(filepath.Join(root, "main"))
	if err != nil {
		t.Fatal(err)
	}
	byAlgo := findingsByAlgo(fs)
	if _, ok := byAlgo["MD5"]; !ok {
		t.Fatalf("expected MD5 from the main module, got %+v", fs)
	}
	if _, ok := byAlgo["SHA-1"]; ok {
		t.Fatalf("go.work pulled in a sibling module; GOWORK=off should ignore it: %+v", fs)
	}
}

func TestAnalyzeExcludesCgoPackage(t *testing.T) {
	// The MD5-absence assertion only proves CGO_ENABLED=0 when a C compiler is
	// present: without one, a regressed CGO_ENABLED=1 would also drop the package
	// (go list fails it for lack of a compiler), so the test would pass for the
	// wrong reason. Skip rather than give false assurance.
	if !hasCCompiler() {
		t.Skip("no C compiler on PATH; cgo exclusion is indistinguishable from a missing toolchain")
	}
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\n// #include <stdlib.h>\nimport \"C\"\n" +
			"import \"crypto/md5\"\nfunc main(){ _ = C.malloc(1); md5.New() }\n",
	})
	// CGO_ENABLED=0 excludes the package; the C compiler is never invoked.
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("cgo package should be excluded, not abort the load: %v", err)
	}
	// Make the exclusion observable: if the cgo guard regressed and the package
	// loaded, md5.New would resolve and emit MD5. Asserting its absence proves
	// the package was dropped, not merely that the load returned without error.
	if _, ok := findingsByAlgo(fs)["MD5"]; ok {
		t.Fatalf("cgo package was not excluded; MD5 resolved: %+v", fs)
	}
}

func TestAnalyzeDropsFindingFromSymlinkEscapingModule(t *testing.T) {
	// A .go file that is a symlink to a target outside the scanned module would
	// leak the target's source line into `evidence` (and its path) — file-content
	// disclosure from an attacker-chosen path. The binary drops findings whose
	// real path escapes the module root, so a standalone run is contained too,
	// not only the path-checking Python bridge.
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.go")
	if err := os.WriteFile(secret,
		[]byte("package main\nimport \"crypto/sha1\"\nfunc leak(){ sha1.New() } // SECRET_CONTENT\n"),
		0o644); err != nil {
		t.Fatal(err)
	}
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nimport \"crypto/md5\"\nfunc main(){ md5.New() }\n",
	})
	if err := os.Symlink(secret, filepath.Join(dir, "evil.go")); err != nil {
		t.Skipf("symlink unsupported on this platform: %v", err)
	}
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	byAlgo := findingsByAlgo(fs)
	if _, ok := byAlgo["MD5"]; !ok {
		t.Fatalf("expected MD5 from the real in-module file, got %+v", fs)
	}
	if _, ok := byAlgo["SHA-1"]; ok {
		t.Fatalf("SHA-1 came from a symlink escaping the module; it must be dropped: %+v", fs)
	}
}

func TestAnalyzeRefusesHostileToolchainDirective(t *testing.T) {
	// The `toolchain` directive (distinct from the `go` language-version directive
	// already covered by TestAnalyzeRefusesHostileToolchain) names a toolchain to
	// switch to. The `go` line here is satisfiable, so only the toolchain directive
	// is exercised: GOTOOLCHAIN=local ignores the unsatisfiable switch rather than
	// downloading it. The contract is no fetch, no hang, no panic — analysis still
	// resolves the in-module call.
	dir := writeModule(t, map[string]string{
		"go.mod":  "module tc\n\ngo 1.24\n\ntoolchain go1.99.0\n",
		"main.go": "package main\nimport \"crypto/md5\"\nfunc main(){ md5.New() }\n",
	})
	fs, err := Analyze(dir)
	if err != nil {
		t.Fatalf("toolchain directive should be ignored under GOTOOLCHAIN=local, not error: %v", err)
	}
	if _, ok := findingsByAlgo(fs)["MD5"]; !ok {
		t.Fatalf("expected MD5 to still resolve under a hostile toolchain directive, got %+v", fs)
	}
}

func TestAnalyzeRefusesHostileToolchain(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"go.mod":  "module tc\n\ngo 1.99.0\n",
		"main.go": "package main\nimport \"crypto/md5\"\nfunc main(){ md5.New() }\n",
	})
	// GOTOOLCHAIN=local makes `go list` refuse the unsatisfiable version rather
	// than download a toolchain: the loader fails, which the bridge turns into a
	// fallback. The contract is a controlled error, no fetch, no panic.
	if _, err := Analyze(dir); err == nil {
		t.Fatal("expected a load error for an unsatisfiable go directive under GOTOOLCHAIN=local")
	}
}
