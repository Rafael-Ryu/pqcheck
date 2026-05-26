package analyzer

import (
	"os"
	"path/filepath"
	"testing"
)

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
	dir := writeModule(t, map[string]string{
		"main.go": "package main\n\n// #include <stdlib.h>\nimport \"C\"\n" +
			"import \"crypto/md5\"\nfunc main(){ _ = C.malloc(1); md5.New() }\n",
	})
	// CGO_ENABLED=0 excludes the package; the C compiler is never invoked. The
	// only contract here is a controlled return, not a crash.
	if _, err := Analyze(dir); err != nil {
		t.Fatalf("cgo package should be excluded, not abort the load: %v", err)
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
