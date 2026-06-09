package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeModule(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module testmod\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRunUsageErrorExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"crypto-analyzer"}, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2 on missing argument", code)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty on a usage error", out.String())
	}
	if !strings.Contains(errOut.String(), "usage:") {
		t.Errorf("stderr = %q, want a usage message", errOut.String())
	}
}

func TestRunEmptyModuleEmitsJSONArray(t *testing.T) {
	// A module with no crypto exercises the findings==nil normalisation: the
	// output must be the JSON array `[]`, not `null`, and the exit code 0.
	dir := writeModule(t, "package main\n\nfunc main() {}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"crypto-analyzer", dir}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, errOut.String())
	}
	if got := strings.TrimSpace(out.String()); got != "[]" {
		t.Fatalf("stdout = %q, want []", got)
	}
}

func TestRunLoaderErrorExitsOne(t *testing.T) {
	// A non-existent directory makes packages.Load fail; the contract is exit 1
	// with a diagnostic on stderr, never a panic or a silent 0.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	var out, errOut bytes.Buffer
	if code := run([]string{"crypto-analyzer", missing}, &out, &errOut); code != 1 {
		t.Fatalf("exit code = %d, want 1 for a loader error; stderr=%s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "crypto-analyzer:") {
		t.Errorf("stderr = %q, want a diagnostic", errOut.String())
	}
}
