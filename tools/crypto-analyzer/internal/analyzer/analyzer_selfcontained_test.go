package analyzer

import (
	"errors"
	"testing"
	"time"
)

// The binary must contain its own panics and hangs rather than relying on the
// Python bridge's process boundary: in-process callers (these tests, a future
// standalone consumer) get no such boundary.

func TestWithRecoverConvertsPanicToError(t *testing.T) {
	findings, err := withRecover(func() ([]Finding, error) {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected an error from a recovered panic, got nil")
	}
	if findings != nil {
		t.Fatalf("expected nil findings on panic, got %v", findings)
	}
}

func TestWithRecoverPassesThroughResult(t *testing.T) {
	want := []Finding{{Algorithm: "AES"}}
	sentinel := errors.New("sentinel")
	findings, err := withRecover(func() ([]Finding, error) {
		return want, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the wrapped error to pass through, got %v", err)
	}
	if len(findings) != 1 || findings[0].Algorithm != "AES" {
		t.Fatalf("expected findings to pass through, got %v", findings)
	}
}

func TestAnalyzeTimeoutReturnsError(t *testing.T) {
	dir := writeModule(t, map[string]string{
		"main.go": "package main\nfunc main() {}\n",
	})
	prev := analyzeTimeout
	analyzeTimeout = time.Nanosecond
	t.Cleanup(func() { analyzeTimeout = prev })

	if _, err := Analyze(dir); err == nil {
		t.Fatal("expected a deadline error when the load timeout is exceeded, got nil")
	}
}
