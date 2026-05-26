package catalog

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The binary embeds a copy of the catalog (go:generate copies it in, since
// go:embed cannot cross the module boundary). That copy must stay byte-for-byte
// identical to the single source in src/pqcheck/data, or the binary would scan
// against a different catalog than the Python side. This guards against a stale
// embedded copy when `go generate` has not run.
func TestEmbeddedCatalogMatchesSingleSource(t *testing.T) {
	embedded, err := os.ReadFile("crypto-catalog.json")
	if err != nil {
		t.Fatalf("read embedded copy: %v", err)
	}
	source := filepath.Join("..", "..", "..", "..", "src", "pqcheck", "data", "crypto-catalog.json")
	single, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read single source %s: %v", source, err)
	}
	if !bytes.Equal(embedded, single) {
		t.Fatalf("embedded catalog differs from single source %s; run `go generate ./...`", source)
	}
}
