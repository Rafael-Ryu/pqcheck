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
// against a different catalog than the Python side.
//
// This compares the actual compiled-in catalogJSON var, not a second disk read
// of the go:generate-produced copy: re-reading that copy from disk would just
// compare the source against a file that was copied from it moments earlier in
// the same CI job, which can never detect drift. Reading catalogJSON checks
// what the binary actually embeds against the committed source of truth.
func TestEmbeddedCatalogMatchesSingleSource(t *testing.T) {
	source := filepath.Join("..", "..", "..", "..", "src", "pqcheck", "data", "crypto-catalog.json")
	single, err := os.ReadFile(source)
	if err != nil {
		t.Fatalf("read single source %s: %v", source, err)
	}
	if !bytes.Equal(catalogJSON, single) {
		t.Fatalf("embedded catalog differs from single source %s; run `go generate ./...`", source)
	}
}
