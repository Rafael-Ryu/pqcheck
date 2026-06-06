package catalog

import "testing"

func TestLoadParsesEntries(t *testing.T) {
	c := Load()
	rsa, ok := c["crypto/rsa.GenerateKey"]
	if !ok {
		t.Fatal("missing crypto/rsa.GenerateKey")
	}
	if rsa.Canonical != "RSA" || rsa.Family != "asymmetric-encryption" || rsa.Curve != "" {
		t.Errorf("rsa = %+v, want {RSA asymmetric-encryption <empty>}", rsa)
	}
	ecdh, ok := c["crypto/ecdh.P256"]
	if !ok {
		t.Fatal("missing crypto/ecdh.P256")
	}
	if ecdh.Canonical != "ECDH" || ecdh.Curve != "P-256" {
		t.Errorf("ecdh = %+v, want canonical ECDH curve P-256", ecdh)
	}
}

// TestCatalogStructuralInvariants gives the Go side a drift floor independent of
// the exhaustive Python guard: a mass deletion or a blank canonical/family in
// the embedded catalog fails `go test` on its own, not only via the Python
// suite that consumes the same JSON.
func TestCatalogStructuralInvariants(t *testing.T) {
	c := Load()
	if len(c) < 40 {
		t.Fatalf("catalog has %d entries, want >= 40 (mass deletion?)", len(c))
	}
	for sym, hit := range c {
		if hit.Canonical == "" {
			t.Errorf("%s: empty canonical", sym)
		}
		if hit.Family == "" {
			t.Errorf("%s: empty family", sym)
		}
	}
}

// TestCatalogAnchors pins one symbol per family (plus the PQC primitive and a
// curve-bearing entry) so canonical/family/curve drift is caught Go-side across
// the catalog's breadth, not just the two entries TestLoadParsesEntries spot
// checks. The full per-symbol guard stays single-sourced in the Python suite.
func TestCatalogAnchors(t *testing.T) {
	c := Load()
	anchors := map[string]struct{ canonical, family, curve string }{
		"crypto/rsa.GenerateKey":      {"RSA", "asymmetric-encryption", ""},
		"crypto/ecdsa.GenerateKey":    {"ECDSA", "signature", ""},
		"crypto/ed25519.GenerateKey":  {"EdDSA", "signature", "Ed25519"},
		"crypto/aes.NewCipher":        {"AES", "symmetric-cipher", ""},
		"crypto/md5.New":              {"MD5", "hash", ""},
		"crypto/ecdh.P256":            {"ECDH", "key-agreement", "P-256"},
		"crypto/mlkem.GenerateKey768": {"ML-KEM", "key-encapsulation", ""},
	}
	for sym, want := range anchors {
		hit, ok := c[sym]
		if !ok {
			t.Errorf("missing anchor %s", sym)
			continue
		}
		if hit.Canonical != want.canonical || hit.Family != want.family || hit.Curve != want.curve {
			t.Errorf("%s = %+v, want canonical=%s family=%s curve=%q",
				sym, hit, want.canonical, want.family, want.curve)
		}
	}
}
