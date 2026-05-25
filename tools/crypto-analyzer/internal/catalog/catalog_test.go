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
