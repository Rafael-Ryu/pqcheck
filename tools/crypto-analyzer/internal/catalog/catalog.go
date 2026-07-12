// Package catalog maps fully-qualified Go callee names (<import-path>.<Func>)
// to canonical crypto algorithms. The crypto-catalog.json single source of
// truth lives in src/pqcheck/data/; the build copies it next to this file so
// go:embed can pull it in (embed cannot cross module/.. boundaries).
package catalog

import (
	_ "embed"
	"encoding/json"
)

//go:generate cp ../../../../src/pqcheck/data/crypto-catalog.json crypto-catalog.json

//go:embed crypto-catalog.json
var catalogJSON []byte

// Hit is one catalog entry: the canonical algorithm a Go symbol maps to.
// Curve is empty unless the symbol encodes a curve in its name (ECDH P-curves,
// Ed25519). KeySize is nil unless the symbol encodes a PQC parameter set in
// its name (mlkem.GenerateKey768/1024) — the policy's approved ML-KEM rules
// match on parameter-sets, so the finding must carry it.
type Hit struct {
	Canonical string `json:"canonical"`
	Family    string `json:"family"`
	Curve     string `json:"curve,omitempty"`
	KeySize   *int   `json:"key_size,omitempty"`
}

// Load parses the embedded catalog. It panics on a malformed embed: the JSON is
// a build artifact validated by tests, not attacker input, so a parse failure
// is a build bug, not a runtime condition to tolerate.
func Load() map[string]Hit {
	var m map[string]Hit
	if err := json.Unmarshal(catalogJSON, &m); err != nil {
		panic("crypto-analyzer: malformed embedded crypto-catalog.json: " + err.Error())
	}
	return m
}
