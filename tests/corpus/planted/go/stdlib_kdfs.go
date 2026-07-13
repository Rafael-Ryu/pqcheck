// Planted fixture: Go 1.24 stdlib KDFs (crypto/hkdf, crypto/pbkdf2).
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml. Real-world corpus repos (age,
// go-jose) have already migrated off golang.org/x/crypto for these onto
// the stdlib packages, hence a separate file from kdfs.go's x/crypto
// versions — both declare a package named "hkdf"/"pbkdf2" and cannot be
// imported unaliased in the same file.
package planted

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
)

func plantedStdlibKDFs() {
	_, _ = pbkdf2.Key(sha256.New, "password", []byte("salt"), 4096, 32)
	_, _ = hkdf.Extract(sha256.New, []byte("secret"), []byte("salt"))
	_, _ = hkdf.Expand(sha256.New, []byte("prk"), "info", 32)
	_, _ = hkdf.Key(sha256.New, []byte("secret"), []byte("salt"), "info", 32)
}

// B2: weak-KDF-parameter fixtures for the stdlib pbkdf2.Key signature, whose
// iter arg sits at position 3 (not 2, as in x/crypto's kdfs.go) — see
// tests/corpus/planted/expected.yaml.
func plantedStdlibKDFParams(iter int) {
	_, _ = pbkdf2.Key(sha256.New, "password", []byte("salt"), 100000, 32)
	_, _ = pbkdf2.Key(sha256.New, "password", []byte("salt"), 650000, 32)
	_, _ = pbkdf2.Key(sha256.New, "password", []byte("salt"), iter, 32)
}
