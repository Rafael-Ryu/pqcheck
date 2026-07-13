// Planted fixture: Go key-derivation functions from golang.org/x/crypto.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml. No go.mod on purpose: the
// tree-sitter detector (go_detector.detect_go_file) is the permanent
// floor and resolves package.Func(...) calls without a compiled module.
package planted

import (
	"crypto/sha256"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

func plantedKDFs() {
	_ = argon2.IDKey([]byte("password"), []byte("salt"), 1, 64*1024, 4, 32)
	_ = argon2.Key([]byte("password"), []byte("salt"), 3, 32*1024, 4, 32)
	_, _ = bcrypt.GenerateFromPassword([]byte("password"), bcrypt.DefaultCost)
	_ = bcrypt.CompareHashAndPassword([]byte("hash"), []byte("password"))
	_, _ = scrypt.Key([]byte("password"), []byte("salt"), 1<<15, 8, 1, 32)
	_ = pbkdf2.Key([]byte("password"), []byte("salt"), 4096, 32, sha256.New)
	_ = hkdf.New(sha256.New, []byte("secret"), []byte("salt"), []byte("info"))
	_ = hkdf.Extract(sha256.New, []byte("secret"), []byte("salt"))
	_ = hkdf.Expand(sha256.New, []byte("prk"), []byte("info"))
}

// B2: weak-KDF-parameter fixtures (weak literal / strong literal / variable
// arg per symbol) — see tests/corpus/planted/expected.yaml.
func plantedKDFParams(iter int) {
	_ = pbkdf2.Key([]byte("password"), []byte("salt"), 100000, 32, sha256.New)
	_ = pbkdf2.Key([]byte("password"), []byte("salt"), 650000, 32, sha256.New)
	_ = pbkdf2.Key([]byte("password"), []byte("salt"), iter, 32, sha256.New)

	_, _ = scrypt.Key([]byte("password"), []byte("salt"), 65536, 8, 1, 32)
	_, _ = scrypt.Key([]byte("password"), []byte("salt"), 131072, 8, 1, 32)
	_, _ = scrypt.Key([]byte("password"), []byte("salt"), iter, 8, 1, 32)

	_, _ = bcrypt.GenerateFromPassword([]byte("password"), 4)
	_, _ = bcrypt.GenerateFromPassword([]byte("password"), 12)
	_, _ = bcrypt.GenerateFromPassword([]byte("password"), iter)
}
