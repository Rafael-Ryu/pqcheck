// Planted fixture: single-assignment dataflow (Task C2).
//
// `h := sha256.New()` / `mac := hmac.New(...)` single-assigned once in a
// function, then `.Sum(...)` called on the variable a few lines later --
// the constructor call site and the method-call site are both expected
// findings. See tests/corpus/planted/expected.yaml. No go.mod on purpose:
// the tree-sitter detector (go_detector.detect_go_file) is the permanent
// floor and resolves this without a compiled module.
package planted

import (
	"crypto/hmac"
	"crypto/sha256"
)

func checksum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func sign(key, text []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(text)
	return mac.Sum(nil)
}

// var-form single assignment (Task C4): `var h = ctor()`, not `:=`, is the
// same kind of single-assignment candidate.
func checksumVar(data []byte) []byte {
	var h = sha256.New()
	h.Write(data)
	return h.Sum(nil)
}
