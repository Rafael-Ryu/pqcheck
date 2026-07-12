// Planted fixture: dot-import call resolution (reduced confidence 0.7).
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	. "crypto/sha256"
)

func plantedDotImport() {
	_ = New()
}
