// Planted fixture: Go legacy/broken ciphers and hashes from
// golang.org/x/crypto.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
)

func plantedLegacyCiphers() {
	_, _ = twofish.NewCipher([]byte("0123456789abcdef"))
	_, _ = cast5.NewCipher([]byte("0123456789abcdef"))
	_, _ = tea.NewCipher([]byte("0123456789abcdef"))
	_, _ = tea.NewCipherWithRounds([]byte("0123456789abcdef"), 64)
	_ = md4.New()
}
