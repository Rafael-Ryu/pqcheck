// Planted fixture: Go crypto primitives, stdlib + golang.org/x/crypto.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml. No go.mod on purpose: the
// tree-sitter detector (go_detector.detect_go_file) is the permanent
// floor and resolves package.Func(...) calls without a compiled module.
package planted

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ripemd160"
)

func plantedHashesAndCiphers() {
	_ = md5.New()
	_ = sha1.New()
	_, _ = des.NewCipher([]byte("01234567"))
	_, _ = des.NewTripleDESCipher([]byte("012345678901234567890123"))
	_, _ = rc4.NewCipher([]byte("shortkey"))
	_, _ = blowfish.NewCipher([]byte("blowfishkey12345"))
	_ = ripemd160.New()
	_, _ = chacha20poly1305.New([]byte("0123456789abcdef0123456789abcdef"))
}
