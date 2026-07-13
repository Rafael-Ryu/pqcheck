// Planted fixture: Go stream ciphers and NaCl constructions from
// golang.org/x/crypto.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/nacl/sign"
	"golang.org/x/crypto/salsa20"
)

func plantedNaclAndStream() {
	var key [32]byte
	var nonce [24]byte
	salsa20.XORKeyStream(nil, []byte("plaintext"), nonce[:8], &key)
	_ = secretbox.Seal(nil, []byte("plaintext"), &nonce, &key)
	_, _ = secretbox.Open(nil, []byte("box"), &nonce, &key)
	_, _, _ = box.GenerateKey(rand.Reader)
	_ = box.Seal(nil, []byte("plaintext"), &nonce, &key, &key)
	_, _ = box.Open(nil, []byte("box"), &nonce, &key, &key)
	_, _, _ = sign.GenerateKey(rand.Reader)
}
