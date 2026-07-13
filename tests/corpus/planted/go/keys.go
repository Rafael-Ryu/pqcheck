// Planted fixture: Go asymmetric key generation and key agreement.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

func plantedKeys() {
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
	_, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, _, _ = ed25519.GenerateKey(rand.Reader)
	var params dsa.Parameters
	_ = dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160)
	_ = ecdh.X25519()
}
