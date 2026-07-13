// Planted fixture: circl classical primitives (EdDSA, X25519/X448, HPKE).
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"crypto/rand"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/dh/x25519"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/sign/ed25519"
	"github.com/cloudflare/circl/sign/ed448"
)

func plantedCirclClassical() {
	_, _, _ = ed25519.GenerateKey(rand.Reader)
	_, _, _ = ed448.GenerateKey(rand.Reader)
	var pub, sec x25519.Key
	x25519.KeyGen(&pub, &sec)
	var pub448, sec448 x448.Key
	x448.KeyGen(&pub448, &sec448)
	_ = hpke.NewSuite(hpke.KEM_X25519_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
}
