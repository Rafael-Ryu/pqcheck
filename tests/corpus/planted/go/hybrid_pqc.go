// Planted fixture: hybrid post-quantum key-agreement/KEM constants (W3).
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"crypto/tls"

	"github.com/cloudflare/circl/hpke"
)

func plantedHybridPQC() {
	_ = &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
	_ = hpke.KEM_XWING
	_ = hpke.NewSuite(hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
}
