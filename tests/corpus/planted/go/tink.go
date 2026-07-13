// Planted fixture: tink-go key templates.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/signature"
)

func plantedTink() {
	_ = aead.AES128GCMKeyTemplate()
	_ = aead.AES256GCMKeyTemplate()
	_ = aead.AES128CTRHMACSHA256KeyTemplate()
	_ = aead.AES256CTRHMACSHA256KeyTemplate()
	_ = aead.AES128GCMSIVKeyTemplate()
	_ = aead.AES256GCMSIVKeyTemplate()
	_ = aead.ChaCha20Poly1305KeyTemplate()
	_ = aead.XChaCha20Poly1305KeyTemplate()
	_ = signature.ECDSAP256KeyTemplate()
	_ = signature.ECDSAP384SHA384KeyTemplate()
	_ = signature.ECDSAP521KeyTemplate()
	_ = signature.ED25519KeyTemplate()
	_ = signature.RSA_SSA_PKCS1_3072_SHA256_F4_Key_Template()
	_ = signature.RSA_SSA_PKCS1_4096_SHA512_F4_Key_Template()
	_ = signature.RSA_SSA_PSS_3072_SHA256_32_F4_Key_Template()
	_ = signature.RSA_SSA_PSS_4096_SHA512_64_F4_Key_Template()
}
