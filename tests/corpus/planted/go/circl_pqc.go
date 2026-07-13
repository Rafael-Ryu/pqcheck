// Planted fixture: circl post-quantum KEMs and signatures.
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import (
	"crypto/rand"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/dilithium/mode2"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
	"github.com/cloudflare/circl/sign/dilithium/mode5"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func plantedCirclPQC() {
	_, _, _ = kyber512.GenerateKeyPair(rand.Reader)
	_, _, _ = kyber768.GenerateKeyPair(rand.Reader)
	_, _, _ = kyber1024.GenerateKeyPair(rand.Reader)
	_, _, _ = mlkem512.GenerateKeyPair(rand.Reader)
	_, _, _ = mlkem768.GenerateKeyPair(rand.Reader)
	_, _, _ = mlkem1024.GenerateKeyPair(rand.Reader)
	_, _, _ = mode2.GenerateKey(rand.Reader)
	_, _, _ = mode3.GenerateKey(rand.Reader)
	_, _, _ = mode5.GenerateKey(rand.Reader)
	_, _, _ = mldsa44.GenerateKey(rand.Reader)
	_, _, _ = mldsa65.GenerateKey(rand.Reader)
	_, _, _ = mldsa87.GenerateKey(rand.Reader)
}
