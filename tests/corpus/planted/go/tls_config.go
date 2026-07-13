// Planted fixture: legacy TLS protocol versions and static-RSA cipher
// suites (B1).
//
// Not real code — do not build as part of any module. See
// tests/corpus/planted/expected.yaml.
package planted

import "crypto/tls"

func plantedTLSConfig() {
	_ = &tls.Config{MinVersion: tls.VersionTLS10}
	_ = &tls.Config{MaxVersion: tls.VersionTLS11}
	_ = tls.VersionSSL30
	_ = tls.TLS_RSA_WITH_RC4_128_SHA
	_ = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
	_ = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	_ = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	_ = tls.TLS_RSA_WITH_AES_128_CBC_SHA256
	_ = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	_ = tls.TLS_RSA_WITH_AES_256_GCM_SHA384
}
