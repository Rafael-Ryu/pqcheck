"""Planted fixture: asymmetric key generation and key agreement.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, rsa, x25519
from Crypto.PublicKey import ECC, RSA

rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ecdsa_key = ec.generate_private_key(ec.SECP256R1())
ecdh_marker = ec.ECDH()
dh_params = dh.generate_parameters(generator=2, key_size=2048)
eddsa_key = ed25519.Ed25519PrivateKey.generate()
x25519_key = x25519.X25519PrivateKey.generate()

rsa_key_pycryptodome = RSA.generate(2048)
ecc_key_pycryptodome = ECC.generate(curve="P-256")
