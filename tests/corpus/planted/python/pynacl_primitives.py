"""Planted fixture: PyNaCl (libsodium bindings) primitives.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

import nacl.hash
import nacl.public
import nacl.pwhash
import nacl.secret
import nacl.signing

signing_key = nacl.signing.SigningKey.generate()
exchange_key = nacl.public.PrivateKey.generate()
box = nacl.secret.SecretBox(b"k" * 32)
digest = nacl.hash.blake2b(b"x")
hashed_id = nacl.pwhash.argon2id.str(b"password")
derived_id = nacl.pwhash.argon2id.kdf(32, b"password", b"s" * 16)
hashed_i = nacl.pwhash.argon2i.str(b"password")
derived_i = nacl.pwhash.argon2i.kdf(32, b"password", b"s" * 16)
hashed_default = nacl.pwhash.str(b"password")
