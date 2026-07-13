"""Planted fixture: `cryptography` symmetric ciphers via the Cipher wrapper.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key16 = b"0" * 16
key24 = b"0" * 24
iv16 = b"0" * 16

aes_gcm = Cipher(algorithms.AES(key16), modes.GCM(iv16))
tripledes_cbc = Cipher(algorithms.TripleDES(key24), modes.CBC(iv16))
rc4_stream = Cipher(algorithms.ARC4(key16), mode=None)
blowfish_ecb = Cipher(algorithms.Blowfish(key16), modes.ECB())
idea_cfb = Cipher(algorithms.IDEA(key16), modes.CFB(iv16))
