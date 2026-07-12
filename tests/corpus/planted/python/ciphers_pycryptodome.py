"""Planted fixture: pycryptodome symmetric ciphers.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

from Crypto.Cipher import AES, ARC4, DES, DES3

key16 = b"0" * 16
key24 = b"0" * 24

aes_ecb = AES.new(key16, AES.MODE_ECB)
des_cbc = DES.new(key16[:8], DES.MODE_CBC)
des3_ctr = DES3.new(key24, DES3.MODE_CTR)
rc4_new = ARC4.new(key16)
