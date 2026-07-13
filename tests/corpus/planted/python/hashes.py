"""Planted fixture: hash primitives, stdlib + cryptography + pycryptodome.

Every call below is a known-detectable crypto primitive use (see
tests/corpus/planted/expected.yaml). Not real code — do not import.
"""

import hashlib

from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA1 as CryptoSHA1

digest_md5 = hashlib.md5(b"x").hexdigest()  # noqa: S324
digest_sha1 = hashlib.sha1(b"x").hexdigest()  # noqa: S324
digest_sha256 = hashlib.sha256(b"x").hexdigest()
digest_ripemd = hashlib.new("ripemd160")

hash_sha1_cryptography = hashes.SHA1()
hash_md5_cryptography = hashes.MD5()

hash_sha1_pycryptodome = CryptoSHA1.new()
