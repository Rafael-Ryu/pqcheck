"""Planted fixture: stdlib/cryptography/argon2/bcrypt/pycryptodome KDFs and MACs.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

import hashlib
import hmac
import secrets

import argon2
import bcrypt
from argon2 import low_level
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Crypto.Hash import HMAC as CryptoHMAC
from Crypto.Protocol import KDF

mac = hmac.new(b"k", b"m")
mac_digest = hmac.digest(b"k", b"m", "sha256")
pbkdf2_key = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 100000)
scrypt_key = hashlib.scrypt(b"password", salt=b"salt", n=16384, r=8, p=1)

token = secrets.token_bytes(32)
token_hex = secrets.token_hex(32)
token_url = secrets.token_urlsafe(32)
choice = secrets.choice([1, 2, 3])
below = secrets.randbelow(100)
sysrand = secrets.SystemRandom()

hkdf = HKDF(algorithm=None, length=32, salt=None, info=None)
hkdf_expand = HKDFExpand(algorithm=None, length=32, info=None)
pbkdf2hmac = PBKDF2HMAC(algorithm=None, length=32, salt=b"s", iterations=100000)
scrypt_kdf = Scrypt(salt=b"s", length=32, n=2**14, r=8, p=1)

hasher = argon2.PasswordHasher()
argon2_hash = low_level.hash_secret(b"password", b"salt", 2, 102400, 8, 32, 0)
argon2_hash_raw = low_level.hash_secret_raw(b"password", b"salt", 2, 102400, 8, 32, 0)
argon2_verify = low_level.verify_secret(b"hash", b"password", 0)

bcrypt_salt = bcrypt.gensalt()
bcrypt_hash = bcrypt.hashpw(b"password", bcrypt_salt)
bcrypt_ok = bcrypt.checkpw(b"password", b"hash")

pc_pbkdf2 = KDF.PBKDF2(b"password", b"salt")
pc_pbkdf1 = KDF.PBKDF1(b"password", b"salt")
pc_scrypt = KDF.scrypt(b"password", b"salt", 32, 2**14, 8, 1)
pc_hkdf = KDF.HKDF(b"master", 32, b"salt", None)
pc_bcrypt = KDF.bcrypt(b"password", 12)
pc_bcrypt_check = KDF.bcrypt_check(b"password", b"hash")

pc_hmac = CryptoHMAC.new(b"key")
