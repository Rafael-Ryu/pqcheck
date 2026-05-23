"""Fixture: pycryptodome surface, banned + acceptable mixed."""

from Crypto.Cipher import AES, DES
from Crypto.Hash import MD5, SHA256
from Crypto.PublicKey import RSA


def banned_block() -> None:
    DES.new(b"k" * 8, DES.MODE_ECB)
    MD5.new(b"x")
    RSA.generate(2048)


def acceptable_block() -> None:
    SHA256.new(b"x")
    AES.new(b"k" * 32, AES.MODE_GCM)
