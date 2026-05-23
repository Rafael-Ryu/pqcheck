"""Fixture: every primitive here is BANNED by policy."""

import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, ec, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def weak_hashes() -> None:
    hashlib.md5(b"x")
    hashlib.sha1(b"y")
    hashes.MD5()
    hashes.SHA1()


def shor_targets() -> None:
    rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec.generate_private_key(curve=ec.SECP256R1())
    dh.generate_parameters(generator=2, key_size=2048)


def broken_ciphers() -> None:
    Cipher(algorithms.TripleDES(b"k" * 24), modes.CBC(b"i" * 8))
    Cipher(algorithms.AES(b"k" * 32), modes.ECB())
