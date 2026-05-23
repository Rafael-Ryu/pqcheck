"""Fixture: every primitive here is APPROVED by policy."""

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def strong_hashes() -> None:
    hashlib.sha256(b"x")
    hashlib.sha384(b"y")
    hashlib.sha3_256(b"z")
    hashlib.blake2b(b"q")


def aes_gcm_only() -> None:
    Cipher(algorithms.AES(b"k" * 32), modes.GCM(b"i" * 12))
