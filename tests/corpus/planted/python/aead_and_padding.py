"""Planted fixture: pyca/cryptography direct AEAD classes, RSA-PSS padding, and Fernet.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM,
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)

key32 = b"k" * 32

aesgcm = AESGCM(key32)
aesgcmsiv = AESGCMSIV(key32)
aesocb3 = AESOCB3(key32)
aessiv = AESSIV(key32 * 2)
aesccm = AESCCM(key32)
chacha = ChaCha20Poly1305(key32)

pss_padding = padding.PSS(mgf=padding.MGF1(algorithm=None), salt_length=32)

fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)
multi = MultiFernet([fernet])
