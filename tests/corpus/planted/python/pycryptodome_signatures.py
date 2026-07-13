"""Planted fixture: pycryptodome signature schemes and DH key agreement.

Deliberately excluded from the catalog (see algorithms.py comments):
Crypto.Signature.DSS.new (key-type ambiguous) and Crypto.PublicKey.ECC.construct
(loads rather than mints a key) — not exercised here since they emit nothing.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

from Crypto.Protocol import DH
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import eddsa, pkcs1_15, pss

rsa_key = RSA.generate(2048)
pkcs1_sig = pkcs1_15.new(rsa_key)
pss_sig = pss.new(rsa_key)

ecc_key = ECC.generate(curve="ed25519")
eddsa_sig = eddsa.new(ecc_key)

dh_shared = DH.key_agreement(eph_priv=1, eph_pub=2)
