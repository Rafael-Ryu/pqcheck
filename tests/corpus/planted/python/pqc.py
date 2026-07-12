"""Planted fixture: post-quantum primitives across PQC libraries.

Not real code — do not import. See tests/corpus/planted/expected.yaml.
"""

import oqs
import pyspx.shake_128f
import pyspx.sha2_256s
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

kem = oqs.KeyEncapsulation("ML-KEM-768")
sig = oqs.Signature("ML-DSA-65")

kyber_pk, kyber_sk = ML_KEM_512.keygen()
kyber_ct, kyber_ss = ML_KEM_768.encaps(kyber_pk)
kyber_ss2 = ML_KEM_1024.decaps(kyber_sk, kyber_ct)

dsa_pk, dsa_sk = ML_DSA_44.keygen()
dsa_sig = ML_DSA_65.sign(dsa_sk, b"msg")
dsa_ok = ML_DSA_87.verify(dsa_pk, b"msg", dsa_sig)

mlkem_key_768 = mlkem.MLKEM768PrivateKey.generate()
mlkem_key_1024 = mlkem.MLKEM1024PrivateKey.generate()
mldsa_key_44 = mldsa.MLDSA44PrivateKey.generate()
mldsa_key_65 = mldsa.MLDSA65PrivateKey.generate()
mldsa_key_87 = mldsa.MLDSA87PrivateKey.generate()

spx_pk, spx_sk = pyspx.shake_128f.generate_keypair(b"s" * 96)
spx_sig = pyspx.shake_128f.sign(b"msg", spx_sk)
spx_ok = pyspx.shake_128f.verify(b"msg", spx_sig, spx_pk)

spx2_pk, spx2_sk = pyspx.sha2_256s.generate_keypair(b"s" * 96)
