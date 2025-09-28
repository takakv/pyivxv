import secrets

from fastecdsa.point import Point

from pyivxv.crypto import drbg
from pyivxv.crypto.ciphertext import ElGamalCiphertext
from pyivxv.crypto.decryption_proof import DecryptionProof, derive_seed
from pyivxv.crypto.keys import PrivateKey
from pyivxv.encoding.ec_point import point_to_bytes


def generate_decryption_proof(M: Point, ct: ElGamalCiphertext, sk: PrivateKey) -> DecryptionProof:
    t = secrets.randbelow(sk.curve.q)
    message_commitment = ct.U * t
    key_commitment = sk.curve.G * t

    message_bytes = point_to_bytes(M)
    mc_bytes = point_to_bytes(message_commitment)
    kc_bytes = point_to_bytes(key_commitment)

    seed = derive_seed(sk.public_key.spki, ct.to_asn1(), message_bytes, mc_bytes, kc_bytes)
    challenge = drbg.randbelow(seed, sk.curve.q)

    response = (challenge * sk.x + t) % sk.curve.q
    return DecryptionProof(message_commitment, key_commitment, response)
