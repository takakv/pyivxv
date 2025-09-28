import pytest

from pyivxv.crypto.exceptions import VerificationError
from pyivxv.crypto.keys import generate_private_key
from pyivxv.crypto.zkp import generate_decryption_proof
from pyivxv.encoding.message import encode_to_point, decode_from_point


def test_unblinding():
    sk = generate_private_key()
    pk = sk.public_key

    message = "0000.101"

    M = encode_to_point(message.encode(), pk.curve)
    ct = pk.encrypt(M, store_ephemeral=True)
    dec = ct.unblind(pk.H)

    decoded = decode_from_point(dec, pk.curve).decode()

    assert dec == M
    assert decoded == message


def test_decryption():
    sk = generate_private_key()
    pk = sk.public_key

    message = "0000.101"

    ct = pk.encode_and_encrypt(message)
    pt = sk.decrypt_and_decode(ct)

    assert pt == message


def test_provable_decryption():
    sk = generate_private_key()
    pk = sk.public_key

    message = "0000.101"

    ct = pk.encode_and_encrypt(message)
    M = sk.decrypt(ct)

    proof = generate_decryption_proof(M, ct, sk)

    assert proof.verify(M, ct, pk) is None

    with pytest.raises(VerificationError):
        proof.verify(M * 2, ct, pk)
