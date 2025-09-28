from pyivxv.crypto.keys import generate_private_key, PrivateKey, PublicKey


def test_read_private_key():
    sk = generate_private_key()
    sk_der = sk.private_bytes("DER")
    sk_pem = sk.private_bytes("PEM")

    sk1 = PrivateKey.from_private_bytes(sk_der, sk.election_id)
    sk2 = PrivateKey.from_private_bytes(sk_pem, sk.election_id)
    assert sk.x == sk1.x == sk2.x


def test_read_public_key():
    pk = generate_private_key().public_key
    pk_der = pk.public_bytes("DER")
    pk_pem = pk.public_bytes("PEM")

    pk1 = PublicKey.from_public_bytes(pk_der)
    pk2 = PublicKey.from_public_bytes(pk_pem)

    assert pk.H == pk1.H == pk2.H
