from fastecdsa.curve import P384

from pyivxv.encoding.message import encode_to_point, decode_from_point


def test_encoding():
    curve = P384

    message = "0000.101"
    encoded = encode_to_point(message.encode(), curve)
    decoded = decode_from_point(encoded, curve).decode()

    assert decoded == message
