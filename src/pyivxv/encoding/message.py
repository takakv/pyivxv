from fastecdsa.curve import Curve
from fastecdsa.point import Point

from pyivxv.math.ntheory import legendre, tonelli

PADDING_HEAD = [
    [0x00],
    [0b00111111],
    [0b00011111],
    [0b00001111],
    [0b00000111],
    [0b00000011],
    [0b00000001],
    [0b00000000, 0b11111111],
    [0b00000000, 0b01111111],
    [0b00000000, 0b00111111],
    [0b00000000, 0b00011111]
]
PADDING_FILL = b"\xFF"
PADDING_END = b"\xFE"
IVXV_SHIFT = 10


def encode_to_point(message: bytes, curve: Curve, shift=IVXV_SHIFT) -> Point:
    curve_byte_len = (curve.p.bit_length() + 7) // 8

    padding_head = PADDING_HEAD[shift]
    padding_len = curve_byte_len - len(padding_head) - len(message) - 1
    padded = bytes(padding_head) + (PADDING_FILL * padding_len) + PADDING_END + message

    candidate = int.from_bytes(padded, "big") << shift
    max_tries = 2 ** shift
    for _ in range(max_tries):
        # y^2 = x^3 + ax + b
        rhs = (pow(candidate, 3, curve.p) + curve.a * candidate + curve.b) % curve.p
        if legendre(rhs, curve.p) == 1:
            y = tonelli(rhs, curve.p)
            return Point(candidate, y, curve)
        candidate += 1

    raise RuntimeError("could not encode the data as a curve point")


def decode_from_point(M: Point, curve: Curve, shift=IVXV_SHIFT) -> bytes:
    curve_byte_len = (curve.p.bit_length() + 7) // 8

    x_bytes = M.x.to_bytes(curve_byte_len, "big")

    # The padded message is structured as follows: 01 head || padding 0 || message.
    # The leading (padding) bits must be 0b01.
    # The padding head is necessary for byte-length alignment and length. It consists of 1-bits that follow
    # the leading 0b01 and 0-bits that precede the leading 0b01.
    # The padding itself consists of 1-bits, and is terminated by a 0-bit ([0xFF]* 0xFE after right-shifting).
    if (x_bytes[0] & 0b11000000) != 0b01000000:
        raise RuntimeError("incorrect leading plaintext padding bits")

    tmp = M.x >> shift
    padded = tmp.to_bytes(curve_byte_len, "big")

    # Verify the padding header to ensure that the shift is correct.
    head = PADDING_HEAD[shift]
    if bytes(head) != padded[:len(head)]:
        raise RuntimeError("incorrect padding heading")

    try:
        # 0xFE = 0b11111110 as the byte-aligned padding is terminated by a 0-bit.
        padding_end = padded.index(0xfe)
    except ValueError:
        raise RuntimeError("padding end not found")

    unpadded = padded[padding_end + 1:]
    return unpadded
