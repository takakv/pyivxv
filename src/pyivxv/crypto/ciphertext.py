from fastecdsa.point import Point
from pyasn1.codec.der import encoder as der_encoder, decoder as der_decoder
from pyasn1_modules.rfc5280 import AlgorithmIdentifier

from pyivxv.asn1.schemas import ElGamalCiphertextInfo, ECCElGamalCiphertext, id_ivxv_ecc_elgamal
from pyivxv.encoding.ec_point import point_to_bytes, point_from_bytes


class ElGamalCiphertext:
    U: Point
    V: Point

    def __init__(self, U: Point, V: Point, r: int | None = None):
        self.U = U
        self.V = V
        self.r = r

    def unblind(self, H: Point) -> Point:
        if self.r is None:
            raise ValueError("Ciphertext ephemeral random not known")
        blind = H * self.r
        return self.V - blind

    def to_asn1(self) -> ElGamalCiphertextInfo:
        eem = ECCElGamalCiphertext()
        eem["uBlind"] = point_to_bytes(self.U)
        eem["vBlindedMessage"] = point_to_bytes(self.V)

        ai = AlgorithmIdentifier()
        ai["algorithm"] = id_ivxv_ecc_elgamal

        eb = ElGamalCiphertextInfo()
        eb["algorithm"] = ai
        eb["ciphertext"] = eem

        return eb

    def to_bytes(self) -> bytes:
        return der_encoder.encode(self.to_asn1())

    @classmethod
    def from_bytes(cls, data: bytes):
        eb, _ = der_decoder.decode(data, asn1Spec=ElGamalCiphertextInfo())
        eem = eb["ciphertext"]
        return cls(point_from_bytes(eem["uBlind"]), point_from_bytes(eem["vBlindedMessage"]))
