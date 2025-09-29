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
        self._r = r

    @property
    def ephemeral_random(self) -> int:
        if self._r is None:
            raise AttributeError("Ciphertext ephemeral random not known")
        return self._r

    @ephemeral_random.setter
    def ephemeral_random(self, r: int) -> None:
        self._r = r

    def unblind(self, H: Point, *, r: int | None = None) -> Point:
        if self._r is None and r is None:
            raise ValueError("Ciphertext ephemeral random not known")
        elif r is None and self._r is not None:
            # Explicitly provided random overrides the internal random of the class.
            # Up for debate: is that a sensible choice? Should it throw on conflict?
            # Allowing to provide r seems sensible in case r should be short-lived, but the class is long-lived.
            r = self._r

        blind = H * r
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
