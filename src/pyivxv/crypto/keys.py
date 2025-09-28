import base64
import secrets
from textwrap import wrap
from typing import Literal

from fastecdsa import keys
from fastecdsa.curve import P384
from fastecdsa.point import Point
from pyasn1.codec.der import decoder as der_decoder, encoder as der_encoder
from pyasn1.type import tag
from pyasn1.type.univ import BitString
from pyasn1_modules import rfc5280, rfc5915, rfc5480

from pyivxv.asn1.schemas import ECCElGamalPublicKey, ECCElGamalParameters, id_ivxv_ecc_elgamal
from pyivxv.crypto.ciphertext import ElGamalCiphertext
from pyivxv.encoding.ec_point import point_from_bytes, point_to_der
from pyivxv.encoding.message import encode_to_point, decode_from_point
from pyivxv.encoding.pem import pem_to_der


class PublicKey:
    def __init__(self, H: Point, election_id: str, spki: rfc5280.SubjectPublicKeyInfo | None = None):
        self.H = H
        self.election_id = election_id

        if spki is None:
            spki = self._to_asn1()

        self.spki = spki

    @classmethod
    def from_public_bytes(cls, data: bytes):
        spki, _ = der_decoder.decode(pem_to_der(data), asn1Spec=rfc5280.SubjectPublicKeyInfo())
        pkey, _ = der_decoder.decode(spki["subjectPublicKey"].asOctets(), asn1Spec=ECCElGamalPublicKey())
        params, _ = der_decoder.decode(spki["algorithm"]["parameters"].asOctets(), asn1Spec=ECCElGamalParameters())
        return cls(point_from_bytes(pkey["pubY"]), params["electionId"], spki)

    def public_bytes(self, encoding: Literal["DER", "PEM"] = "DER") -> bytes:
        if encoding != "DER" and encoding != "PEM":
            raise ValueError("Unsupported encoding")

        der = der_encoder.encode(self.spki)
        if encoding == "DER":
            return der

        b64 = base64.b64encode(der).decode("ascii")
        pem_lines = wrap(b64, 64)
        pem_lines = ["-----BEGIN PUBLIC KEY-----"] + pem_lines + ["-----END PUBLIC KEY-----"]
        pem_bytes = "\n".join(pem_lines).encode("ascii")
        return pem_bytes

    def encrypt(self, M: Point, store_ephemeral=False) -> ElGamalCiphertext:
        r = secrets.randbelow(self.curve.q)
        return ElGamalCiphertext(self.curve.G * r, M + (self.H * r),
                                 r if store_ephemeral else None)

    def encode_and_encrypt(self, m: str) -> ElGamalCiphertext:
        encoded = encode_to_point(m.encode(), self.curve)
        return self.encrypt(encoded)

    def _to_asn1(self) -> rfc5280.SubjectPublicKeyInfo:
        params = ECCElGamalParameters()
        params["curve"] = "P-384"
        params["electionId"] = self.election_id

        spki = rfc5280.SubjectPublicKeyInfo()
        spki["algorithm"]["algorithm"] = id_ivxv_ecc_elgamal
        spki["algorithm"]["parameters"] = params

        x_bytes = self.H.x.to_bytes(48, "big")
        y_bytes = self.H.y.to_bytes(48, "big")
        ec_point = b"\x04" + x_bytes + y_bytes

        pk = ECCElGamalPublicKey()
        pk["pubY"] = ec_point
        pk_der = der_encoder.encode(pk)

        spki["subjectPublicKey"] = BitString.fromOctetString(pk_der)
        return spki

    @property
    def curve(self):
        return self.H.curve


class PrivateKey:
    def __init__(self, x: int, election_id: str, curve=P384):
        self.x = x
        self.election_id = election_id
        self.curve = curve
        self.public_key = PublicKey(self.x * self.curve.G, self.election_id)

    @classmethod
    def from_private_bytes(cls, data: bytes, election_id: str, curve=P384):
        ecpk, _ = der_decoder.decode(pem_to_der(data), asn1Spec=rfc5915.ECPrivateKey())
        x = int.from_bytes(ecpk["privateKey"].asOctets(), "big")
        return cls(x, election_id, curve)

    def private_bytes(self, encoding: Literal["DER", "PEM"] = "DER") -> bytes:
        if encoding != "DER" and encoding != "PEM":
            raise ValueError("Unsupported encoding")

        ec_params = rfc5480.ECParameters().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )
        ec_params["namedCurve"] = rfc5480.secp384r1

        ec_pub = BitString().fromOctetString(point_to_der(self.public_key.H)).subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))

        epk = rfc5915.ECPrivateKey()
        epk["version"] = 1
        epk["privateKey"] = self.x.to_bytes(48, "big")
        epk["parameters"] = ec_params
        epk["publicKey"] = ec_pub

        der = der_encoder.encode(epk)
        if encoding == "DER":
            return der

        pem_type = "EC PRIVATE KEY"

        b64 = base64.b64encode(der).decode("ascii")
        pem_lines = wrap(b64, 64)
        pem_lines = [f"-----BEGIN {pem_type}-----"] + pem_lines + [f"-----END {pem_type}-----"]
        pem_bytes = "\n".join(pem_lines).encode("ascii")
        return pem_bytes

    def decrypt(self, ct: ElGamalCiphertext) -> Point:
        D = self.x * ct.U
        return ct.V - D

    def decrypt_and_decode(self, ct: ElGamalCiphertext) -> str:
        M = self.decrypt(ct)
        m_bytes = decode_from_point(M, self.curve)
        return m_bytes.decode()


def generate_private_key(election_id: str = "TEST") -> PrivateKey:
    x, H = keys.gen_keypair(P384)
    return PrivateKey(x, election_id)
