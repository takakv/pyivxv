from fastecdsa.point import Point
from pyasn1.codec.der import encoder, decoder
from pyasn1_modules import rfc5280

from pyivxv.asn1.schemas import ECCElGamalDecryptionProof, ECCElGamalDecryptionChallenge, ElGamalCiphertextInfo
from pyivxv.crypto import drbg
from pyivxv.crypto.ciphertext import ElGamalCiphertext
from pyivxv.crypto.exceptions import VerificationError
from pyivxv.crypto.keys import PublicKey
from pyivxv.encoding.ec_point import point_to_bytes, point_from_bytes


class DecryptionProof:
    mComm: Point
    kComm: Point
    response: int

    def __init__(self, mc: Point, kc: Point, res: int):
        self.mComm = mc
        self.kComm = kc
        self.response = res

    def to_bytes(self) -> bytes:
        adp = ECCElGamalDecryptionProof()
        adp["aMsgCommitment"] = point_to_bytes(self.mComm)
        adp["bKeyCommitment"] = point_to_bytes(self.kComm)
        adp["sResponse"] = self.response
        return encoder.encode(adp)

    @classmethod
    def from_bytes(cls, data: bytes):
        dp, _ = decoder.decode(data, asn1Spec=ECCElGamalDecryptionProof())
        mComm = point_from_bytes(dp["aMsgCommitment"])
        kComm = point_from_bytes(dp["bKeyCommitment"])
        response = int(dp["sResponse"])
        return cls(mComm, kComm, response)

    def verify(self, M: Point, ct: ElGamalCiphertext, pk: PublicKey) -> None:
        message_bytes = point_to_bytes(M)
        mc_bytes = point_to_bytes(self.mComm)
        kc_bytes = point_to_bytes(self.kComm)

        seed = derive_seed(pk.spki, ct.to_asn1(), message_bytes, mc_bytes, kc_bytes)
        challenge = drbg.randbelow(seed, pk.curve.q)

        failed = []

        lhs1 = self.response * ct.U
        rhs1 = self.mComm + (ct.V - M) * challenge
        if lhs1 != rhs1:
            failed.append("aMsgCommitment")

        lhs2 = self.response * pk.curve.G
        rhs2 = self.kComm + pk.H * challenge
        if lhs2 != rhs2:
            failed.append("bKeyCommitment")

        if failed:
            raise VerificationError(failed)


def derive_seed(pub: rfc5280.SubjectPublicKeyInfo, enc: ElGamalCiphertextInfo, dec: bytes,
                msg_commitment: bytes, key_commitment: bytes) -> bytes:
    seed = ECCElGamalDecryptionChallenge()
    seed["niProofDomain"] = "DECRYPTION"
    seed["publicKey"] = pub
    seed["ciphertextInfo"] = enc
    seed["encodedPlaintext"] = dec
    seed["aMsgCommitment"] = msg_commitment
    seed["bKeyCommitment"] = key_commitment

    return encoder.encode(seed)
