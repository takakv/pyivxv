from pyasn1.type.char import GeneralString
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import ObjectIdentifier, Sequence, OctetString, Integer
from pyasn1_modules import rfc5280

id_ivxv_ecc_elgamal = ObjectIdentifier("1.3.6.1.4.1.99999.1")


class ECCElGamalParameters(Sequence):
    componentType = NamedTypes(
        NamedType("curve", GeneralString()),
        NamedType("electionId", GeneralString())
    )


class ECCElGamalPublicKey(Sequence):
    componentType = NamedTypes(NamedType("pubY", OctetString()))


class ECCElGamalCiphertext(Sequence):
    componentType = NamedTypes(
        NamedType("uBlind", OctetString()),
        NamedType("vBlindedMessage", OctetString())
    )


class ElGamalCiphertextInfo(Sequence):
    componentType = NamedTypes(
        NamedType("algorithm", rfc5280.AlgorithmIdentifier()),
        NamedType("ciphertext", ECCElGamalCiphertext())
    )


class ECCElGamalDecryptionProof(Sequence):
    componentType = NamedTypes(
        NamedType("aMsgCommitment", OctetString()),
        NamedType("bKeyCommitment", OctetString()),
        NamedType("sResponse", Integer())
    )


class ECCElGamalDecryptionChallenge(Sequence):
    componentType = NamedTypes(
        NamedType("niProofDomain", GeneralString()),
        NamedType("publicKey", rfc5280.SubjectPublicKeyInfo()),
        NamedType("ciphertextInfo", ElGamalCiphertextInfo()),
        NamedType("encodedPlaintext", OctetString()),
        NamedType("aMsgCommitment", OctetString()),
        NamedType("bKeyCommitment", OctetString())
    )
