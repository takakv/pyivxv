# pyivxv

A Python3 library for common IVXV operations.
IVXV is the codename for the current Estonian internet voting system.

Usage examples:

```python
from pyivxv.crypto.keys import PublicKey
from pyivxv.encoding.message import decode_from_point

pk = PublicKey.from_public_bytes(b"...")

message = "0000.101"
ct = pk.encode_and_encrypt(message, store_ephemeral=True)

unblinded = ct.unblind(pk.H)
decoded = decode_from_point(unblinded, pk.curve).decode()

print("Message:", message)
print("Encryption randomness:", ct.ephemeral_random)
```

```python
from pyivxv.crypto.keys import generate_private_key
from pyivxv.crypto.zkp import generate_decryption_proof

sk = generate_private_key()
pk = sk.public_key

message = "0000.101"
ct = pk.encode_and_encrypt(message)
M = sk.decrypt(ct)

proof = generate_decryption_proof(M, ct, sk)
proof.verify(M, ct, pk)
```
