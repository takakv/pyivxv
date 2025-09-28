# pyivxv

A Python3 library for common IVXV operations.
IVXV is the codename for the current Estonian internet voting system.

This is an independent, 3rd party library.
It is not developed or endorsed by the Estonian [State Electoral Office](https://www.valimised.ee/en).
The official IVXV repositories can be found at [github.com/valimised](https://github.com/valimised).

> **NB!** This library should not be used in production settings, see [Security](#Security) for more details.

You can install `pyivxv` with:

```pycon
pip install pyivxv
```

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

## Security

This library is designed for testing and quick scripting, rather than for production use.

**This library does not protect against side-channel attacks!**

Do **not** use it to process sensitive data, such as a legitimate vote during an election.  
If you do, at a minimum, ensure that no attacker can observe your system during encryption or ciphertext unblinding.
This includes, for example:

- Timing measurements
- Power consumption measurements
- RF emissions measurements
- Running code on the device

Other vulnerabilities may also exist.
