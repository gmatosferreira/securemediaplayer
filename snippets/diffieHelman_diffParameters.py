from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Generate some parameters. These can be reused.
parameters_server = dh.generate_parameters(generator=2, key_size=2048)
parameters_client = dh.generate_parameters(generator=2, key_size=2048)

# Generate a private key for use in the exchange.
server_private_key = parameters_server.generate_private_key()
print("server_private_bey", server_private_key)
print()

# In a real handshake the peer is a remote client. For this
# example we'll generate another local private key though. Note that in
# a DH handshake both peers must agree on a common set of parameters.
peer_private_key = parameters_client.generate_private_key()
print("peer_private_key", peer_private_key)
print()

shared_key = server_private_key.exchange(peer_private_key.public_key())
print("shared_key", shared_key)
print()

# Perform key derivation.
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)
print("derived_key", derived_key)
print()

# And now we can demonstrate that the handshake performed in the
# opposite direction gives the same final value
same_shared_key = peer_private_key.exchange(
    server_private_key.public_key()
)
print("same_shared_key", same_shared_key)
print()

same_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(same_shared_key)
print("same_derived_key", same_derived_key)
print()

assert derived_key == same_derived_key
