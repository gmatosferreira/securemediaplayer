import sys
from cryptography import x509
import PyKCS11

# Run with: $ python3 digitalsignature.py <fileToSign> <fileToStoreSignature>
# Example: $ python3 digitalsignature.py files/alice.txt signatures/alice.sign

# Validate arguments
if len(sys.argv) != 3:
    print("USAGE: $ python3 digitalsignature.py <fileToSign> <fileToStoreSignature>")
    exit()

# Get CC slot and start session for that one
lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

for slot in slots:
    token = pkcs11.getTokenInfo(slot)

if len(slots) != 1:
    print(f"There are {len(slots)} slot(s) available! Can't handle it...")
    exit()

slot = slots[0]
session = pkcs11.openSession(slot)

# 5.4. Digital signature
print("5.4.Digital signature...")

# Get private key
print("\nLoading CITIZEN AUTHENTICATION KEY (private key)...")
private_key = session.findObjects([
    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
    (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
])[0]
mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)

# Load document
print(f"\nSigning {sys.argv[1]}...")
f = open(sys.argv[1], 'rb')
text = f.read()
f.close()
signature = bytes(session.sign(private_key, text, mechanism))

# Save signature
with open(sys.argv[2], 'wb') as fs:
    fs.write(signature)
print(f"\nSaved signature at {sys.argv[2]}!")

print("\nSee you soon! ;)")