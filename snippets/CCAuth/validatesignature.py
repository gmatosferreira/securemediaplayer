import sys
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidSignature
import PyKCS11

# Run with: $ python3 validatesignature.py <fileToValidate> <fileToSignature> <fileToPublicKey>
# Example: $ python3 validatesignature.py files/alice.txt signatures/alice.sign 'certs/CITIZEN AUTHENTICATION CERTIFICATE.cert'

# Validate arguments
if len(sys.argv) != 4:
    print("USAGE: $ python3 validatesignature.py <fileToValidate> <fileToSignature> <fileToPublicKey>")
    exit()

# 5.4. Digital signature
print("5.5. Signature validation...")

# Get certificate
print(f"\nLoading public key certificate at {sys.argv[3]}...")
f = open(sys.argv[3], 'rb')
CAC = x509.load_der_x509_certificate(bytes(f.read()))
f.close()
print(CAC)

# Load document
print(f"\nLoading document to validate at {sys.argv[1]}...")
f = open(sys.argv[1], 'rb')
text = f.read()
f.close()
print("Done!")

# Load signature
print(f"\nLoading signature at {sys.argv[2]}...")
f = open(sys.argv[2], 'rb')
signature = f.read()
f.close()
print("Done!")

# Validate signature
# 
print("\nValidating signature...")
try:
    pk = CAC.public_key()
    pk.verify(signature, text, padding.PKCS1v15(), hashes.SHA1())
except InvalidSignature:
    print("The signature is not valid!")
    exit()

print("The signature is valid!")

print("\nSee you soon! ;)")