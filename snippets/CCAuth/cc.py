from cryptography import x509
import PyKCS11
import binascii

# Read DER certificates with open ssl
# $ openssl x509 -in '<certFile>' -text -inform der

# Run with: $ python3 cc.py

# 5.2.1. List all slots available
print("################################################################################################")
print("\n\n5.2.1. The available slots are...")
lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

for slot in slots:
    print("\n--- Slot", slot)
    token = pkcs11.getTokenInfo(slot)
    print(token)

if len(slots) != 1:
    print(f"There are {len(slots)} slot(s) available! Can't handle it...")
    exit()

slot = slots[0]

# 5.3. List the content of the CC
print("\n\n################################################################################################")
print("\n\n5.3.Listing all the content of the CC...\n")
all_attr = list(PyKCS11.CKA.keys())
all_attr = [e for e in all_attr if isinstance(e, int)]  # Filter

session = pkcs11.openSession(slot)
certs = {}
for obj in session.findObjects():
    # Get object attributes
    attr = session.getAttributeValue(obj, all_attr)
    # Create dictionary with attributes
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

    # Output object
    print("\n--- Object")
    print('Label: ', attr['CKA_LABEL'])
    print('Class: ', attr['CKA_CLASS'])
    print('Certificate Type: ', attr['CKA_CERTIFICATE_TYPE'])

    # Add cert to certs array
    # We just want class 1 certificates
    if attr['CKA_VALUE'] and attr['CKA_CLASS']==1:
        certs[attr['CKA_LABEL']] = attr['CKA_VALUE']

# 5.3. Load certificates
print("\n\nLoading class 1 certs...")

for certName, certData in certs.items():
    print("\n--- Cert", certName)
    with open(f'certs/{certName}.cert', 'wb') as f:
        f.write(bytes(certData))
        print(f"Saved to certs/{certName}.cert")
    
    try:
        cert = x509.load_der_x509_certificate(bytes(certData))
        print(cert)
        print("Issuer:", cert.issuer)
        print("Subject:", cert.subject)
    except:
        print("ERROR")