import PyKCS11
from cryptography import x509

class CitizenCard:

    def __init__(self):
        """
        This class handles cryptography with portuguese citizen card
        """
        print("\nCITIZEN CARD")

        # 1. Find the slot for smart card
        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load('/usr/local/lib/libpteidpkcs11.so')
        slots = pkcs11.getSlotList()
        for slot in slots:
            print("\n--- Slot", slot)
            token = pkcs11.getTokenInfo(slot)
            print(token)
        if len(slots) != 1:
            print(f"\nThere are {len(slots)} cart slot(s) available! Can't handle it...")
            exit()
        self.slot = slots[0]

        # 2. Get the certificates for signature
        session = pkcs11.openSession(slot)

        # 2.1. Get private key
        self.private_key = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
        ])[0]
        print("\nLoaded private key...\n", self.private_key)

        # 2.2. Get public key
        self.public_key = None
        for obj in session.findObjects():
            # Get object attributes
            attr = session.getAttributeValue(obj, all_attr)
            # Create dictionary with attributes
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))

            if attr['CKA_LABEL'] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                self.public_key = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE'])).public_key()
        print("\nLoaded public key...\n", self.private_key)

        # 2.3. Validate
        if not self.private_key or not self.public_key:
            print("\nERROR! Could not load keys...")
            exit()

    def sign(self, message):
        """
        This method is used to sign a message
        --- Parameteres
        message         bytes
        --- Returns
        signature       bytes
        """
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
        return bytes(session.sign(self.private_key, message, mechanism))

    def validateSign(self, message, sign):
        """
        This method is used to validate a signature of a message
        --- Parameteres
        message         bytes
        signature       bytes
        --- Returns
        valid           bool
        """
        try:
            self.public_key.verify(sign, message, padding.PKCS1v15(), hashes.SHA1())
        except InvalidSignature:
            return False
        return True







