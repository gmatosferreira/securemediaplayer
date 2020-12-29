import PyKCS11
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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
        if len(slots) != 1:
            print(f"\nThere are {len(slots)} cart slot(s) available! Can't handle it...")
            exit()
        slot = slots[0]

        # 2. Get the certificates for signature
        self.session = pkcs11.openSession(slot)

        # 2.1. Get private key
        self.private_key = self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY'),
        ])[0]
        print("Loaded private key...")

        # 2.2. Get certificate
        self.cert = None
        self.intermedium = []
        all_attr = list(PyKCS11.CKA.keys())
        all_attr = [e for e in all_attr if isinstance(e, int)]  # Filter
        for obj in self.session.findObjects():
            # Get object attributes
            attr = self.session.getAttributeValue(obj, all_attr)
            # Create dictionary with attributes
            attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
            # We just want the class 1 certificates
            if attr['CKA_CLASS']==1:
                if attr['CKA_LABEL'] == 'CITIZEN AUTHENTICATION CERTIFICATE':
                    self.cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']))
                    print("Loaded cert!", self.cert)
                else:
                    c = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']))
                    self.intermedium.append(c)
                    print("Loaded interdium...", c)
        print("Loaded all certificates...")

        # 2.3. Validate
        if not self.private_key or not self.cert:
            print("\nERROR! Could not load keys...")
            exit()
        print()

    def sign(self, message):
        """
        This method is used to sign a message
        --- Parameteres
        message         bytes
        --- Returns
        signature       bytes
        """
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
        return bytes(self.session.sign(self.private_key, message, mechanism))

    @staticmethod
    def validateSignature(public_key, message, sign):
        """
        This method is used to validate a signature of a message
        --- Parameteres
        public_key      
        message         bytes
        signature       bytes
        --- Returns
        valid           bool
        """
        try:
            public_key.verify(sign, message, padding.PKCS1v15(), hashes.SHA1())
        except InvalidSignature:
            return False
        return True







