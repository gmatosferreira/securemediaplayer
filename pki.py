import os
from cryptography import x509
from datetime import datetime
import pathlib

class PKI:

    TRUSTEDCERTS = {
        # Folder: PEM format?
        '../certscc': False,
        '../certsca': True,
        '/etc/ssl/certs': True,
    }

    def __init__(self, certificate, intermedium, pem = False):
        """
        This class must be initialized with a cert to validate and a list of intermedium ones
        --- Parameters
        certificate         String
        intermedium         String[]
        """
        print("\nPKI")

        # Load certificate
        if pem:
            self.cert = x509.load_pem_x509_certificate(certificate.encode('latin'))
        else:
            self.cert = x509.load_der_x509_certificate(certificate.encode('latin'))
        print("\nGot cert\n", self.cert)

        # Load intermedium certs
        self.intermedium = {}
        for c in intermedium:
            if pem:
                pkic = x509.load_pem_x509_certificate(c.encode('latin'))
            else:
                pkic = x509.load_der_x509_certificate(c.encode('latin'))
            self.intermedium[pkic.subject] = pkic
        print("\nGot intermedium certs list...\n", self.intermedium)

        # Get all system certs
        self.systemcerts = {}
        for folder, pem in PKI.TRUSTEDCERTS.items():
            for file in os.scandir(folder):
                # Validate if it is a certificate
                if not file.is_file():
                    continue
                # Get certificate at file
                cert = PKI.getCert(file.path, pem)
                self.systemcerts[cert.subject] = cert

    def validateCerts(self):
        """
        This method validates the certificate
        """
        return PKI.validateCertHierarchy(self.cert, self.intermedium, self.systemcerts)

    @staticmethod
    def getCert(fileLocation, pem=True):
        """
        This method allows to load a certificate from a file
        """
        print("Loading cert from...", fileLocation)
        f = open(fileLocation, 'rb')
        data = f.read()
        if pem:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
        f.close()
        return cert

    @staticmethod
    def certRevoked(cert):
        """
        This method tells is the certificate has been revoked
        """
        if cert.not_valid_before < datetime.now() and cert.not_valid_after > datetime.now():
            return False
        return True

    @staticmethod
    def validateCertHierarchy(cert, intermedium, trustable):
        """
        This method validates a certificate given a list of intermedium and trustable (system) certificates
        """
        print(f"> Validating {cert.subject}")
        # Check that it has not expired
        if PKI.certRevoked(cert):
            print(f"> Certificate has already expired!")
            return False
        # If issuer is trustable, it is valid
        if cert.issuer in trustable:
            print(f"> It was issued by {cert.issuer}, a trustable issuer!")
            return True
        # If it was self signed and not trusted, return to avoid infinite loop
        if cert.issuer == cert.subject:
            print(f"The certificate is self signed, but is not on trusted list!")
            return False
        # If it is intermedium, validate intermedium
        if cert.issuer in intermedium:
            print(f"> It was issued by an intermedium issuer ({cert.issuer}), validating it...")
            return PKI.validateCertHierarchy(intermedium[cert.issuer], intermedium, trustable)
        # If not valid, return False
        print(f"> The issuer ({cert.issuer}) is not registered as a intermedium or trustable issuer!")
        return False