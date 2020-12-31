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

    def __init__(self):
        """
        This class allows for the certification chain validation
        """
        # Get all trustable certs
        self.trustedcerts = {}
        for folder, pem in PKI.TRUSTEDCERTS.items():
            for file in os.scandir(folder):
                # Validate if it is a certificate
                if not file.is_file():
                    continue
                # Get certificate at file
                cert = PKI.getCert(file.path, pem)
                self.trustedcerts[cert.subject] = cert

    def validateCerts(self, certificate, intermedium, pem = False):
        """
        This method validates the a certification chain for a given certificate
        --- Parameters
        certificate         String
        intermedium         String[]
        pem                 Tells if certs are PEM or DER
        """
        # Load certificate
        if pem:
            cert = x509.load_pem_x509_certificate(certificate.encode('latin'))
        else:
            cert = x509.load_der_x509_certificate(certificate.encode('latin'))

        # Load intermedium certs
        intermediumCerts = {}
        for c in intermedium:
            if pem:
                pkic = x509.load_pem_x509_certificate(c.encode('latin'))
            else:
                pkic = x509.load_der_x509_certificate(c.encode('latin'))
            intermediumCerts[pkic.subject] = pkic

        return PKI.validateCertHierarchy(cert, intermediumCerts, self.trustedcerts)

    @staticmethod
    def getCert(fileLocation, pem = False):
        """
        This method allows to load a certificate from a file
        """
        f = open(fileLocation, 'rb')
        data = f.read()
        if pem:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
        f.close()
        return cert

    @staticmethod
    def getCertFromString(certString, pem = False):
        """
        This method allows to load a certificate from a file
        """
        if type(certString) != bytes:
            data = certString.encode('latin')
        else:
            data = certString
        if pem:
            cert = x509.load_pem_x509_certificate(data)
        else:
            cert = x509.load_der_x509_certificate(data)
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
        # Check that it has not expired
        if PKI.certRevoked(cert):
            return False
        # If issuer is trustable, it is valid
        if cert.issuer in trustable:
            return True
        # If it was self signed and not trusted, return to avoid infinite loop
        if cert.issuer == cert.subject:
            return False
        # If it is intermedium, validate intermedium
        if cert.issuer in intermedium:
            return PKI.validateCertHierarchy(intermedium[cert.issuer], intermedium, trustable)
        # If not valid, return False
        return False