from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
from crypto_functions import *


"""
    Method used to load certificate from file 
    return: certificate object
"""
def load_cert(file):
    
    try:
        with open(file, "rb") as f:
            data = f.read()
            cert = x509.load_pem_x509_certificate(data)

        return cert
    except:
        raise TypeError

"""
    Method used to load certificate key from file 
    return: certificate key object
"""
def load_cert_key(file):
    
    try:
        with open(file, "rb") as f:
            key = load_pem_private_key(f.read(), password=None)
        return key
    except:
        raise False

"""
    Method used to load certificate key from file 
    return: certificate key object
"""
def load_all_certs():
        #load server cert
        client_cert = load_cert("certificates/client_localhost.crt")
        print(client_cert)
        print(client_cert.issuer)
        print(client_cert.subject)
        server_cert = load_cert("certificates/server_localhost.crt")
        print(server_cert)
        print(server_cert.issuer)
        print(server_cert.subject)
        ca_cert = load_cert("certsca/SIO_CA.pem" ) 
        print(ca_cert)
        print(ca_cert.issuer)
        print(ca_cert.subject)
        
        client_private_key = load_cert_key("keys/client_localhost.pem")
        print(client_private_key)
        server_privateKey = load_cert_key("keys/server_localhost.pem")
        print(server_privateKey)

        print("\n\n\nSigning test...")
        message = b"asdsfgh"
        print(f"\nGoing to sign {message} with server private key")
        sign = CryptoFunctions.signingRSA(message, server_privateKey)
        print("\nGenerated signature...\n", sign)
        print("\nGoing to validate signature...")

        print(CryptoFunctions.validacaoAssinatura_RSA(
            signature=sign,
            message= message,
            public_key=server_cert.public_key()
        ))




if __name__ == '__main__':
    load_all_certs()
