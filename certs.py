from cryptography import x509
import PyKCS11
import binascii

"""
    Method used to load certificate from file 
"""
def load_cert(file):
    
    try:
        with open(file, "rb") as f:
            pem_data = f.read()
            cert = x509.load_pem_x509_certificate(pem_data)
        return cert
    except:
        print("ERROR")

    try:
        with open(file, "rb") as f:
            pem_data = f.read()
            cert = x509.load_der_x509_certificate(pem_data)
        return cert
    except:
        print("ERROR")

