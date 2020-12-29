from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key


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
            key = load_pem_private_key(f.read(), password="key".encode('utf-8'))
        return key
    except:
        raise TypeError

"""
    Method used to load certificate key from file 
    return: certificate key object
"""
def load_all_certs():
        #load server cert
        server_cert = load_cert("certificates/server_cert.pem")
        print(server_cert)
        print(server_cert.issuer)
        print(server_cert.subject)

        ca_cert = load_cert("certsca/CA_cert.pem" )
        print(ca_cert)
        print(ca_cert.issuer)
        print(ca_cert.subject)
        
        rsa_private_key = load_cert_key("keys/server_cert_key.pk8")
        print(rsa_private_key)


if __name__ == '__main__':
    load_all_certs()
