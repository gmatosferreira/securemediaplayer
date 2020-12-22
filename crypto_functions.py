from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.hazmat.primitives import hashes

class CryptoFunctions:

    """
    This method handles the creation of private/public keys pair
    --- Returns
    (private, public) 
    """
    @staticmethod
    def newKeys(parameters):
        # Create a private key
        private = parameters.generate_private_key()
        # Create a public key
        public = private.public_key()
        return private, public

    """
    This method creates a criptogram for a message ciphered with a public key
    --- Parameteres
    key             The key to cipher with
    message         The text to cipher
    algorithm       The algorithm to cipher with
    --- Returns
    criptogram      The text ciphered
    """
    @staticmethod
    def assymetric_encryption(key, message, algorithm=hashes.SHA256):
        return key.encrypt(
            message,
            padding.OAEP(
                mgf = padding.MGF1(algorithm=hashes.SHA256()),
                algorithm = hashes.SHA256(),
                label = None
            )
        )

    @staticmethod
    def assymetric_decryption(key, cryptogram, algorithm=hashes.SHA256):
        return key.decrypt(
            cryptogram,
            padding.OAEP(
                mgf = padding.MGF1(algorithm=algorithm()),
                algorithm = algorithm(),
                label = None
            )
        )
