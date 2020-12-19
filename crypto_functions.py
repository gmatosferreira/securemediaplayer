from cryptography.hazmat.primitives.asymmetric import dh

class CryptoFunctions:

    parameters = dh.generate_parameters(generator=2, key_size=2048)

    """
    This method handles the creation of private/public keys pair
    --- Returns
    (private, public) 
    """
    @staticmethod
    def newKeys():
        # Create a private key
        private = CryptoFunctions.parameters.generate_private_key()
        # Create a public key
        public = private.public_key()
        return private, public