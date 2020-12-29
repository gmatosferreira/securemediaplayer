import requests
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.fernet import Fernet


class CryptoFunctions:

    digests = ['SHA512', 'BLAKE2']

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

    """
    This method checks and applys a digest function to a given message
    The default size is 256
    --- Returns
    digest      bytes
    """
    @staticmethod
    def create_digest(message, digst_algorithm):
        hash_algorithm = None
        
        if digst_algorithm == "SHA512":
            hash_algorithm = hashes.SHA512_256()
        elif digst_algorithm == "BLAKE2":
            hash_algorithm = hashes.BLAKE2b(64)
        else:
            print("Digest Algorithm name not founded! ")
        
        digest = hashes.Hash(hash_algorithm)
        digest.update(message)
        
        return digest.finalize()

    @staticmethod
    def create_mac(message, key, digst_algorithm):
        
        hash_algorithm = None

        if digst_algorithm == "SHA512":
            hash_algorithm = hashes.SHA512()
        elif digst_algorithm == "BLAKE2":
            hash_algorithm = hashes.BLAKE2b(64)
        else:
            raise Exception("Digest Algorithm name not founded!")

        mac = hmac.HMAC(key, digst_algorithm, backend=default_backend())
        mac.update(message)
        
        return mac.finalize()

    """
    This method handles symetric encryption/decription
    --- Parameters
    key             String      The key to use on encription/decription
    message         Bytes       The text to encrypt/crytpogram to decript
    algorithm_name  String      AES or 3DES
    cypher_mode     String      CBC or OFB
    digest_mode     String      SHA512 or BLAKE2
    encode          bool        True for encription and False for decription
    --- Returns
    criptograma     Bytes       Criptogram for encription and plain text for decription
    """
    @staticmethod
    def symetric_encryption(key,message, algorithm_name, cypher_mode, digest_mode, encode=True ):

        # If key length does not match expected, create digest for it
        print(f"\nSymetric encription with key of size {len(key)*8}...")
        if len(key)*8 != 256:
            key = CryptoFunctions.create_digest(key, digest_mode)
        print(f"Symetric encription with key of size {len(key)*8}...")

        # Define algorithm
        algorithm = None
        blockLength = 0
        iv = None

        if algorithm_name == "AES":
            algorithm = algorithms.AES(key)
            # Divide by 8 because it returns size on bits and we want on bytes (8 bits)
            blockLength = algorithms.AES.block_size // 8
            
        elif algorithm_name == "3DES":
            algorithm = algorithms.TripleDES(key[:24])
            blockLength = algorithm.block_size // 8
            
        else:
            raise Exception("Algorithm not found!")


        print(f"# Going to work with {algorithm.name} algorithm")
        print("# Block size will be", blockLength)

        # Generate initialization vector
        if encode and iv == None:
            iv = os.urandom(blockLength)
        # On decription, get IV
        else:
            iv = message[0:blockLength]
            message = message[blockLength:]

        # Initialize Cipher with user chosen algorithm and Cipher Block Chaining mode
        if cypher_mode == "CBC":
            cipher = Cipher(algorithm, modes.CBC(iv))
        elif cypher_mode == "OFB":
            cipher = Cipher(algorithm,  modes.OFB(iv))
        else:
            raise Exception("Cypher mode not found!")

        # Get encryptor for initialized cipher
        if encode:
            cryptor = cipher.encryptor()
        else:
            cryptor = cipher.decryptor()

        criptograma = b""

        # On encription, save IV at the beggining
        if encode:
            criptograma += iv

        # Iterate over blocks
        print(f"# Starting from 0 to {len(message)+1} with jumps of {blockLength}")
        for i in range(0,len(message)+1,blockLength):
            data = message[i:i+blockLength] if i < len(message) else b''
            # If data has block size, just encrypt
            if len(data) == blockLength:
                criptograma += cryptor.update(data)
            # If smaller, reached end, add/remove padding and finalyze
            else:
                # On encription, save IV at the beggining
                if encode:
                    padding_length = blockLength - len(data)
                    padding = [padding_length] * (padding_length)
                    criptograma += cryptor.update(data + bytes(padding))
        print()
    
        # Add finalization on both modes
        criptograma += cryptor.finalize()
        print(f"Finished at index {i} to {i+blockLength-1}")

        # If decripting, remove padding
        if not encode:
            print("Removing padding of ", criptograma[-1])
            criptograma = criptograma[:-1*criptograma[-1]]
            
        if encode:
            print(f"Encripted to\n{criptograma}")
        else:
            print(f"Decripted to\n{criptograma}")
        
        return criptograma

    @staticmethod
    def signingRSA(message, private_key):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return signature

    @staticmethod
    def validacaoAssinatura_RSA(signature, message, public_key):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256(),
            )
        except:
            print("erro ao verificar a assinatura")
            return False

        return True
    
   
            

        

        

