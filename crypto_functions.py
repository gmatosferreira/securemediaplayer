import requests
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding
from cryptography.fernet import Fernet


class CryptoFunctions:

    suites = [
        'AES / CBC / SHA512',
        'AES / OFB / SHA512',
        '3DES / CBC / BLAKE2',
        '3DES / OFB / BLAKE2',
    ]
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

        # Define algorithm
        algorithm = None
        blockLength = 0
        iv = None

        if algorithm_name == "AES":
            key = CryptoFunctions.validateKey(key, digest_mode, 256)
            algorithm = algorithms.AES(key)
            # Divide by 8 because it returns size on bits and we want on bytes (8 bits)
            blockLength = algorithms.AES.block_size // 8
            
        elif algorithm_name == "3DES":
            key = CryptoFunctions.validateKey(key, digest_mode, 192)
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
    def validateKey(key, digest_mode, size):
        """
        This method makes a key suitable for requested size
        If it does not have that size, a digest is created
        - Parameteres
        key             bytes
        digest_mode     String
        size            Number of bits
        """
        # If key length does not match expected, create digest for it
        if len(key)*8 != size:
            return CryptoFunctions.create_digest(key, digest_mode)
        return key        

    @staticmethod
    def signingRSA(message, private_key):
        print("\nSIGNING...", message)
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), 
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return signature

    @staticmethod
    def validacaoAssinatura_RSA(signature, message, public_key):
        """
        Valida assinatura
        param: signature        Bytes
        param: message          Bytes
        param: public_key       Public Key
        """
        print("\nVALIDATING SIGNATURE OF...", message)
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()), 
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except:
            return TypeError

        return True
    
   
            

        

        

