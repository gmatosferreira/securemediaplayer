import requests
import logging
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding

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

    """
    This method asks the server for the available protocols
    and lets the user define the protocols to use.
    It returns the cipher suite.
    """
    @staticmethod
    def client_chosen_options(server_url):
        # Ask server for available protocols
        req = requests.get(f'{server_url}/api/protocols')    
        
        if req.status_code == 200:
            print("Got Protocols!")
        else:
            print("The server is not available!")
            exit()
    
        protocols = req.json()

        # Cipher choice
        while True:
            # Show options
            print("\nChoose a cipher algorithm: ")
            i=1
            for cipher in protocols['cipher']:
                print(i, ")",cipher)
                i+=1
            # Receive input
            print("> " , end =" ")
            op = int(input())
            if op >= 1 and op <= len(protocols['cipher']):
                cipher = protocols['cipher'][op-1]
                break
            print("That is not a valid option! Try again!")
        
        # Digest choice
        while True:
            # Show options
            print("\nChoose a digest: ")
            i=1
            for digest in protocols['digests']:
                print(i, ")",digest)
                i+=1
            # Receive input
            print("> " , end =" ")
            op = int(input())
            if op >= 1 and op <= len(protocols['digests']):
                cipher = protocols['digests'][op-1]
                break
            print("That is not a valid option! Try again!")

        # Cipher mode choice
        while True: 
            # Show options
            print("\nChoose a cipher mode: ")
            i=1
            for mode in protocols['cipher_mode']:
                print(i, ")",mode)
                i+=1
            # Receive input
            print("> " , end =" ")
            op = int(input())
            if op >= 1 and op <= len(protocols['cipher_mode']):
                cipher_mode = protocols['cipher_mode'][op-1]
                break
            print("That is not a valid option! Try again!")

        cipherSuite = {'cipher': cipher, 'digest': digest, 'cipher_mode':cipher_mode}
        
        return cipherSuite


    """
    This method checks and applys a digest function to a given message
    return: message with diggest
    """
    @staticmethod
    def create_digest(message, digst_algorithm):
        hash_algorithm = None
        
        if digst_algorithm == "SHA512":
            hash_algorithm = hashes.SHA512()
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
        elif algorithm == "BLAKE2":
            digst_algorithm = hashes.BLAKE2b(64)
        else:
            raise Exception("Digest Algorithm name not founded!")

        mac = hmac.HMAC(key, digst_algorithm, backend=default_backend())
        mac.update(message)
        
        return mac.finalize()

    """

    """
    @staticmethod
    def symetric_encryption(key,message, algorithm_name, cypher_mode, encode=True ):
        
        # Encode key (to bytes)
        key = str.encode(key)

        # Define algorithm
        algorithm = None
        blockLength = 0
        iv = None
        #useIv = True

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
        if encode and  iv == None:
            iv = os.urandom(blockLength)

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

        if encode:
            for i in range(0,len(message),blockLength ):
                finalIndex = i+blockLength-1 if len(message)>=i+blockLength else
                data = message[i:i+finalIndex]
                padding_length = blockLength - len(data)
                padding = [padding_length] * (padding_length)
                criptograma = cryptor.update(data + bytes(padding)) + cryptor.finalize()

        if encode:
            print(f"{source} has been sucessfully encripted to {destination}!")
        else:
            print(f"{source} has been sucessfully decripted to {destination}!")
        
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


