import requests
import logging
import binascii
import json
import os
import subprocess
import time

import sys
from aux_functions import *

# Serialization
from cryptography.hazmat.primitives import serialization

# Diffie-hellman
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import sys
sys.path.append('..')


from crypto_functions import CryptoFunctions
logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

class MediaClient:

    # Constructor
    def __init__(self, SERVER_URL):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        self.SERVER_URL = SERVER_URL

        # 1. Define the client private and public keys
        print("Initializing client...")
        self.parameters = ask_server_parameters(self.SERVER_URL)
        print("\nGot parameters\n", self.parameters)

        # 2. Generate the client private and public keys
        self.private_key, self.public_key = CryptoFunctions.newKeys(self.parameters)

        print("\nPrivate key created!\n", self.private_key)
        print(self.private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))
        print("\nPublic key generated!\n", self.public_key)
        print(self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Initialize other vars
        self.shared_key = None
        self.CIPHER = None
        self.DIGEST = None
        self.CIPHERMODE = None

    def start(self):
        """
        Defines the cipher suite and negociates the shared key
        """
        # 1. Let user choose chipher suite
        cipherSuite = client_chosen_options(self.SERVER_URL)
        self.CIPHER, self.DIGEST, self.CIPHERMODE = cipherSuite['cipher'], cipherSuite['digest'], cipherSuite['cipher_mode']
        requests.post(f'{self.SERVER_URL}/api/suite', data = cipherSuite)
        print(f"\nCipher suite defined!\nCipher: {self.CIPHER}; DIGEST: {self.DIGEST}; CIPHERMODE: {self.CIPHERMODE}")

        # 2. Negociate encription keys (Diffie-Hellman)
        self.shared_key = diffieHellman(self.SERVER_URL, self.private_key, self.public_key)
        print("\nGenerated the client shared key!\n", self.shared_key)
    
    def run(self):
        """
        This method is used to play the media content from the server
        """
        # Validate that client has already been started
        required = [self.shared_key, self.CIPHER, self.DIGEST, self.CIPHERMODE]
        if not all([a for a in required]):
            print("ERROR! The client can't be run without having been started first!")
            return

        # Get a list of media files
        print("Contacting Server")
        
        # TODO: Secure the session

        # ?. Get media list from server
        req = requests.get(f'{SERVER_URL}/api/list')
        if req.status_code == 200:
            print("Got Server List")
        
        print(req)
        print("req.content", req.content)
        media_list = json.loads(self.decipher(req.content).decode())
        print(media_list)
        
        # ?. Present a simple selection menu    
        idx = 0
        print("MEDIA CATALOG\n")
        for item in media_list:
            print(f'{idx} - {media_list[idx]["name"]}')
        print("----")

        while True:
            selection = input("Select a media file number (q to quit): ")
            if selection.strip() == 'q':
                sys.exit(0)

            if not selection.isdigit():
                continue

            selection = int(selection)
            if 0 <= selection < len(media_list):
                break

        # Example: Download first file
        media_item = media_list[selection]
        print(f"Playing {media_item['name']}")

        # Detect if we are running on Windows or Linux
        # You need to have ffplay or ffplay.exe in the current folder
        # In alternative, provide the full path to the executable
        if os.name == 'nt':
            proc = subprocess.Popen(['ffplay.exe', '-i', '-'], stdin=subprocess.PIPE)
        else:
            proc = subprocess.Popen(['ffplay', '-i', '-'], stdin=subprocess.PIPE)

        # Get data from server and send it to the ffplay stdin through a pipe
        for chunk in range(media_item['chunks'] + 1):
            req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
            
            chunk = json.loads(self.decipher(req.content).decode())
                
            # TODO: Process chunk

            data = binascii.a2b_base64(chunk['data'].encode('latin'))
            try:
                proc.stdin.write(data)
            except:
                break

    def decipher(self, content):
        """
        Deciphers a criptogram passed as argument
        """
        return CryptoFunctions.symetric_encryption( 
            key = self.shared_key, 
            message = content, 
            algorithm_name = self.CIPHER, 
            cypher_mode = self.CIPHERMODE, 
            digest_mode = self.DIGEST, 
            encode = False 
        ) 
    
c = MediaClient(SERVER_URL)
c.start()

while True:
    c.run()
    time.sleep(1)