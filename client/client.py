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
        print("Initializing client...")

        # 1. Get DH parameters from server 
        req = requests.get(f'{self.SERVER_URL}/api/parameters')
        data = self.processResponse(
            request = req,
            ciphered = False
        )
        if req.status_code != 200:
            self.responseError(req, data)
            exit()
        self.parameters = serialization.load_pem_parameters(bytes(data['parameters'], 'utf-8'))   
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
        self.sessionid = None
        self.shared_key = None
        self.CIPHER = None
        self.DIGEST = None
        self.CIPHERMODE = None
    
    def start(self):
        """
        Defines the cipher suite, negociates the shared key and authenticates the user at the server
        """
        # 1. Let user choose chipher suite
        # 1.1. Ask server for available protocols 
        req = requests.get(f'{self.SERVER_URL}/api/protocols')            
        data = self.processResponse(
            request = req,
            ciphered = False
        )
        if req.status_code != 200:
            self.responseError(req, data)
            exit()   
        # 1.2. Let user choose the cipher suite to use
        cipherSuite = client_chosen_options(data)
        self.CIPHER, self.DIGEST, self.CIPHERMODE = cipherSuite['cipher'], cipherSuite['digest'], cipherSuite['cipher_mode']
        print(f"\nCipher suite defined!\nCipher: {self.CIPHER}; DIGEST: {self.DIGEST}; CIPHERMODE: {self.CIPHERMODE}")
        
        # 2. Register client at server and negociate encription keys (Diffie-Hellman)

        # 2.1. Exchange public key with the server
        pk = self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("\nSerialized public key to send server!\n", pk)
        data = cipherSuite
        data['public_key'] = pk.decode('utf-8') 
        req = requests.post(f'{self.SERVER_URL}/api/register', data=data)
        reqdata = self.processResponse(
            request = req,
            ciphered = False
        )
        if req.status_code != 200:
            self.responseError(req, reqdata)
            exit()
        # 2.1.1. Get the session id
        self.sessionid = uuid.UUID(bytes=req.headers['sessionid'].encode('latin'))
        print("\nGot session id...\n", self.sessionid)
        # 2.1.2. Get the server public key as an answer to the POST request
        server_public_key_bytes = bytes(reqdata['public_key'], 'utf-8')
        server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
        print("\nGot the server public key!\n", server_public_key)

        # 2.2. Generate the shared key based on the server public key
        self.shared_key = self.private_key.exchange(server_public_key)
        print("\nGenerated the client shared key!\n", self.shared_key)

        # 3. Authenticate at server
        while True:
            print("\nAUTHENTICATION")
            username = input("Username: ")
            password = input("Password: ")
            if not username or not password: continue
            data, MIC  = self.cipher({"username": username, "password": password})
            req = requests.post(f'{self.SERVER_URL}/api/auth', data = data, headers = {'mic': MIC, 'sessionid': self.sessionid.bytes})
            reqResp = self.processResponse(request = req)
            if req.status_code != 200:
                self.responseError(req, reqResp)
            else:
                print("\nAUTHENTICATION SUCCESSFUL!")
                break


    def run(self):
        """
        This method is used to play the media content from the server
        """
        # 1. Validate that client has already been started
        required = [self.shared_key, self.CIPHER, self.DIGEST, self.CIPHERMODE]
        if not all([a for a in required]):
            print("ERROR! The client can't be run without having been started first!")
            return

        # 2. Get a list of media files
        print("Contacting Server")
        req = requests.get(f'{SERVER_URL}/api/list')
        if req.status_code == 200:
            print("Got Server List")
        
        print(req.headers)
        media_list = self.processResponse(req)
        if not media_list:
            return
        print(media_list)
        
        # 3. Present a simple selection menu    
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

            # Make request until gets a valid answer (max 5 times)
            for i in range(0,5):
                req = requests.get(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
                
                chunk = self.processResponse(req, bytes(chunk))
                if chunk:
                    break

            # TODO: Process chunk

            data = binascii.a2b_base64(chunk['data'].encode('latin'))
            try:
                proc.stdin.write(data)
            except:
                break

    # Secrecy

    # Cipher
    def cipher(self, jsonobj):
        """
        This method ciphers a request payload
        It also generates a MIC for the cryptogram
        --- Parameters
        jsonobj         A JSON parsable python object to encode
        --- Returns
        cryptogram      
        MIC 
        """
        message = json.dumps(jsonobj).encode()
        print("JSON to STR", message)

        cryptogram = CryptoFunctions.symetric_encryption(
            key = self.shared_key,
            message = message,
            algorithm_name = self.CIPHER,
            cypher_mode = self.CIPHERMODE,
            digest_mode = self.DIGEST,
            encode = True
        )

        MIC = CryptoFunctions.create_digest(cryptogram, self.DIGEST).strip()
        print("Generated MIC:\n",MIC)

        return cryptogram, MIC
    
    # Response
    def processResponse(self, request, append=None, ciphered=True):
        """
        Processes a request response
        Validates the MIC sent on the header 
        --- Parameters
        request     
        append      Bytes to append to shared_key before decyphering
        ciphered    If response must be ciphered!
        --- Returns
        payload     The payload (Python obj) of the request deciphered (if the case) and validated (the MIC)
        """
        if not request.content: return None
        print("\n# Deciphering request...\n", request.content.strip())
        print("\nHeaders:\n", request.headers)
        # Check if response is ciphered
        if 'ciphered' not in request.headers.keys() or request.headers['ciphered'] == 'False':
            print("\nIt is not ciphered!")
            if ciphered:
                print("\nERROR! Response is not ciphered, but should be!")
                return None
        elif not ciphered:
            print("\nExpecting not ciphered response, but it is ciphered!")
            return None
        # Validate MIC
        if ciphered:
            print("\nGot MIC...\n", request.headers['Mic'].encode('latin'))
            MIC = CryptoFunctions.create_digest(request.content.strip(), self.DIGEST)
            print("\nMIC computed...\n", MIC)
            if MIC != request.headers['Mic'].encode('latin'):
                print("INVALID MIC!")
                return None
            else:
                print("Validated MIC!")
        else:
            print("\nIgnoring MIC for now...")
            # print("\nGot MIC (hash)...\n", request.headers['Mic'])
            # MIC = str(request.content.strip()).__hash__()
        # Check if response is ciphered
        if not ciphered:
            print("\nResponse is not ciphered!")
            message = request.content
        else:
            message = CryptoFunctions.symetric_encryption( 
                key = self.shared_key if not append else self.shared_key + append, 
                message = request.content, 
                algorithm_name = self.CIPHER, 
                cypher_mode = self.CIPHERMODE, 
                digest_mode = self.DIGEST, 
                encode = False 
            ) 
        # Convert message bytes to str and to Python Object
        return json.loads(message.decode()) 

    def responseError(self, request, data):
        """
        This method shows the error details of an error response
        --- Parameters
        request
        data        The response payload
        """
        if not data:
            message = "Got an empty response!"
        elif 'error' in data:
            message = data['error']
        else:
            message = f"Invalid response: {str(data)}"
        print(f"\nERROR! Received response with code {request.status_code}: {message}")
        

        


    
c = MediaClient(SERVER_URL)
c.start()

while True:
    c.run()
    time.sleep(1)