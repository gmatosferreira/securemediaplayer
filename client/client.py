import requests
import logging
import binascii
import json
import os
import signal
import subprocess
import time
import base64
from datetime import datetime

import sys
from aux_functions import *
from cc import CitizenCard

# Serialization
from cryptography.hazmat.primitives import serialization

# Diffie-hellman
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import sys
sys.path.append('..')

from pki import PKI
from crypto_functions import CryptoFunctions
logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'
FILEPRIVATEKEY = '../keys/client_localhost.pem'
FILECERTIFICATE = '../certificates/client_localhost.crt'
MAXDOWNLOADERRORS = 20

class MediaClient:

    # Constructor
    def __init__(self, SERVER_URL):
        print("|--------------------------------------|")
        print("|         SECURE MEDIA CLIENT          |")
        print("|--------------------------------------|\n")

        self.SERVER_URL = SERVER_URL
        print("Initializing client...")

        # Initialize pki
        self.pki = PKI()

        # Load private key
        fp = open(FILEPRIVATEKEY, 'rb')
        self.cert_private_key = serialization.load_pem_private_key(
            fp.read(),
            password = None
        )
        fp.close()
        print("\nLoaded certificate private key...\n", self.cert_private_key)

        # Load certificate
        fc = open(FILECERTIFICATE, "rb")
        self.cert = PKI.getCertFromString(fc.read(), pem=True)
        fc.close()
        print("\nLoaded certificate...\n", self.cert)

        # 1. Get DH parameters from server 
        req = requests.get(f'{self.SERVER_URL}/api/parameters')
        data = self.processResponse(
            request = req,
            ciphered = False
        )
        if req.status_code != 200:
            self.responseError(req, data)
            exit()
        elif not data:
            print("Couldn't get parameters from server... :/")
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
        self.logged = False
        self.downloadErrors = 0

    
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
        req = requests.post(f'{self.SERVER_URL}/api/session', data=data)
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

    def run(self):
        # 1. Validate that client has already been started
        required = [self.shared_key, self.CIPHER, self.DIGEST, self.CIPHERMODE]
        if not all([a for a in required]):
            print("ERROR! The client can't be run without having been started first!")
            return
        
        # 2. Show menu
        print("|--------------------------------------|")
        print("|       SECURE MEDIA CLIENT MENU       |")
        print("|                                      |")
        if not self.logged:
            print("| 1. Login                             |")
            print("| 2. Register                          |")
        else:
            print("| 1. Log out                           |")
        print("| 3. Play media                        |")
        print("| 4. Look up license                   |")
        print("| 5. Renew license                     |")
        print("| 6. Exit                              |")
        print("|--------------------------------------|\n")

        op = input("What is your option? ").strip()
        if not op.isdigit():
            print("Invalid option")
            return
        op = int(op)

        if op == 1:
            if not self.logged:
                print("\nAUTHENTICATION")
                self.auth()
            else:
                print("\nLOG OUT")
                self.logout()
        elif op == 2:
            print("\nREGISTER")
            self.auth(registration=True)
        elif op == 3:
            print("\nPLAY")
            self.play()
        elif op == 4:
            print("\nLICENSE")
            self.license()
        elif op == 5:
            print("\nRENEW LICENSE")
            self.renew()
        elif op == 6:
            print("\nEXIT")
            print("Closing session...")
            if self.closeSession():
                print("Session has been closed! Bye ;)")
                exit()
            else:
                print("An error occured... Try again!")
        else:
            print("Invalid option!")

    def auth(self, registration = False):
        """
        This method handles the client authentication (or registration) at server
        """
        cc = CitizenCard() 
        
        url = f'{self.SERVER_URL}/api/auth' if not registration else f'{self.SERVER_URL}/api/newuser'
        while True:
            username = input("Username (ENTER to exit): ").strip()
            if not username: break
            if len(username.split(" "))!=1:
                print("Username must be a single word! Spaces are not supported!")
                continue
            password = input("Password (ENTER to exit): ").strip()
            if not password: break
            # Create digest for password
            if not registration:
                passwordDigest = CryptoFunctions.create_digest(password.encode('latin'), self.DIGEST).decode('latin')
            else:
                passwordDigest = password
            print("Password digest: ", passwordDigest)
            # Sign username+password
            signature = cc.sign((username+passwordDigest).encode('latin')).decode('latin')
            print("\nSigned username+password:", signature)
            # Create payload
            payload = {"username": username, "password": passwordDigest, "signature": signature}
            # On registration, send signature certificate
            if registration:
                payload['signcert'] = cc.cert.public_bytes(serialization.Encoding.DER).decode('latin')
                payload['intermedium'] = [c.public_bytes(serialization.Encoding.DER).decode('latin') for c in cc.intermedium]
                print("\nEncoded CC public key...\n", payload['signcert'])
            data, headers  = self.cipher(payload)
            # POST to server
            req = requests.post(url, data = data, headers = headers)
            # Process server response
            reqResp = self.processResponse(request = req)
            if req.status_code != 200:
                self.responseError(req, reqResp)
            elif not registration:
                self.logged = True
                print(f"\nSUCCESS: {reqResp['success'] if reqResp else ''}")
                self.showLicense(reqResp)
                break
            else:
                print(f"\nSUCCESS: {reqResp['success'] if reqResp else ''}")
                self.showLicense(reqResp)
                break

    def play(self):
        """
        This method is used to play the media content from the server
        """
        # 1. Get a list of media files
        print("Contacting Server...")
        req = requests.get(f'{SERVER_URL}/api/list', headers = {'sessionid': base64.b64encode(self.sessionid.bytes)})
        reqResp = self.processResponse(req)
        if req.status_code != 200:
            self.responseError(req, reqResp)
            return
        
        media_list = reqResp
        if not media_list:
            return
        print("Got media list", media_list)
        
        # 2. Present a simple selection menu    
        idx = 0
        print("MEDIA CATALOG\n")
        for item in media_list:
            print(f'{idx} - {media_list[idx]["name"]}')
        print("----")

        while True:
            selection = input("Select a media file number (q to quit): ")
            if selection.strip() == 'q':
                return

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
                data, headers  = self.cipher({"media": media_item["id"], "chunk": chunk})
                # POST to server
                req = requests.post(f'{self.SERVER_URL}/api/download', data = data, headers = headers)
                media = self.processResponse(req, bytes(chunk))

                if req.status_code != 200:
                    self.responseError(req, media)
                    continue

                if media:
                    break

            if not media or 'error' in media:
                print("\nGot empty or invalid chunk!!")
                self.downloadErrors += 1
                if self.downloadErrors > MAXDOWNLOADERRORS:
                    print("\nReached max download errors, aborting media play...")
                    # Kill reproducer window
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    break
                continue

            data = binascii.a2b_base64(media['data'].encode('latin'))
            try:
                proc.stdin.write(data)
            except:
                break

    def logout(self):
        """
        This method handles the client log out at server
        """
        data, headers  = self.cipher({"logout": True})
        # POST to server
        req = requests.post(f'{self.SERVER_URL}/api/auth', data = data, headers = headers)
        # Process server response
        reqResp = self.processResponse(request = req)
        if req.status_code != 200:
            self.responseError(req, reqResp)
        else:
            self.logged = False
            print(f"\nSUCCESS: {reqResp['success'] if reqResp else ''}")

    def license(self):
        """
        This method allows the client to look up his license status
        """
        req = requests.get(f'{SERVER_URL}/api/license', headers = {'sessionid': base64.b64encode(self.sessionid.bytes)})
        reqResp = self.processResponse(req)
        if req.status_code != 200:
            self.responseError(req, reqResp)
            return

        self.showLicense(reqResp)


    def renew(self):
        """
        This method allows the client to renew his certificate with the server
        """
        data, headers  = self.cipher({"renew": True})
        # POST to server
        req = requests.post(f'{self.SERVER_URL}/api/renew', data = data, headers = headers)
        # Process server response
        reqResp = self.processResponse(request = req)
        if req.status_code != 200:
            self.responseError(req, reqResp)
        else:
            print(f"\nSUCCESS: {reqResp['success'] if reqResp else ''}")
            self.showLicense(reqResp)


    def closeSession(self):
        """
        This method is resposible for closing session with server
        --- Returns
        success         Boolean
        """
        data, headers  = self.cipher({"close": True})
        # POST to server
        req = requests.post(f'{self.SERVER_URL}/api/sessionend', data = data, headers = headers)
        # Process server response
        reqResp = self.processResponse(request = req)
        if req.status_code != 200:
            self.responseError(req, reqResp)
            return False
        
        print(f"\nSUCCESS: {reqResp['success'] if reqResp else ''}")
        return True

    # Auxiliar functions
    def showLicense(self, payload):
        """
        This function shows the license information, given a dictionary
        It must have the attrs 'views' and 'time'
        """
        # Validate that required attrs are given
        if not payload or not all(attr in payload for attr in ['views', 'time']):
            return

        t = datetime.utcfromtimestamp(payload['time'])
        print("\n---- LICENSE ----")
        print(f"Views: {payload['views']-1}")
        print(f"Until: {t}")
        if t < datetime.now() or payload['views']-1 <= 0:
            print("EXPIRED!")
        print("-----------------\n")


    # Secrecy

    # Cipher
    def cipher(self, jsonobj):
        """
        This method ciphers a request payload
        It also generates a MIC for the cryptogram
        --- Parameters
        jsonobj         A JSON parsable python object to encode
        --- Returns
        cryptogram      bytes
        headers         dict() with validation headers (MIC, MAC, SIGN, session info and cert)
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
        MAC = CryptoFunctions.create_digest(cryptogram+self.shared_key, self.DIGEST).strip()
        print("\nGenerated MAC:\n", MAC)
        
        SIGN = CryptoFunctions.signingRSA(cryptogram, self.cert_private_key)
        print("\nGenerated SIGN:\n", SIGN)
        print("\nContent signed:\n", cryptogram)

        headers = {
            'mic': base64.b64encode(MIC), 
            'mac': base64.b64encode(MAC), 
            'signature': base64.b64encode(SIGN), 
            'cert': base64.b64encode(self.cert.public_bytes(encoding = serialization.Encoding.PEM)), 
            'sessionid': base64.b64encode(self.sessionid.bytes)
        }

        return cryptogram, headers
    
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
            MIC = CryptoFunctions.create_digest(request.content.strip(), self.DIGEST)
            if MIC != base64.b64decode(request.headers['Mic']):
                print("INVALID MIC!")
                return None
            else:
                print("Validated MIC!")
            
            MAC = CryptoFunctions.create_digest(request.content.strip() + self.shared_key, self.DIGEST)
            if MAC != base64.b64decode(request.headers['Mac']):
                print("INVALID MAC!")
                return None
            else:
                print("Validated MAC!")
        else:
            print("\nIgnoring MIC for now...")
            # print("\nGot MIC (hash)...\n", request.headers['Mic'])
            # MIC = str(request.content.strip()).__hash__()
        
        # Validate certificate
        cert = base64.b64decode(request.headers['Certificate']).decode('latin')
        if not self.pki.validateCerts(cert, [], pem=True):
            print("\nERROR! The server certificate is not valid!")
            return None
        else:
            print("\nThe server certificate is valid!")
        
        # Validate signature!
        cert = self.pki.getCertFromString(cert, pem=True) 
        sign = base64.b64decode(request.headers['Signature']) 
        print("\nGot signature...\n", sign) 
        if not CryptoFunctions.validacaoAssinatura_RSA(sign, request.content, cert.public_key()): 
            print("\nERROR! The server signature is not valid!") 
            return None 
        else: 
            print("\nThe server signature is valid! :)") 

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
        try:
            return json.loads(message.decode()) 
        except:
            return None

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