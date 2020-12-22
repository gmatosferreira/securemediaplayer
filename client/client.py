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

# Client variables
PARAMETERS = None
PRIVKEY = None
PUBLICKEY = None
CIPHER = None
DIGEST = None
CIPHERMODE = None

    
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Define the client private and public keys
    print("Initializing client...")
    # Create the private/public keys pais
    PARAMETERS = ask_server_parameters(SERVER_URL)
    print("\nGot parameters\n", PARAMETERS)

    PRIVKEY, PUBLICKEY = CryptoFunctions.newKeys(PARAMETERS)

    print("\nPrivate key created!\n", PRIVKEY)
    print(PRIVKEY.private_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    ))
    print("\nPublic key generated!\n", PUBLICKEY)
    print(PUBLICKEY.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    ))

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session
    #isto é.. concorrênia?
    
    
    # 1. Let user choose chipher suite
    cipherSuite = client_chosen_options(SERVER_URL)
    CIPHER, DIGEST, CIPHERMODE = cipherSuite['cipher'], cipherSuite['digest'], cipherSuite['cipher_mode']
    requests.post(f'{SERVER_URL}/api/suite', data = cipherSuite)
    print(f"\nCipher suite defined!\nCipher: {CIPHER}; DIGEST: {DIGEST}; CIPHERMODE: {CIPHERMODE}")

    # 2. Negociate encription keys (Diffie-Hellman)
    diffieHellman(SERVER_URL, PRIVKEY, PUBLICKEY)

    req = requests.get(f'{SERVER_URL}/api/list')
    if req.status_code == 200:
        print("Got Server List")
    
    media_list = req.json()
    print(media_list)
    
    # Present a simple selection menu    
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
        chunk = req.json()
       
        # TODO: Process chunk

        data = binascii.a2b_base64(chunk['data'].encode('latin'))
        try:
            proc.stdin.write(data)
        except:
            break
    
if __name__ == '__main__':
    while True:
        main()
        time.sleep(1)