import requests
import logging
import binascii
import json
import os
import subprocess
import time
import sys

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.INFO)

SERVER_URL = 'http://127.0.0.1:8080'

def client_chosen_options():
    req = requests.get(f'{SERVER_URL}/api/protocols')    
    
    if req.status_code == 200:
        print("Got Protocols!")
   
    protocols = req.json()
    
    print(protocols)
    

    while True:
        print("Choose a cipher algorithm ")
        i=1
        for cipher in protocols['cipher']:
            print(i, ") ",cipher)
            i+=1
        cipher_option = input()
        if cipher_option == 1:
            cipher = 'AES'
            break
        elif cipher_option==2:
            cipher = '3DES'
            break
    
    while True:
        print("Choose a digest ")
        i=1
        for digest in protocols['digests']:
            print(i, ") ",digest)
            i+=1
        digest_option = input()
        if digest_option == 1:
            cipher = 'SHA512'
            break
        elif digest_option==2:
            cipher = 'BLAKE2'
            break
    while True: 
        print("Choose a cipher mode")
        i=1
        for mode in protocols['modes']:
            print(i, ") ",mode)
            i+=1
        cipher_mode_op = input()
        if cipher_mode_op == 1:
            cipher = 'CBC'
            break
        elif cipher_mode_op==2:
            cipher = 'OFB'
            break
        

    
    inputs_list = {'cipher': cipher, 'digest': digest, 'cipher_mode':cipher_mode}
    """
    req = requests.post(f'{SERVER_URL}/api/download?id={media_item["id"]}&chunk={chunk}')
    chunk = req.json()
    """
    
    
def main():
    print("|--------------------------------------|")
    print("|         SECURE MEDIA CLIENT          |")
    print("|--------------------------------------|\n")

    # Get a list of media files
    print("Contacting Server")
    
    # TODO: Secure the session
    
    
    #DÁ ERRO AO FAZER UM SIMPLES POST E N SEI PQ ...
    client_chosen_options()


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