import requests
import logging

import sys
sys.path.append('..')
from crypto_functions import CryptoFunctions

# Serialization
from cryptography.hazmat.primitives import serialization

def ask_server_parameters(server_url):

    # 1. Get the server parameters
    req = requests.get(f'{server_url}/api/parameters')

    if req.status_code != 200:
        print("The server is not available!")
        exit()

    parameters_bytes = bytes(req.json()['parameters'], 'utf-8')
    print("\nGot serialized parameters!\n", parameters_bytes)
    
    parameters = serialization.load_pem_parameters(parameters_bytes)    
    return parameters

"""
This method asks the server for the available protocols
and lets the user define the protocols to use.
It returns the cipher suite.
"""
def client_chosen_options(server_url):
    # Ask server for available protocols
    req = requests.get(f'{server_url}/api/protocols')    
    
    if req.status_code == 200:
        print("Got Protocols!")
    else:
        print("The server is not available!")
        exit()
   
    protocols = req.json()
    print(protocols)

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
            digest = protocols['digests'][op-1]
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
This method negociates the encription keys to use 
in the communications with the server.
--- Parameteres
server_url          The server base url
private_key         The client private key
public_key          The client public key
--- Returns
shared_key          The client shared key
"""
def diffieHellman(server_url, private_key, public_key):
    
    # 1. Exchange public key with the server
    pk = public_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("\nSerialized public key to send server!\n", pk)
    # 1.1. Send the client public key to the server
    req = requests.post(f'{server_url}/api/publickey', data={
        'public_key': pk.decode('utf-8'),
    })

    if req.status_code != 200:
        print("The server is not available!")
        exit()

    # 1.2. Get the server public key as an answer to the POST request
    server_public_key_bytes = bytes(req.json()['public_key'], 'utf-8')
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    print("\nGot the server public key!\n", server_public_key)

    # 2. Generate the shared key based on the server public key
    shared_key = private_key.exchange(server_public_key)

    return shared_key
