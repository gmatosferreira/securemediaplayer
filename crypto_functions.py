import requests
import logging
from cryptography.hazmat.primitives import hashes

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
       
    """
def digest(message, digst_algorithm):
    hash_algorithm = None
    
    if digst_algorithm == "SHA512":
        hash_algorithm = hashes.SHA512()
    elif digst_algorithm == "BLAKE2":
        hash_algorithm = hashes.BLAKE2b(64)
    else:
        print("Digest Algorithm name not found! ")
    
    digest = hashes.Hash(hash_algorithm)

    digest.update(message)
    return digest.finalize()
    
    
        

    