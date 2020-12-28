import requests
import logging

import sys
sys.path.append('..')
from crypto_functions import CryptoFunctions
import uuid

# Serialization
from cryptography.hazmat.primitives import serialization

"""
This method lets the user define the protocols to use.
It returns the cipher suite.
"""
def client_chosen_options(protocols):
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
def user_logout(self):
    requests.post(f'{self.SERVER_URL}/api/update_license', data = {"username": self.username})
"""