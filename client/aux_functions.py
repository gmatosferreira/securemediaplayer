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
def client_chosen_options(suites):
    """
    Given a list of suites, returns the chipher suite choosen
    """
    # Print available suites
    print("\nThe available cipher suites are...")
    print(f"\n{'Number':10}  {'Cipher alg':30}  {'Cipher mode':30}  {'Digest':30}")
    counter = 0
    for s in suites:
        s = s.split(" / ")
        print(f"{counter:<10}  {s[0]:30}  {s[1]:30}  {s[2]:30}")
        counter += 1
    
    # Let user choose  
    while True:
        print("\nWhat suite do you choose? ", end="")
        op = input()
        if op.isdigit():
            op = int(op)
            if op >= 0 and op < len(suites):
                suite = suites[op]
                break
        print("That is not a valid option! Try again!")

    suite = suite.split(" / ")
    cipherSuite = {'cipher': suite[0], 'cipher_mode':suite[1], 'digest': suite[2]}
    return cipherSuite
        
"""
def user_logout(self):
    requests.post(f'{self.SERVER_URL}/api/update_license', data = {"username": self.username})
"""