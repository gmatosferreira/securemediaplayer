
import json

import sys
sys.path.append('..')
from crypto_functions import CryptoFunctions

def register(username, password):
    """
    This function handles the registration of a new user at server
    It gives the user a default license of 5 views
    --- Parameters
    username        String
    password        String (digest)
    --- Returns
    userData        The object with user info at licenses.json
    """
    print("\nREGISTER")
    if not username or not password: return None

    # Load users
    users = json.load(open('../licenses.json', 'r'))

    # Check that user is not registered yet
    for u in users:
        if u['username'] == username:
            print("ERROR! User already exists!")
            return None

    # Create user
    user = {
        'username': username,
        'passwords': {},
        'views': 5,
        'time': 0 
    }

    # Create digests for password
    for digest in CryptoFunctions.digests:
        user['passwords'][digest] = CryptoFunctions.create_digest(password.encode('latin'), digest).decode('latin')

    print("Created user\n", user)

    # Add user to users list
    users.append(user)

    # Update file
    json.dump(users, open('../licenses.json', 'w'))

    return user
    

def authenticate(username, password, sessionData):
    """
    This function authenticates a user given its password
    --- Parameters
    username        String
    password        String (digest)
    sessionData     The session data
    --- Returns
    userData        The object with user info at licenses.json
    """
    print("\nAUTHENTICATE")
    # Load users
    users = json.load(open('../licenses.json', 'r'))
    
    # Find user object
    for u in users:
        if u['username'] == username:
            print("Found user!")

            print("Expected password is", u['passwords'][sessionData['digest']].encode('latin'), f"({len(u['passwords'][sessionData['digest']].encode('latin'))})")
            print("Got", password.encode('latin'), f"({len(password.encode('latin'))})")
            
            if u['passwords'][sessionData['digest']] == password:
                print("Password is valid! :)")
                return u
            else:
                print("Password is not valid! :/")
                return None

    # If not found, return None
    print("User not found...")
    return None