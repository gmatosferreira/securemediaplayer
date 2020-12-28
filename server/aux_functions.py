
import json

import sys
sys.path.append('..')
from crypto_functions import CryptoFunctions

import datetime

LICENSE_VIEWS = 3
LICENSE_SPAN = datetime.timedelta(minutes=5)

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
        'views': LICENSE_VIEWS,
        'time': (datetime.datetime.now() + LICENSE_SPAN).timestamp()
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

def licenseValid(license):
    """
    Given a license, this method tells if it is valid
    """    
    # Validate attributes
    if not all(attr in license and license[attr] for attr in ['views', 'time']):
        return False
    # Check that license has not expired yet
    t = datetime.datetime.utcfromtimestamp(license['time'])
    if t < datetime.datetime.now():
        return False
    # Check that number of views is greater that zero
    if license['views'] <= 0:
        return False
    # If passed validations, license is valid!
    return True
    
def updateLicense(username, renew = False, view = False):
    """
    This method updates a user license
    --- Parameters 
    renew           If wants to renew license
    view            If wants to decrement views
    --- Returns 
    userData        The object with user info at licenses.json
    """
    print("\nRENEW LICENSE")
    if not username: return None

    # Load users
    users = json.load(open('../licenses.json', 'r'))

    # Find user on file
    user = None
    userindex = 0
    for u in users:
        if u['username'] == username:
            user = u
            break
        userindex += 1

    if not user: return None

    # Renew license
    if renew:
        user['views'] = LICENSE_VIEWS
        user['time'] = (datetime.datetime.now() + LICENSE_SPAN).timestamp()
    elif view:
        user['views'] = user['views'] - 1
    
    # Update users list (and file)
    users[userindex] = user
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