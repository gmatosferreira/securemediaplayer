
import json
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization

import sys
sys.path.append('..')
from crypto_functions import CryptoFunctions
from pki import PKI 
from cc import CitizenCard

LICENSE_VIEWS = 4
LICENSE_SPAN = datetime.timedelta(minutes=5)

def register(server, username, password, signature, signcert, intermedium):
    """
    This function handles the registration of a new user at server
    It gives the user a default license of 5 views
    --- Parameters
    server          MediaServer     The server that calls the method
    username        String          The user username
    password        String          The raw password
    signature       String          The username+password signature
    signcert        String          Certificate used to generate signature
    intermedium     String[]        List of intermedium certs
    --- Returns
    userData        dict()          The object with user info at licenses.json
    errorMessage    String          A message describing the error
    """
    print("\nREGISTER")
    if not username or not password: return None, "There are attributes missing!"

    # Load users
    usersfile = server.getFile('./licenses.json')
    if not usersfile:
        users = []
    else:
        users = json.loads(usersfile)
        print("Got users", [u['username'] for u in users])

    # Check that user is not registered yet
    for u in users:
        if u['username'] == username:
            print("ERROR! User already exists!")
            return None, "The username given is already being used! Please choose other."

    # Validate certificate
    print("\nVALIDATING SIGNATURE CERTIFICATE...")
    pki = PKI(signcert, intermedium)
    if not pki.validateCerts():
        print("ERROR! The signature certificate is not valid!")
        return None, "The signature certificate is not valid!"
    else:
        print("It is valid! :)")

    # Validate signature
    valid = CitizenCard.validateSignature(
        public_key = pki.cert.public_key(), 
        message = (username+password).encode('latin'),
        sign = signature.encode('latin')
    )
    print("\nValidating signature...", valid)
    if not valid:
        return None, "The signature is not valid!"

    # Create user
    user = {
        'username': username,
        'passwords': {},
        'views': LICENSE_VIEWS,
        'time': (datetime.datetime.now() + LICENSE_SPAN).timestamp(),
        'cert': pki.cert.public_bytes(serialization.Encoding.DER).decode('latin')
    }

    # Create digests for password
    for digest in CryptoFunctions.digests:
        user['passwords'][digest] = CryptoFunctions.create_digest(password.encode('latin'), digest).decode('latin')

    print("Created user\n", user)

    # Add user to users list
    users.append(user)

    # Update file
    server.updateFile('./licenses.json', json.dumps(users))

    return user, ""

def getLicense(server, username):
    """
    This method returns a license for a user given his username
    - Parameters
    server          MediaServer     The server that calls the method
    """
    # Load users
    usersfile = server.getFile('./licenses.json')
    if not usersfile:
        users = []
    else:
        users = json.loads(usersfile)

    # Find user on file
    for u in users:
        if u['username'] == username:
            return u

    return None

def licenseValid(server, username):
    """
    Given a license, this method tells if it is valid
    """    
    license = getLicense(server, username)

    # Validate attributes
    if not license or not all(attr in license and license[attr] for attr in ['views', 'time']):
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
    
def updateLicense(server, username, renew = False, view = False):
    """
    This method updates a user license
    --- Parameters 
    server          MediaServer     The server that calls the method
    renew           If wants to renew license
    view            If wants to decrement views
    --- Returns 
    userData        The object with user info at licenses.json
    """
    print("\nRENEW LICENSE")
    if not username: return None

    # Load users
    usersfile = server.getFile('./licenses.json')
    if not usersfile:
        users = []
    else:
        users = json.loads(usersfile)

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
    server.updateFile('./licenses.json', json.dumps(users))

    return user

def authenticate(server, username, password, signature, sessionData):
    """
    This function authenticates a user given its password
    --- Parameters
    server          MediaServer     The server that calls the method
    username        String
    password        String (digest)
    signature       String          The username+password signature
    sessionData     The session data
    --- Returns
    userData        The object with user info at licenses.json
    error           The error message
    """
    print("\nAUTHENTICATE")
    # Load users
    usersfile = server.getFile('./licenses.json')
    if not usersfile:
        users = []
    else:
        users = json.loads(usersfile)
    
    # Find user object
    for u in users:
        if u['username'] == username:
            print("Found user!")

            # Validate signature with user stored certificate 
            cert = x509.load_der_x509_certificate(u['cert'].encode('latin'))
            valid = CitizenCard.validateSignature(
                public_key = cert.public_key(), 
                message = (username+password).encode('latin'),
                sign = signature.encode('latin')
            )
            print("\nValidating signature...", valid)
            if not valid:
                return None, "The signature is not valid!"
                
            # Check password
            print("Expected password is", u['passwords'][sessionData['digest']].encode('latin'), f"({len(u['passwords'][sessionData['digest']].encode('latin'))})")
            print("Got", password.encode('latin'), f"({len(password.encode('latin'))})")
            
            if u['passwords'][sessionData['digest']] == password:
                print("Password is valid! :)")
                return u, ""
            else:
                print("Password is not valid! :/")
                return None, ""

    # If not found, return None
    print("User not found...")
    return None