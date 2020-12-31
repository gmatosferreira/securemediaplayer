#!/usr/bin/env python
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import uuid
import base64
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
from pki import PKI

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 10,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce_cut10_e.mp3',
                'file_size': 160958
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4  #block
FILEPRIVATEKEY = '../keys/server_localhost.pem'
FILECERTIFICATE = '../certificates/server_localhost.crt'

# Load server key
with open('key.txt') as f:
    KEY = f.read().strip()
print("\nWorking with key:", KEY)

class MediaServer(resource.Resource):
    isLeaf = True

    # Constructor
    def __init__(self):
        print("\nInitializing server...")

        # Load parameters
        with open('parameters', 'rb') as f:
            self.parameters = serialization.load_pem_parameters(f.read().strip())    
            print("Loaded parameters!")

        # Load media files
        self.MEDIA = dict()
        print("\nLoading media...")
        for _, c in CATALOG.items():
            print(c['file_name'])
            self.MEDIA[c['file_name']] = self.getFile(os.path.join(CATALOG_BASE, c['file_name'])).encode('latin')

        # Load private key
        fp = open(FILEPRIVATEKEY, 'rb')
        self.private_key = serialization.load_pem_private_key(
            fp.read(),
            password = None
        )
        fp.close()
        print("\nLoaded private key...\n", self.private_key)

        # Load certificate
        fc = open(FILECERTIFICATE, "rb")
        self.cert = PKI.getCertFromString(fc.read(), pem=True)
        fc.close()
        print("\nLoaded certificate...\n", self.cert)

        # Initialize session dictionary
        self.sessions = {}

        # Initialize pki
        self.pki = PKI()

        print("\nServer has been started!")

    # Send the server DH parameters
    def do_parameters(self, request):
        # Validate client certificate
        if not self.processRequestCertificate(request):
            return self.rawResponse(
                request = request,
                response = {'error': 'The client certificate is not valid!'}
            )
        # Convert parameters to bytes
        pr = self.parameters.parameter_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.ParameterFormat.PKCS3
        )
        print("\nSerialized parameters as bytes to answer request!\n", pr)
        # Return it
        return self.rawResponse(
            request = request,
            response = {'parameters': pr.decode('utf-8')}
        )

    # Send the list of available protocols
    def do_choose_protocols(self, request):
        # Validate client certificate
        if not self.processRequestCertificate(request):
            return self.rawResponse(
                request = request,
                response = {'error': 'The client certificate is not valid!'}
            )
        # Return protocols available
        return self.rawResponse(
            request = request,
            response = CryptoFunctions.suites
        )


    # Send the list of media files to clients
    def do_list(self, request):
        # Validate client certificate
        if not self.processRequestCertificate(request):
            return self.rawResponse(
                request = request,
                response = {'error': 'The client certificate is not valid!'}
            )
        
        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        # Validate license
        if not licenseValid(self, session['username']):
            return self.cipherResponse(
                request = request,
                response = {'error': 'License is not valid! Please renew it.'},
                sessioninfo = session,
                error = True
            )

        # Build list
        media_list = []
        for media_id in CATALOG:
            media = CATALOG[media_id]
            media_list.append({
                'id': media_id,
                'name': media['name'],
                'description': media['description'],
                'chunks': math.ceil(media['file_size'] / CHUNK_SIZE),
                'duration': media['duration']
            })

        # Return list to client
        return self.cipherResponse(
            request = request, 
            response = media_list,
            sessioninfo = session
        )

    def do_license(self, request):
        """
        This method allows the client to look up his license status
        """
        # Validate client certificate
        if not self.processRequestCertificate(request):
            return self.rawResponse(
                request = request,
                response = {'error': 'The client certificate is not valid!'}
            )

        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        license = getLicense(self, session['username'])
        return self.cipherResponse(
            request = request, 
            response = {
                'success': 'Here is your license! :)',
                'views': license['views'],
                'time': license['time'],
            }, 
            sessioninfo = session
        )

    # Handle a GET request
    def render_GET(self, request):
        logger.debug(f'\nReceived request for {request.uri}')

        try:
            if request.path == b'/api/parameters':
                return self.do_parameters(request)
            elif request.path == b'/api/protocols':
                return self.do_choose_protocols(request)
            #elif request.uri == 'api/key':
            #...
            #elif request.uri == 'api/auth':
            elif request.path == b'/api/list':
                return self.do_list(request)
            elif request.path == b'/api/license':
                return self.do_license(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
        
    """
    This method allows the client to start a new session at the server 
    --- Start
    The client sends his public key
    The server generates a key pair for that client and a shared key based on those
    It also generates a session id for client
    Answers to client the server public key and the session id
    """
    def do_session(self, request):
        data = request.args
        if data == None or data == '':
            print('Data is none or empty')
            return 
        print(request.args) 

        # 1.1. Get the client public key
        print("\nClient public key raw.\n", request.args[b'public_key'][0])
        client_public_key = serialization.load_pem_public_key(request.args[b'public_key'][0])
        print("\nGot the client public key!\n", client_public_key)

        # 1.2. Get the client cipher suite
        CIPHER = request.args[b'cipher'][0].decode('utf-8')
        DIGEST = request.args[b'digest'][0].decode('utf-8')
        CIPHER_MODE = request.args[b'cipher_mode'][0].decode('utf-8')
        print("\nGot client cipher suite!")
        print("Cipher:", CIPHER)
        print("Digest:", DIGEST)
        print("Mode:", CIPHER_MODE)

        # 2. Generate a session id for client
        sessionid = uuid.uuid1()
        print("\nGenerated session id for client:", sessionid)

        # 3. Generate key pair for client
        private_key, public_key = CryptoFunctions.newKeys(self.parameters)
        print("\nPrivate key created!\n", private_key)
        print(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))
        print("\nPublic key generated!\n", public_key)
        print(public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # 4. Diffie-Hellman | Generate shared key
        shared_key = private_key.exchange(client_public_key)
        print("\nGenerated the shared key for client!\n", shared_key)

        # 5. Convert public key to bytes
        pk = public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("\nSerialized public key to answer request!\n", pk)

        # 6. Register client session
        self.sessions[sessionid] = {
            'public_key': public_key,
            'private_key': private_key,
            'shared_key': shared_key,
            'cipher': CIPHER,
            'digest': DIGEST,
            'mode': CIPHER_MODE,
            'authenticated': False,
            'data': None 
        }

        # 7. Return public key to client
        request.responseHeaders.addRawHeader(b"sessionid", sessionid.bytes)
        return self.rawResponse(
            request = request,
            response = {'public_key': pk.decode('utf-8')}
        )

    
    """
    This method handles the client authentication (log in and log out)
    To authenticate, the client must have started a session!
    """
    def do_auth(self, request, registration = False):
        # Get data from request header
        if not registration:
            print("\n\nAUTHENTICATION")
        else:
            print("\n\nREGISTRATION")

        # Process request 
        # (Get session and decipher payload)
        session, data = self.processRequest(request)

        # Validate that client has open session
        if not session:
            return self.rawResponse(
                request = request,
                response = {'error': 'Client does not have a valid session!'},
                error = True
            )

        # If logout, log user out, 
        if 'logout' in data and data['logout']:
            print("\nLOG OUT")
            session['authenticated'] = False
            return self.cipherResponse(
                request = request, 
                response = {
                    'success': 'The user has been sucessfully logged out!'
                }, 
                sessioninfo = session,
            )

        # Validate that payload has data
        invalid = not data
        invalid = invalid or not all(attr in data and data[attr] for attr in ['username', 'password', 'signature'])
        invalid = invalid or (registration and not all(attr in data and data[attr] for attr in ['signcert', 'intermedium']))
        if invalid:
            return self.cipherResponse(
                request = request, 
                response = {'error': 'Payload is not valid!'}, 
                sessioninfo = session,
                error = True
            )
        
        # Check that user is already logged on authentication
        if not registration and session['authenticated']:
            return self.cipherResponse(
                request = request, 
                response = {
                    'success': 'The user is already logged!',
                }, 
                sessioninfo = session,
            )
            
        print("\nData received is...\n", data)
        # Validate data
        if not registration:
            userData, error = authenticate(self, data['username'], data['password'], data['signature'], session)
        else:
            userData, error = register(self, data['username'], data['password'], data['signature'], data['signcert'], data['intermedium'])
        # If authenticated/registered sucessfully
        if userData:
            if not registration:
                session['authenticated'] = True
                session['username'] = userData['username']
                message = 'The user was authenticated sucessfully!'
            else:
                message = 'The user was registered sucessfully!'
            return self.cipherResponse(
                request = request, 
                response = {
                    'success': message
                }, 
                sessioninfo = session,
            )

        return self.cipherResponse(
            request = request, 
            response = {'error':  'The sent data is not valid!' if not error else error}, 
            sessioninfo = session,
            error = True
        )

    def do_session_end(self, request):
        """
        This method allows client to end his session
        """
        print("\n\nEND SESSION")
        # Process request 
        # (Get session and decipher payload)
        session, data = self.processRequest(request)
        
        print("Session:", session)
        print("Open sessions are:", self.sessions.keys())

        # Validate that client has open session
        if not session:
            return self.rawResponse(
                request = request,
                response = {'error': 'Client does not have a valid session!'},
                error = True
            )

        # If so, delete it
        for id, s in self.sessions.items():
            if s == session:
                self.sessions.pop(id)
                print("Poped session!")
                print("Open sessions are:", self.sessions.keys())
                return self.cipherResponse(
                    request = request, 
                    response = {
                        'success': 'The session was ended successfully!',
                    }, 
                    sessioninfo = session,
                )

        return self.cipherResponse(
            request = request, 
            response = {
                'success': 'An error occured! Try again!',
            }, 
            sessioninfo = session,
            error = True
        )

    def do_renew_license(self, request):
        """
        This method allows the client to renew his certificate with the server
        """
        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        # Get payload
        session, data = self.processRequest(request)
        if not data or 'renew' not in data or not data['renew']:
            return self.cipherResponse(
                request = request,
                response = {
                    'error': 'Invalid payload! Try again!'
                },
                sessioninfo = session,
                error=True,
            ) 


        # Renew it
        user = updateLicense(self, session['username'], renew=True)

        if not user:
            return self.cipherResponse(
                request = request,
                response = {
                    'error': 'An error occured! Try again!'
                },
                sessioninfo = session,
                error=True,
            )  
            
        return self.cipherResponse(
            request = request,
            response = {
                'success': 'The license was successfully renewed!',
                'views': user['views'],
                'time': user['time']
            },
            sessioninfo = session,
        )

    # Send a media chunk to the client
    def do_download(self, request):

        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        # Get payload
        session, data = self.processRequest(request)
        if not data or not all(attr in data for attr in ['media', 'chunk']):
            return self.cipherResponse(
                request = request,
                response = {
                    'error': 'Invalid payload! Try again!'
                },
                sessioninfo = session,
                error=True,
            )

        logger.debug(f'Download: args: {request.args}')
        
        media_id = data['media']
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            return self.cipherResponse(
                request = request, 
                response = {'error': 'invalid media id'}, 
                sessioninfo = session,
                append = bytes(chunk_id),
                error = True
            )
        
        # Search media_id in the catalog
        if media_id not in CATALOG:
            return self.cipherResponse(
                request = request, 
                response = {'error': 'media file not found'}, 
                sessioninfo = session,
                append = bytes(chunk_id),
                error = True
            )
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = data['chunk']
        valid_chunk = False
        try:
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
                #if is valid chunck update_license
                media_duration= media_item['duration']
        except:
            logger.warn("Chunk format is invalid")

        # Update license for first chunk (decrement views)
        if chunk_id==0:
            user = updateLicense(self, session['username'], view=True)
            if not user:
                return self.cipherResponse(
                    request = request,
                    response = {'error': 'There was an error updating the license. Try again!'},
                    sessioninfo = session,
                    error = True
                )

        if not valid_chunk:
            return self.cipherResponse(
                request = request, 
                response = {'error': 'invalid chunk id'}, 
                sessioninfo = session,
                append = bytes(chunk_id),
                error = True
            )
            
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        data = self.MEDIA[media_item['file_name']][offset:offset+CHUNK_SIZE]
        message = {
            'media_id': media_id, 
            'chunk': chunk_id, 
            'data': binascii.b2a_base64(data).decode('latin').strip()
        }
        return self.cipherResponse(
            request = request, 
            response = message, 
            sessioninfo = session,
            append = bytes(chunk_id)
        )

        # File was not open?
        return self.cipherResponse(
            request = request, 
            response = {'error': 'unknown'}, 
            sessioninfo = session,
            append = bytes(chunk_id),
            error = True
        )


    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'\nReceived POST for {request.uri}')
        try:
            if request.path == b'/api/session':
                return self.do_session(request)
            elif request.path == b'/api/newuser':
                return self.do_auth(request, registration=True)
            elif request.path == b'/api/auth':
                return self.do_auth(request)
            elif request.path == b'/api/sessionend':
                return self.do_session_end(request)
            elif request.path == b'/api/renew':
                return self.do_renew_license(request)
            elif request.path == b'/api/download':
                return self.do_download(request)
        
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(501)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    # Responses processing
    def cipherResponse(self, request, response, sessioninfo, append = None, error = False):
        """
        This method ciphers a response to a request
        It also generates a MIC for the cryptogram
        --- Parameters
        request     
        response        A Python object to send encrypted as response
        sessioninfo     Client session data
        append          Bytes to append to shared_key before ciphering
        error           If error, set response code to 400
        --- Returns
        cryptogram      The response encrypted
        """
        print("\nAnswering...", response)
        if not response or not sessioninfo: return None
        # Convert Python Object to str and then to bytes
        message = json.dumps(response).encode()
        print("\nSerialized to...", message)
        # Encrypt
        cryptogram = CryptoFunctions.symetric_encryption(
            key = sessioninfo['shared_key'] if not append else sessioninfo['shared_key'] + append,
            message = message,
            algorithm_name = sessioninfo['cipher'],
            cypher_mode = sessioninfo['mode'],
            digest_mode = sessioninfo['digest'],
            encode = True
        )
        # Generate MIC
        MIC = CryptoFunctions.create_digest(cryptogram, sessioninfo['digest'])
        print("\nGenerated MIC:\n", MIC)
        MAC = CryptoFunctions.create_digest(cryptogram+sessioninfo['shared_key'], sessioninfo['digest'])
        print("\nGenerated MAC:\n", MAC)
        # Sign request with private key
        SIGN = CryptoFunctions.signingRSA(cryptogram, self.private_key)
        print("\nGenerated signature:\n", SIGN)
        # Add headers
        request.responseHeaders.addRawHeader(b"mic", base64.b64encode(MIC))
        request.responseHeaders.addRawHeader(b"mac", base64.b64encode(MAC))
        request.responseHeaders.addRawHeader(b"signature", base64.b64encode(SIGN))
        request.responseHeaders.addRawHeader(b"certificate", base64.b64encode(self.cert.public_bytes(encoding = serialization.Encoding.PEM)))
        request.responseHeaders.addRawHeader(b"ciphered", b"True")
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        if error:
            request.setResponseCode(400)
        # Return cryptogram
        return cryptogram

    def rawResponse(self, request, response, error = False):
        """
        This method returns a raw response to a request
        It also generates a pseudo MIC (hash) for the cryptogram
        --- Parameters
        request     
        response        A Python object to send encrypted as response
        error           If error, set response code to 400
        --- Returns
        cryptogram      The response encrypted
        """
        print("\nAnswering...", response)
        if not response: return None
        # Convert Python Object to str and then to bytes
        message = json.dumps(response).encode().strip()
        print("\nSerialized to...", message)
        print("\nType of serialized...", type(message))
        # Generate pseudo MIC
        MIC = str(str(message).__hash__()).encode('latin')
        print("\nGenerated pseudo MIC:\n", MIC)
        # Sign request with private keya
        SIGN = CryptoFunctions.signingRSA(message, self.private_key)
        print("\nGenerated signature:\n", SIGN)
        # Add headers
        request.responseHeaders.addRawHeader(b"mic", base64.b64encode(MIC))
        request.responseHeaders.addRawHeader(b"signature", base64.b64encode(SIGN))
        request.responseHeaders.addRawHeader(b"certificate", base64.b64encode(self.cert.public_bytes(encoding = serialization.Encoding.PEM)))
        request.responseHeaders.addRawHeader(b"ciphered", b'False')
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        if error:
            request.setResponseCode(400)
        # Return message
        return message

    # Requests processing
    def processRequest(self, request):
        """
        Gets the user session
        Validates the MIC sent on the header 
        Deciphers the criptogram on the request content with the key given
        --- Parameters
        request
        --- Returns
        session         Dict with session info
        data            The payload deciphered and validated
        """
        print("\nProcessing request...")

        headers = request.getAllHeaders()

        # Validate certificate and request signature
        if not self.processRequestCertificate(request):
            return None, None

        # Get session and validate it
        session = self.getSession(request)
        if not session:
            return None, None
        
        # Get MIC and validate it
        RMIC = base64.b64decode(headers[b'mic'])
        print("\nGot MIC...\n", RMIC)
        MIC = CryptoFunctions.create_digest(request.content.getvalue().strip(), session['digest']).strip()
        print("\nMIC computed...\n", MIC)
        if MIC != RMIC:
            print("INVALID MIC!")
            return None, None
        else:
            print("Validated MIC!")

        RMAC = base64.b64decode(headers[b'mac'])
        print("\nGot MAC...\n", RMIC)
        MAC = CryptoFunctions.create_digest(request.content.getvalue().strip() + session['shared_key'], session['digest']).strip()
        print("\nMAC computed...\n", MAC)
        if MAC != RMAC:
            print("INVALID MAC!")
            return None, None
        else:
            print("Validated MAC!")

        # Decipher request
        print("\nDeciphering request...\n", request.content.getvalue().strip())
        message = CryptoFunctions.symetric_encryption( 
            key = session['shared_key'], 
            message = request.content.getvalue(), 
            algorithm_name = session['cipher'], 
            cypher_mode = session['mode'], 
            digest_mode = session['digest'], 
            encode = False 
        ) 
        return session, json.loads(message)

    # Process client certificates
    def processRequestCertificate(self, request):
        """
        This method validates the client certificates for a request
        --- Returns
        certificate valid       boolean
        """
        headers = request.getAllHeaders()

        # Validate certificate
        print("\nGot Certificate and Signature...")
        cert =  base64.b64decode(headers[b'cert']).decode('latin')
        print("\nCert is...\n", cert)
        if not self.pki.validateCerts(cert, [], pem=True):
            print("ERROR! The server certificate is not valid!")
            return False
        else:
            print("\nThe server certificate is valid!")

        # Validate signature!
        cert = self.pki.getCertFromString(cert, pem=True) 
        sign = base64.b64decode(headers[b'signature']) 
        signMessage = request.content.getvalue() if request.content.getvalue() else json.dumps(dict()).encode('latin')
        if not CryptoFunctions.validacaoAssinatura_RSA(sign, signMessage, cert.public_key()):
            print("\nERROR! The client signature is not valid!")
            return False
        else: 
            print("\nThe client signature is valid! :)") 
        return True        

    # Session management
    def getSession(self, request):
        """
        This method gets the session for the token sent on request header
        """
        headers = request.getAllHeaders()
        sessionid = uuid.UUID(bytes=base64.b64decode(headers[b'sessionid']))
        if sessionid not in self.sessions.keys():
            print(f"\nInvalid session! ({sessionid})")
            return None
        session = self.sessions[sessionid]
        print("\nSession", sessionid)
        print(session)
        return session

    # Validate that client has open session
    def invalidSession(self, request):
        """
        This method validates that the client has a valid session and is logged in
        --- Returns 
        response
        session
        """
        session = self.getSession(request)
        error = ""
        if not session:
            return self.rawResponse(
                request = request,
                response = {'error': 'Client does not have a valid session!'},
                error = True
            ), None
        # If has session, must be logged
        elif not session['authenticated']:
            return self.cipherResponse(
                request = request,
                response = {'error': 'Client must be logged in to access this resource!'},
                sessioninfo = session,
                error = True
            ), None
        return None, session

    # Server files
    def getFile(self, location):
        """
        Loads encrypted file at server folder
        - Parameters
        location        String      The file location
        - Returns
        content         String      The file decripted
        """
        print(f"\ngetFile({location})")
        # Load file
        content = open(location, 'rb').read()
        # Descript it
        return CryptoFunctions.symetric_encryption(
            key = KEY.encode('latin'),
            message = content,
            algorithm_name = "AES",
            digest_mode = "SHA512",
            cypher_mode = "CBC",
            encode = False
        ).decode('latin')
        
    def updateFile(self, location, content):
        """
        Loads the content of an encripted file at server 
        - Parameters
        location        String      The file location
        content         String      The content to update with
        - Returns
        content         String      The file decripted
        """
        print(f"\nupdateFile({location})")
        # Generate cryptogram
        cryptogram = CryptoFunctions.symetric_encryption(
            key = KEY.encode('latin'),
            message = content.encode('latin'),
            algorithm_name = "AES",
            digest_mode = "SHA512",
            cypher_mode = "CBC",
            encode = True
        )
        # Save to file
        open(location, 'wb').write(cryptogram)
        

print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()