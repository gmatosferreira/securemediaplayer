#!/usr/bin/env python
from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math
import uuid
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
from licenses import *

logger = logging.getLogger('root')
FORMAT = "[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s"
logging.basicConfig(format=FORMAT)
logger.setLevel(logging.DEBUG)

CATALOG = { '898a08080d1840793122b7e118b27a95d117ebce': 
            {
                'name': 'Sunny Afternoon - Upbeat Ukulele Background Music',
                'album': 'Upbeat Ukulele Background Music',
                'description': 'Nicolai Heidlas Music: http://soundcloud.com/nicolai-heidlas',
                'duration': 3*60+33,
                'file_name': '898a08080d1840793122b7e118b27a95d117ebce.mp3',
                'file_size': 3407202
            }
        }

CATALOG_BASE = 'catalog'
CHUNK_SIZE = 1024 * 4  #block

class MediaServer(resource.Resource):
    isLeaf = True

    # Constructor
    def __init__(self):
        print("Initializing server...")
        # TODO Change on production to new parameters every initialization! 
        # self.parameters = dh.generate_parameters(generator=2, key_size=2048)
        with open('parameters', 'rb') as f:
            self.parameters = serialization.load_pem_parameters(f.read().strip())    
            print("Loaded parameters!")

        # Initialize session dictionary
        self.sessions = {}

    # Send the server DH parameters
    def do_parameters(self, request):
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
        protocols = {
            'cipher': ['AES','3DEs'], 
            'digests': CryptoFunctions.digests, 
            'cipher_mode': ['CBC', 'OFB']  
        }
        return self.rawResponse(
            request = request,
            response = protocols
        )


    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'
        
        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        # Validate license
        if not licenseValid(session['data']):
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


    # Send a media chunk to the client
    def do_download(self, request):

        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        # Validate license
        if not licenseValid(session['data']):
            return self.cipherResponse(
                request = request,
                response = {'error': 'License is not valid! Please renew it.'},
                sessioninfo = session,
                error = True
            )

        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
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
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

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
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
                #if is valid chunck update_license
                media_duration= media_item['duration']
                
                update_license(self.username,media_duration)
        except:
            logger.warn("Chunk format is invalid")

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
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)
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

    def do_license(self, request):
        """
        This method allows the client to look up his license status
        """
        # Validate session and log in
        invalid, session = self.invalidSession(request)
        if invalid: return invalid

        return self.cipherResponse(
            request = request, 
            response = {
                'success': 'Here is your license! :)',
                'views': session['data']['views'],
                'time': session['data']['time'],
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
            elif request.path == b'/api/download':
                return self.do_download(request)
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
        return json.dumps({
            'public_key': pk.decode('utf-8'),
        }).encode('latin')

    
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
        if not data or not all(attr in data and data[attr] for attr in ['username', 'password']):
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
                    'views': session['data']['views'],
                    'time': session['data']['time']
                }, 
                sessioninfo = session,
            )
            
        print("\nData received is...\n", data)
        # Validate data
        if not registration:
            userData = authenticate(data['username'], data['password'], session)
        else:
            userData = register(data['username'], data['password'])
        # If authenticated/registered sucessfully
        if userData:
            if not registration:
                session['authenticated'] = True
                session['data'] = userData
                message = 'The user was authenticated sucessfully!'
            else:
                message = 'The user was registered sucessfully!'
            return self.cipherResponse(
                request = request, 
                response = {
                    'success': message,
                    'views': userData['views'],
                    'time': userData['time']
                }, 
                sessioninfo = session,
            )

        return self.cipherResponse(
            request = request, 
            response = {'error': 'The sent data is not valid!'}, 
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
        user = renewLicense(session['data']['username'])

        # Update session
        session['data'] = user

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
                'time': user['time'],
            },
            sessioninfo = session,
        )



    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'\nReceived POST for {request.uri}')
        try:
            if request.path == b'/api/suite':
                return self.process_negotiation(request)
            elif request.path == b'/api/session':
                return self.do_session(request)
            elif request.path == b'/api/newuser':
                return self.do_auth(request, registration=True)
            elif request.path == b'/api/auth':
                return self.do_auth(request)
            elif request.path == b'/api/sessionend':
                return self.do_session_end(request)
            elif request.path == b'/api/renew':
                return self.do_renew_license(request)
        
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
        # Add headers
        request.responseHeaders.addRawHeader(b"mic", MIC)
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
        # Add headers
        request.responseHeaders.addRawHeader(b"mic", MIC)
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

        # Get session and validate it
        session = self.getSession(request)
        if not session:
            return None, None
        
        # Get MIC and validate it
        headers = request.getAllHeaders()
        RMIC = headers[b'mic']
        print("\nGot MIC...\n", RMIC)
        MIC = CryptoFunctions.create_digest(request.content.getvalue().strip(), session['digest']).strip()
        print("\nMIC computed...\n", MIC)
        if MIC != RMIC:
            print("INVALID MIC!")
            return None, None
        else:
            print("Validated MIC!")

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

    # Session management
    def getSession(self, request):
        """
        This method gets the session for the token sent on request header
        """
        headers = request.getAllHeaders()
        sessionid = uuid.UUID(bytes=headers[b'sessionid'])
        if sessionid not in self.sessions.keys():
            print(f"\nInvalid session! ({sessionid})")
            return None
        session = self.sessions[sessionid]
        print("\nSession", sessionid)
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


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()