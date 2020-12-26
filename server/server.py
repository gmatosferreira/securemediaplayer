#!/usr/bin/env python

from twisted.web import server, resource
from twisted.internet import reactor, defer
import logging
import binascii
import json
import os
import math

# Serialization
from cryptography.hazmat.primitives import serialization

# Diffie-hellman
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import sys
sys.path.append('..')

from crypto_functions import CryptoFunctions

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
        # Create the private/public keys pairs
        self.private_key, self.public_key = CryptoFunctions.newKeys(self.parameters)
        self.shared_key = None

        self.CIPHER = None
        self.DIGEST = None
        self.CIPHER_MODE= None
        self.KEY = None
        
        print("\nPrivate key created!\n", self.private_key)
        print(self.private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))
        print("\nPublic key generated!\n", self.public_key)
        print(self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Send the server public key
    def do_parameters(self, request):
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        # Convert parameters to bytes
        pr = self.parameters.parameter_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.ParameterFormat.PKCS3
        )
        print("\nSerialized parameters as bytes to answer request!\n", pr)

        # Return it
        return json.dumps({
            'parameters': pr.decode('utf-8')
        }).encode('latin')

    # Send the list of available protocols
    def do_choose_protocols(self, request):
        protocols = {
            'cipher': ['AES','3DEs'], 
            'digests': ['SHA512', 'BLAKE2'], 
            'cipher_mode': ['CBC', 'OFB']  
        }
        
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        return json.dumps(protocols).encode('latin')


    # Send the list of media files to clients
    def do_list(self, request):

        #auth = request.getHeader('Authorization')
        #if not auth:
        #    request.setResponseCode(401)
        #    return 'Not authorized'

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
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        message = json.dumps(media_list).encode()
        return self.cipher(request, message)


    # Send a media chunk to the client
    def do_download(self, request):
        logger.debug(f'Download: args: {request.args}')
        
        media_id = request.args.get(b'id', [None])[0]
        logger.debug(f'Download: id: {media_id}')

        # Check if the media_id is not None as it is required
        if media_id is None:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = json.dumps({'error': 'invalid media id'}).encode()
            return self.cipher(request, message)
        
        # Convert bytes to str
        media_id = media_id.decode('latin')

        # Search media_id in the catalog
        if media_id not in CATALOG:
            request.setResponseCode(404)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = json.dumps({'error': 'media file not found'}).encode()
            return self.cipher(request, message)
        
        # Get the media item
        media_item = CATALOG[media_id]

        # Check if a chunk is valid
        chunk_id = request.args.get(b'chunk', [b'0'])[0]
        valid_chunk = False
        try:
            chunk_id = int(chunk_id.decode('latin'))
            if chunk_id >= 0 and chunk_id  < math.ceil(media_item['file_size'] / CHUNK_SIZE):
                valid_chunk = True
        except:
            logger.warn("Chunk format is invalid")

        if not valid_chunk:
            request.setResponseCode(400)
            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = json.dumps({'error': 'invalid chunk id'}).encode()
            return self.cipher(request, message)
            
        logger.debug(f'Download: chunk: {chunk_id}')

        offset = chunk_id * CHUNK_SIZE

        # Open file, seek to correct position and return the chunk
        with open(os.path.join(CATALOG_BASE, media_item['file_name']), 'rb') as f:
            f.seek(offset)
            data = f.read(CHUNK_SIZE)

            request.responseHeaders.addRawHeader(b"content-type", b"application/json")
            message = json.dumps(
                {
                    'media_id': media_id, 
                    'chunk': chunk_id, 
                    'data': binascii.b2a_base64(data).decode('latin').strip()
                }
            ).encode()
            return self.cipher(request, message)

        # File was not open?
        request.responseHeaders.addRawHeader(b"content-type", b"application/json")
        message = json.dumps({'error': 'unknown'}).encode()
        return self.cipher(request, message)

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
                print("OK")
                return self.do_download(request)
            else:
                request.responseHeaders.addRawHeader(b"content-type", b'text/plain')
                return b'Methods: /api/protocols /api/list /api/download'

        except Exception as e:
            logger.exception(e)
            request.setResponseCode(500)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''
        
    """
    This method allows the client to send his public key
    and get the server's one, so that they both generate the 
    session shared key (Diffie-Hellman) 
    """
    def do_public_key(self, request):
        data = request.args.get(b'public_key')
        if data == None or data == '':
            print('Data is none or empty')
            return 
        print(request.args) 

        # 1. Get the client shared key and public key
        print("\nClient public key raw.\n", request.args[b'public_key'][0])
        client_public_key = serialization.load_pem_public_key(request.args[b'public_key'][0])
        print("\nGot the client public key!\n", client_public_key)

        # 2. Diffie-Hellman | Generate shared key
        self.shared_key = self.private_key.exchange(client_public_key)
        print("\nGenerated the server shared key!\n", self.shared_key)

        # 3. Convert public key to bytes
        pk = self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("\nSerialized public key to answer request!\n", pk)
 
        # 3.1. Return it
        return json.dumps({
            'public_key': pk.decode('utf-8'),
        }).encode('latin')
    
    def process_negotiation(self,request):
        data = request.args.get(b'id', "digest" )
        
        if data == None or data == '':
            print('Data is none or empty')
        else:
            self.CIPHER = request.args[b'cipher'][0].decode('utf-8')
            self.DIGEST = request.args[b'digest'][0].decode('utf-8')
            self.CIPHER_MODE = request.args[b'cipher_mode'][0].decode('utf-8')
            print(f"\n\nDefined chiper suite as:\nCipher: {self.CIPHER}\nDigest: {self.DIGEST}\nMode: {self.CIPHER_MODE}\n")
        
    # Handle a POST request
    def render_POST(self, request):
        logger.debug(f'\nReceived POST for {request.uri}')
        try:
            if request.path == b'/api/suite':
                return self.process_negotiation(request)
            elif request.path == b'/api/publickey':
                return self.do_public_key(request)

        
        except Exception as e:
            logger.exception(e)
            request.setResponseCode(501)
            request.responseHeaders.addRawHeader(b"content-type", b"text/plain")
            return b''

    # Cipher
    def cipher(self, request, response):
        """
        This method ciphers a response to a request
        It also generates a MIC for the cryptogram
        """
        cryptogram = CryptoFunctions.symetric_encryption(
            key = self.shared_key,
            message = response,
            algorithm_name = self.CIPHER,
            cypher_mode = self.CIPHER_MODE,
            digest_mode = self.DIGEST,
            encode = True
        )

        MIC = CryptoFunctions.create_digest(cryptogram, self.DIGEST)
        print("Generated MIC:\n",MIC)
        request.responseHeaders.addRawHeader(b"MIC", MIC)
        print(request.responseHeaders)

        return cryptogram


print("Server started")
print("URL is: http://IP:8080")

s = server.Site(MediaServer())
reactor.listenTCP(8080, s)
reactor.run()