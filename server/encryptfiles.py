# Based on cryptography.io/en/latest/hazmat/primitives/symmetric-encryption.html
# Usage for encription: python3 FilesEncription.py encrypt.txt cryptogram.txt e 
# Usage for decription: python3 FilesEncription.py cryptogram.txt decripted.txt d
import os 
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DEFAULT_KEY = "RI1lakfYaos8Zj6G02wbGYZPfifc1gWK"

# Validate execution
if len(sys.argv)!=5:
	print("There must be givven 3 arguments:")
	print("\t1. The name of the file to encrypt")
	print("\t2. The name of the file to store the cryptogram")
	print("\t3. Encprition (e) or Decription (d)")
	print("\t4. The key to use on encription (32 bytes long)")
	exit()
	
# Get the encription key
key = None
with open(sys.argv[4], 'r') as f:
	key = f.read().strip()

if len(key)!=32:
	print("ERROR! The key must be exactly 32 chars long!")
	exit()

print("# Using key",key)

# Encode key (to bytes)
key = str.encode(key)

# Get user arguments
source = sys.argv[1]
destination = sys.argv[2]

mode = sys.argv[3]
if mode not in ['e', 'd']:
	print("Invalid mode!")
	exit()

# Define algorithm
algorithm = None
blockLength = 0
iv = None
useIv = True
algorithm = algorithms.AES(key)
# Divide by 8 because it returns size on bits and we want on bytes (8 bits)
blockLength = algorithms.AES.block_size // 8

print(f"# Going to work with {algorithm.name} algorithm")
print("# Block size will be", blockLength)

# Generate initialization vector
if mode == 'e' and iv == None:
	iv = os.urandom(blockLength)
if mode == 'd' and iv == None:
	with open(source, 'rb') as f:
		iv = f.read(blockLength)
print("# Initialization vector is", iv)

# Initialize Cipher with user chosen algorithm and Cipher Block Chaining mode
if useIv:
	cipher = Cipher(algorithm, modes.CBC(iv))
else:
	cipher = Cipher(algorithm, mode=None)

# Get encryptor for initialized cipher
if mode == 'e':
	cryptor = cipher.encryptor()
else:
	cryptor = cipher.decryptor()

# Encrypt file, block by block
with open(source, 'rb') as f:
	with open(destination, 'wb') as fc:
		# On encription, save IV at the beggining
		if mode == 'e':
			fc.write(iv)
		# On decription, ignore IV
		else:
			f.read(blockLength)
		# Iterate over blocks
		while True:
			data = f.read(blockLength)
			# If data has block size, just encrypt
			if len(data) == blockLength:
				fc.write(cryptor.update(data))
			# If smaller, reached end, add padding and finalyze
			else:
				# On encription, save IV at the beggining
				if mode == 'e':
					padding_length = blockLength - len(data)
					padding = [padding_length] * (padding_length)
					fc.write(cryptor.update(data + bytes(padding)))
				# On decription, just add finalization
				else:
					pass
				fc.write(cryptor.finalize())
				break

if mode == 'e':
	print(f"{source} has been sucessfully encripted to {destination}!")
else:
	print(f"{source} has been sucessfully decripted to {destination}!")