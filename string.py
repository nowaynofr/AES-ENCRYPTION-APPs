import hashlib
import os
import os.path
from Crypto import Random
from Crypto.Cipher import AES
import base64


def encrypt(key, plaintext):
    key = hashlib.sha256(key.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    ciphertext = base64.b64encode(ciphertext).decode('utf-8')
    return ciphertext, tag
def decrypt(key, ciphertext, tag):
# Hash the key to ensure it is 32 bytes long
    key = hashlib.sha256(key.encode('utf-8')).digest()

    # Decode the ciphertext from base64
    ciphertext = base64.b64decode(ciphertext.encode('utf-8'))

    # Create a new cipher object using the key
    cipher = AES.new(key, AES.MODE_EAX, tag)

    # Decrypt the ciphertext
    plaintext = cipher.decrypt(ciphertext).decode('utf-8')

    # Return the plaintext
    return plaintext

def main():
    # Prompt the user for the key and plaintext
    key = input("Enter the key: ")
    plaintext = input("Enter the plaintext: ")
    
    # Encrypt the plaintext
    ciphertext, tag = encrypt(key, plaintext)
    
    # Print the ciphertext and tag
    print("Ciphertext:", ciphertext)
    print("Tag:", tag)
    
    ciphertexts =input("nhap bản mã hóa")
    plaintexts =decrypt(key,ciphertexts,tag)
    print("plaintext:", plaintexts)


if __name__ == "__main__":
    main()    