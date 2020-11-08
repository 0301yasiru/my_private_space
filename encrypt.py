# !/usr/bin/python

# this is the script for encrypting

#firstly import the liblary to encrypt project
from os import remove
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

passwd = input('Please enter the key to encrypt -> ').strip()
passwd = passwd.encode('utf-8')

salt = b'\xb0}\x8b,\xf6\xdcX\xa1\x8b\xcc\xa920!\xc2\xe2'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

key = urlsafe_b64encode(kdf.derive(passwd))

file_path = input("Enter file path: ").strip()

with open (file_path, 'rb') as original:
    original_content = original.read()

fernet_obj = Fernet(key)

encrypted_content = fernet_obj.encrypt(original_content)

#before saving the file remove old file
remove(file_path)
with open(file_path, 'wb') as encrypted:
    encrypted.write(encrypted_content)
