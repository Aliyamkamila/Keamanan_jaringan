# aes_encryption.py
from Crypto.Cipher import AES
import base64
import hashlib
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

def get_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_aes(message, password):
    key = get_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), BLOCK_SIZE))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ":" + ct

def decrypt_aes(enc_message, password):
    key = get_key(password)
    iv, ct = enc_message.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), BLOCK_SIZE)
    return pt.decode('utf-8')