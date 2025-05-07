import os
import base64
import pytest
from dotenv import load_dotenv
from encryption import encrypt_data, decrypt_data, encrypt_aes

load_dotenv()

def encrypt_aes_for_test(data, key):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def test_encryption_decryption():
    test_data = "Test data rahasia"
    encrypted = encrypt_data(test_data)
    decrypted = decrypt_data(encrypted)
    assert decrypted == test_data

def test_aes_encryption():
    test_data = "Data rahasia"
    key = os.getenv('AES_KEY').encode()
    encrypted = encrypt_aes(test_data, key)
    decrypted = decrypt_data(encrypted)
    assert decrypted == test_data

def test_invalid_key_decryption():
    original_key = os.getenv('AES_KEY')  # Simpan key asli
    test_data = "Test untuk key tidak valid"

    encrypted = encrypt_data(test_data)

    os.environ['AES_KEY'] = 'invalid_key_1234567890abcdef'
    with pytest.raises(ValueError):
        decrypt_data(encrypted)

    os.environ['AES_KEY'] = original_key  # Restore key
