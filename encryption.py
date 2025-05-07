from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from dotenv import load_dotenv

load_dotenv()
key = os.getenv('AES_KEY').encode('utf-8')

def encrypt_data(data: str) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_data(encrypted_data: str) -> str:
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except (ValueError, KeyError) as e:
        raise ValueError("Dekripsi gagal: kunci tidak valid atau data korup") from e

def encrypt_user_data(data: dict) -> str:
    sensitive_fields = ['card', 'cvv']
    encrypted_data = data.copy()
    for field in sensitive_fields:
        if field in data:
            encrypted_data[field] = encrypt_data(data[field])
    return str(encrypted_data)

def encrypt_aes(data: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def test_invalid_key_decryption():
    original_key = os.getenv('AES_KEY')  # Simpan kunci asli
    encrypted = encrypt_data("test")  # Enkripsi dengan kunci valid
    
    # Ganti kunci ke invalid
    invalid_key = "invalid_key_1234567890abcdef"  # 28 karakter (tidak valid)
    os.environ['AES_KEY'] = invalid_key
    
    # Muat ulang kunci di modul encryption
    from importlib import reload
    reload(encryption)  # Pastikan kunci terupdate
    
    # Tes
    with pytest.raises(ValueError):
        decrypt_data(encrypted)
    
    # Kembalikan kunci asli
    os.environ['AES_KEY'] = original_key
    reload(encryption)
