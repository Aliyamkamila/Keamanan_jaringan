# rsa_encryption.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)

def load_keys():
    with open("private.pem", "rb") as priv_file:
        private_key = priv_file.read().decode()

    with open("public.pem", "rb") as pub_file:
        public_key = pub_file.read().decode()

    return private_key, public_key

def encrypt_rsa(message, public_key_str):
    try:
        public_key = RSA.import_key(public_key_str.encode())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted = cipher_rsa.encrypt(message.encode())
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        raise ValueError(f"❌ Gagal enkripsi RSA: {str(e)}")

def decrypt_rsa(encrypted_b64, private_key_str):
    try:
        # Pastikan format kunci PEM yang benar
        if not private_key_str.startswith('-----BEGIN'):
            raise ValueError("Format kunci RSA tidak valid")
            
        private_key = RSA.import_key(private_key_str.encode())
        cipher_rsa = PKCS1_OAEP.new(private_key)
        decrypted = cipher_rsa.decrypt(base64.b64decode(encrypted_b64))
        return decrypted.decode()
    except ValueError as e:
        raise ValueError(f"❌ Gagal dekripsi RSA: {str(e)}")
    except Exception as e:
        raise ValueError(f"❌ Error dalam dekripsi RSA: {str(e)}")