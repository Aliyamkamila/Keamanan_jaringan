import sqlite3
from encryption import encrypt_data, decrypt_data
import os
import secrets
from typing import Tuple
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

load_dotenv()

class KeyManager:
    def __init__(self):
        self.current_key = os.getenv('AES_KEY').encode('utf-8')  # Ambil dari .env
        assert len(self.current_key) == 32, "Kunci harus 32 byte"
        self.key_versions = {"v1": "old_key", "v2": self.current_key}

    @staticmethod
    def decrypt_aes_key(encrypted_aes_key: bytes, private_key: bytes) -> bytes:
        rsa_key = RSA.import_key(private_key)
        return PKCS1_OAEP.new(rsa_key).decrypt(encrypted_aes_key)

    def rotate_key(self, new_key: str):
        """Migrasi data ke kunci baru"""
        if len(new_key.encode('utf-8')) != 32:
            raise ValueError("Kunci harus 32 byte")
        
        conn = None
        old_key = self.current_key
        try:
            conn = sqlite3.connect('encrypted_data.db')
            cursor = conn.cursor()
            
            rows = cursor.execute("SELECT id, data FROM transactions").fetchall()
            for row in rows:
                decrypted = decrypt_data(row[1])
                self.current_key = new_key.encode('utf-8')
                reencrypted = encrypt_data(decrypted)
                
                cursor.execute(
                    "UPDATE transactions SET data=? WHERE id=?",
                    (reencrypted, row[0])
                )
            
            conn.commit()
            self.key_versions["v3"] = new_key.encode('utf-8')
            os.environ['AES_KEY'] = new_key
            
            with open('.env', 'w') as f:
                f.write(f"AES_KEY={new_key}\nFLASK_SECRET={os.getenv('FLASK_SECRET')}")
            
            return True
            
        except Exception as e:
            print(f"Error during key rotation: {str(e)}")
            if conn:
                conn.rollback()
            self.current_key = old_key
            return False
        finally:
            if conn:
                conn.close()

    @staticmethod
    def generate_key() -> str:
        """Generate random 32-byte key"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    @staticmethod
    def validate_key(key: str) -> Tuple[bool, str]:
        """Validasi panjang dan karakter kunci"""
        if len(key.encode('utf-8')) != 32:
            return False, "Kunci harus 32 byte"
        if not all(ord(c) < 128 for c in key):
            return False, "Hanya gunakan karakter ASCII"
        return True, "Valid"

if __name__ == "__main__":
    print("\n=== Demo Rotasi Kunci ===")
    
    new_key = KeyManager.generate_key()
    print(f"[1] Generated Key: {new_key} (Length: {len(new_key)})")
    
    is_valid, msg = KeyManager.validate_key(new_key)
    print(f"[2] Validation: {msg}")
    
    if is_valid:
        km = KeyManager()
        if km.rotate_key(new_key):
            print("[3] Key rotated successfully!")
            print(f"Current Key: {os.getenv('AES_KEY')}")
        else:
            print("[3] Key rotation failed")