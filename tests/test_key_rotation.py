import os
import pytest
from key_management import KeyManager
from dotenv import load_dotenv

load_dotenv()

def rotate_key(self, new_key: str):
    if len(new_key.encode('utf-8')) != 32:  # Validasi byte, bukan karakter
        raise ValueError("Kunci harus 32 byte")

def test_key_initialization():
    km = KeyManager()
    assert len(km.current_key) == 32
    assert "v1" in km.key_versions
    assert "v2" in km.key_versions

def test_key_rotation():
    km = KeyManager()
    # Pastikan panjang tepat 32 karakter
    new_key = "New32ByteKeyForRotationTest1234567"  # 32 chars
    
    # Test valid key
    assert km.rotate_key(new_key) is True
    assert os.getenv('AES_KEY') == new_key
    
    # Test invalid key
    with pytest.raises(ValueError, match="Kunci harus 32 byte"):
        km.rotate_key("short-key")