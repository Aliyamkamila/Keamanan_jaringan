import pytest
from key_management import KeyManager

def test_key_generation():
    key = KeyManager.generate_key()
    assert len(key) == 32
    assert KeyManager.validate_key(key)[0] is True

def test_key_validation():
    # Test kunci valid
    assert KeyManager.validate_key("A"*32)[0] is True
    # Test kunci invalid
    assert KeyManager.validate_key("A"*31)[0] is False  # Panjang salah
    assert KeyManager.validate_key("∆"*32)[0] is False  # Karakter non-ASCII