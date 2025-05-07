import pytest
from key_management import KeyManager

@pytest.fixture
def valid_key():
    """Fixture untuk kunci valid"""
    return "Valid32ByteKey-1234567890!@#$%^&*()"

@pytest.fixture
def invalid_key():
    """Fixture untuk kunci invalid"""
    return "ShortKey"