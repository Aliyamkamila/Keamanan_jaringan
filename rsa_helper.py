from Crypto.PublicKey import RSA
import re

def format_pem_key(key_str):
    """
    Memastikan string kunci RSA memiliki format PEM yang benar
    """
    # Hapus whitespace di awal dan akhir
    key_str = key_str.strip()
    
    # Hapus semua header dan footer yang mungkin sudah ada untuk menghindari duplikasi
    key_str = re.sub(r'-----BEGIN RSA PRIVATE KEY-----', '', key_str)
    key_str = re.sub(r'-----END RSA PRIVATE KEY-----', '', key_str)
    
    # Hapus semua whitespace dan newline
    key_str = re.sub(r'\s+', '', key_str)
    
    # Format ulang dengan struktur PEM yang benar (60 karakter per baris)
    formatted_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    for i in range(0, len(key_str), 64):
        formatted_key += key_str[i:i+64] + '\n'
    formatted_key += '-----END RSA PRIVATE KEY-----'
    
    return formatted_key

def is_valid_pem(key_str):
    """
    Memeriksa apakah string kunci adalah format PEM yang valid
    """
    try:
        RSA.import_key(key_str)
        return True
    except Exception:
        return False

def extract_pem_content(key_str):
    """
    Mengekstrak konten base64 dari kunci PEM
    """
    matches = re.search(r'-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----', 
                       key_str, re.DOTALL)
    if matches:
        return matches.group(1).strip()
    return None