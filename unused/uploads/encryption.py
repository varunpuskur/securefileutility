from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from hashlib import pbkdf2_hmac
import os

def generate_key(password, salt):
    """Generate a key from the password using PBKDF2."""
    return pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)

def encrypt_data(password, data):
    """Encrypt data with the provided password."""
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return b64encode(salt + iv + ciphertext).decode('utf-8')

def decrypt_data(password, encrypted_data):
    """Decrypt data with the provided password."""
    encrypted_data = b64decode(encrypted_data)
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = generate_key(password, salt)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
