"""
Encryption module for password vault
Handles encryption and decryption of passwords using Fernet symmetric encryption
"""
from cryptography.fernet import Fernet
import base64
import hashlib


class PasswordEncryption:
    def __init__(self, master_password: str):
        """Initialize encryption with a master password"""
        self.key = self._derive_key(master_password)
        self.cipher = Fernet(self.key)
    
    def _derive_key(self, password: str) -> bytes:
        """Derive a Fernet key from the master password"""
        # Use SHA256 to create a 32-byte hash from the password
        hash_obj = hashlib.sha256(password.encode())
        key_bytes = hash_obj.digest()
        # Fernet requires a base64-encoded 32-byte key
        return base64.urlsafe_b64encode(key_bytes)
    
    def encrypt(self, password: str) -> str:
        """Encrypt a password"""
        encrypted_bytes = self.cipher.encrypt(password.encode())
        return encrypted_bytes.decode()
    
    def decrypt(self, encrypted_password: str) -> str:
        """Decrypt a password"""
        try:
            decrypted_bytes = self.cipher.decrypt(encrypted_password.encode())
            return decrypted_bytes.decode()
        except Exception:
            return ""
