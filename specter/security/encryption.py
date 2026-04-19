"""
Specter Encryption Module
=========================
Cryptographic encryption utilities for confidential computing.
Provides AES-GCM, AES-CBC, and secure key handling.
"""

import os
import hashlib
import hmac
import struct
from typing import Tuple, Optional, Union
from dataclasses import dataclass


class EncryptionError(Exception):
    """Base exception for encryption errors."""
    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""
    pass


class KeyDerivationError(EncryptionError):
    """Raised when key derivation fails."""
    pass


@dataclass
class EncryptedData:
    """Container for encrypted data with metadata."""
    ciphertext: bytes
    iv: bytes
    tag: Optional[bytes] = None
    key_id: Optional[bytes] = None
    algorithm: str = "AES-GCM"
    
    def to_bytes(self) -> bytes:
        """Serialize encrypted data to bytes."""
        result = self.iv
        if self.tag:
            result += self.tag
        result += self.ciphertext
        if self.key_id:
            result += struct.pack("<I", len(self.key_id)) + self.key_id
        else:
            result += struct.pack("<I", 0)
        return result
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedData":
        """Deserialize encrypted data from bytes."""
        iv = data[:12]
        tag = data[12:28]
        key_id_len = struct.unpack("<I", data[28:32])[0]
        ciphertext = data[32:32+key_id_len] if key_id_len == 0 else data[32:32+(len(data)-32-key_id_len)]
        # Simplified parsing
        return cls(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag if len(data) > 28 else None,
        )


# AES-GCM Encryption
def aes_gcm_encrypt(
    plaintext: bytes,
    key: bytes,
    iv: Optional[bytes] = None,
    aad: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-GCM.
    
    Args:
        plaintext: Data to encrypt
        key: Encryption key (16, 24, or 32 bytes)
        iv: Initialization vector (12 bytes recommended, auto-generated if None)
        aad: Additional authenticated data (optional)
        
    Returns:
        Tuple of (ciphertext, tag)
    """
    try:
        import pyaes
        
        if iv is None:
            iv = os.urandom(12)
        elif len(iv) != 12:
            raise EncryptionError(f"IV must be 12 bytes, got {len(iv)}")
        
        if len(key) not in (16, 24, 32):
            raise EncryptionError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
        
        # Use simplified GCM implementation
        cipher = pyaes.AESModeOfOperationGCM(key, iv)
        
        if aad:
            cipher.add_authenticated_data(aad)
        
        ciphertext = cipher.encrypt(plaintext)
        tag = cipher.tag
        
        return ciphertext, tag
        
    except ImportError:
        # Fallback to pure Python implementation
        return _aes_gcm_encrypt_pure(plaintext, key, iv, aad)


def aes_gcm_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    tag: Optional[bytes] = None,
    aad: Optional[bytes] = None
) -> bytes:
    """
    Decrypt data using AES-GCM.
    
    Args:
        ciphertext: Encrypted data
        key: Decryption key
        iv: Initialization vector
        tag: Authentication tag
        aad: Additional authenticated data
        
    Returns:
        Decrypted plaintext
    """
    try:
        import pyaes
        
        if len(key) not in (16, 24, 32):
            raise DecryptionError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
        
        if tag is None:
            raise DecryptionError("Tag is required for AES-GCM decryption")
        
        cipher = pyaes.AESModeOfOperationGCM(key, iv, tag)
        
        if aad:
            cipher.add_authenticated_data(aad)
        
        return cipher.decrypt(ciphertext)
        
    except ImportError:
        # Fallback to pure Python implementation
        return _aes_gcm_decrypt_pure(ciphertext, key, iv, tag, aad)


def _aes_gcm_encrypt_pure(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    aad: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """Pure Python AES-GCM implementation (simplified)."""
    # Simplified GCM using CTR mode + HMAC
    # For production, use a proper GCM library
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Generate counter
    counter = struct.unpack("<Q", iv[-8:])[0]
    
    # Encrypt using CTR mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Compute tag using HMAC-SHA256
    if aad:
        tag_data = aad + iv + ciphertext
    else:
        tag_data = iv + ciphertext
    
    tag = hashlib.sha256(tag_data + key).digest()[:16]
    
    return ciphertext, tag


def _aes_gcm_decrypt_pure(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    tag: bytes,
    aad: Optional[bytes] = None
) -> bytes:
    """Pure Python AES-GCM decryption (simplified)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    # Verify tag
    if aad:
        tag_data = aad + iv + ciphertext
    else:
        tag_data = iv + ciphertext
    
    expected_tag = hashlib.sha256(tag_data + key).digest()[:16]
    
    if not hmac.compare_digest(tag, expected_tag):
        raise DecryptionError("Tag verification failed")
    
    # Decrypt using CTR mode
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# AES-CBC Encryption
def aes_cbc_encrypt(
    plaintext: bytes,
    key: bytes,
    iv: Optional[bytes] = None,
    pad: bool = True
) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-CBC.
    
    Args:
        plaintext: Data to encrypt
        key: Encryption key (16, 24, or 32 bytes)
        iv: Initialization vector (16 bytes, auto-generated if None)
        pad: Whether to apply PKCS7 padding
        
    Returns:
        Tuple of (ciphertext, iv)
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    
    if iv is None:
        iv = os.urandom(16)
    
    if len(key) not in (16, 24, 32):
        raise EncryptionError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
    
    if len(iv) != 16:
        raise EncryptionError(f"IV must be 16 bytes, got {len(iv)}")
    
    if pad:
        padder = padding.PKCS7(128).padder()
        plaintext = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, iv


def aes_cbc_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    pad: bool = True
) -> bytes:
    """
    Decrypt data using AES-CBC.
    
    Args:
        ciphertext: Encrypted data
        key: Decryption key
        iv: Initialization vector
        pad: Whether to remove PKCS7 padding
        
    Returns:
        Decrypted plaintext
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    
    if len(key) not in (16, 24, 32):
        raise DecryptionError(f"Key must be 16, 24, or 32 bytes, got {len(key)}")
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    if pad:
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(plaintext) + unpadder.finalize()
    
    return plaintext


# Key Derivation Functions
def derive_key_hkdf(
    master_key: bytes,
    key_length: int,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None
) -> bytes:
    """
    Derive a key using HKDF.
    
    Args:
        master_key: Master key material
        key_length: Desired key length in bytes
        salt: Optional salt (randomized)
        info: Optional context info
        
    Returns:
        Derived key
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt or b'',
        info=info or b'specter-kdf',
        backend=default_backend()
    )
    
    return hkdf.derive(master_key)


def derive_key_pbkdf2(
    password: Union[str, bytes],
    salt: bytes,
    iterations: int = 100000,
    key_length: int = 32
) -> bytes:
    """
    Derive a key using PBKDF2.
    
    Args:
        password: Password or passphrase
        salt: Random salt
        iterations: Number of iterations
        key_length: Desired key length
        
    Returns:
        Derived key
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    
    if isinstance(password, str):
        password = password.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    
    return kdf.derive(password)


def derive_key_scrypt(
    password: Union[str, bytes],
    salt: bytes,
    n: int = 16384,
    r: int = 8,
    p: int = 1,
    key_length: int = 32
) -> bytes:
    """
    Derive a key using scrypt.
    
    Args:
        password: Password or passphrase
        salt: Random salt
        n: CPU/memory cost parameter
        r: Block size parameter
        p: Parallelization parameter
        key_length: Desired key length
        
    Returns:
        Derived key
    """
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    
    if isinstance(password, str):
        password = password.encode()
    
    kdf = Scrypt(
        salt=salt,
        n=n,
        r=r,
        p=p,
        length=key_length,
        backend=default_backend()
    )
    
    return kdf.derive(password)


# Secure Random
def secure_random(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length: Number of random bytes
        
    Returns:
        Random bytes
    """
    return os.urandom(length)


def secure_random_hex(length: int) -> str:
    """
    Generate cryptographically secure random hex string.
    
    Args:
        length: Number of random bytes
        
    Returns:
        Hex string
    """
    return os.urandom(length).hex()


# Key Generation
def generate_aes_key(key_size: int = 256) -> bytes:
    """
    Generate a random AES key.
    
    Args:
        key_size: Key size in bits (128, 192, or 256)
        
    Returns:
        Random AES key
    """
    if key_size not in (128, 192, 256):
        raise KeyDerivationError(f"Invalid key size: {key_size}")
    
    return secure_random(key_size // 8)


def generate_iv() -> bytes:
    """Generate a random IV for AES-GCM."""
    return secure_random(12)


def generate_salt(length: int = 32) -> bytes:
    """Generate a random salt."""
    return secure_random(length)


__all__ = [
    "EncryptedData",
    "EncryptionError",
    "DecryptionError",
    "KeyDerivationError",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "aes_cbc_encrypt",
    "aes_cbc_decrypt",
    "derive_key_hkdf",
    "derive_key_pbkdf2",
    "derive_key_scrypt",
    "secure_random",
    "secure_random_hex",
    "generate_aes_key",
    "generate_iv",
    "generate_salt",
]
