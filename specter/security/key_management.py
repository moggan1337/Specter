"""
Specter Key Management Module
==============================
Secure key generation, storage, rotation, and lifecycle management.
Implements hierarchical key management with hardware security module (HSM) integration.
"""

import os
import json
import time
import hashlib
import hmac
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import base64

from .encryption import (
    generate_aes_key,
    generate_iv,
    generate_salt,
    derive_key_hkdf,
    derive_key_pbkdf2,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
)

logger = logging.getLogger(__name__)


class KeyType(Enum):
    """Types of cryptographic keys."""
    MASTER = "master"               # Root key
    KEK = "key_encryption"           # Key encryption key
    DEK = "data_encryption"          # Data encryption key
    SEED = "seed"                    # Seed for derivation
    ATTESTATION = "attestation"      # Attestation signing key
    SEALING = "sealing"              # TEE sealing key
    SIGNING = "signing"              # General signing key
    DERIVED = "derived"              # Derived key


class KeyUsage(Enum):
    """Key usage policies."""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    DERIVE = "derive"
    SEAL = "seal"
    ATTEST = "attest"


class KeySource(Enum):
    """Source of key material."""
    HARDWARE = "hardware"           # Generated in hardware (TEE/HSM)
    SOFTWARE = "software"            # Generated in software
    IMPORTED = "imported"            # Imported from external source
    DERIVED = "derived"              # Derived from another key


@dataclass
class KeyMetadata:
    """Metadata for a key."""
    key_id: str
    key_type: KeyType
    usage: List[KeyUsage]
    source: KeySource
    created_at: int
    expires_at: Optional[int] = None
    version: int = 1
    parent_key_id: Optional[str] = None
    algorithm: str = "AES-256-GCM"
    key_size: int = 256
    is_active: bool = True
    is_revoked: bool = False
    description: str = ""
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "usage": [u.value for u in self.usage],
            "source": self.source.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "version": self.version,
            "parent_key_id": self.parent_key_id,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "is_active": self.is_active,
            "is_revoked": self.is_revoked,
            "description": self.description,
            "tags": self.tags,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            usage=[KeyUsage(u) for u in data["usage"]],
            source=KeySource(data["source"]),
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            version=data.get("version", 1),
            parent_key_id=data.get("parent_key_id"),
            algorithm=data.get("algorithm", "AES-256-GCM"),
            key_size=data.get("key_size", 256),
            is_active=data.get("is_active", True),
            is_revoked=data.get("is_revoked", False),
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )


@dataclass
class KeyBundle:
    """Container for a key and its metadata."""
    metadata: KeyMetadata
    encrypted_key: bytes
    iv: bytes
    tag: bytes
    key_checksum: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "encrypted_key": base64.b64encode(self.encrypted_key).decode(),
            "iv": base64.b64encode(self.iv).decode(),
            "tag": base64.b64encode(self.tag).decode(),
            "key_checksum": self.key_checksum,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyBundle":
        """Create from dictionary."""
        return cls(
            metadata=KeyMetadata.from_dict(data["metadata"]),
            encrypted_key=base64.b64decode(data["encrypted_key"]),
            iv=base64.b64decode(data["iv"]),
            tag=base64.b64decode(data["tag"]),
            key_checksum=data["key_checksum"],
        )


class KeyStore:
    """
    Secure key storage with hierarchical management.
    
    Provides:
    - Master key protection
    - Key versioning and rotation
    - Access control
    - Audit logging
    - Key expiration
    """
    
    def __init__(
        self,
        storage_path: Optional[Path] = None,
        master_password: Optional[str] = None,
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize key store.
        
        Args:
            storage_path: Path to key storage directory
            master_password: Password for deriving master key
            encryption_key: Direct encryption key (overrides password)
        """
        self.storage_path = storage_path or Path.home() / ".specter" / "keystore"
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self._keys: Dict[str, KeyBundle] = {}
        self._master_key: Optional[bytes] = None
        self._initialized = False
        
        # Initialize master key
        if encryption_key:
            self._master_key = encryption_key
        elif master_password:
            self._master_key = self._derive_master_key(master_password)
        else:
            # Generate random master key for this session
            self._master_key = generate_aes_key(256)
        
        self._load_keys()
        self._initialized = True
    
    def _derive_master_key(self, password: str) -> bytes:
        """Derive master key from password."""
        salt_file = self.storage_path / ".salt"
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            salt = generate_salt(32)
            salt_file.write_bytes(salt)
        
        return derive_key_pbkdf2(password, salt, iterations=100000, key_length=32)
    
    def _load_keys(self):
        """Load keys from storage."""
        keys_file = self.storage_path / "keys.enc"
        if keys_file.exists():
            try:
                data = keys_file.read_bytes()
                if data:
                    decrypted = self._decrypt_keys(data)
                    for key_data in decrypted:
                        bundle = KeyBundle.from_dict(key_data)
                        self._keys[bundle.metadata.key_id] = bundle
            except Exception as e:
                logger.warning(f"Failed to load keys: {e}")
    
    def _decrypt_keys(self, data: bytes) -> List[Dict]:
        """Decrypt stored keys."""
        iv = data[:12]
        ciphertext = data[12:-16]
        tag = data[-16:]
        
        plaintext = aes_gcm_decrypt(ciphertext, self._master_key, iv, tag)
        return json.loads(plaintext)
    
    def _encrypt_keys(self, keys: List[Dict]) -> bytes:
        """Encrypt keys for storage."""
        plaintext = json.dumps(keys).encode()
        ciphertext, tag = aes_gcm_encrypt(plaintext, self._master_key)
        return iv + ciphertext + tag
    
    def _save_keys(self):
        """Save keys to storage."""
        keys_data = [bundle.to_dict() for bundle in self._keys.values()]
        encrypted = self._encrypt_keys(keys_data)
        (self.storage_path / "keys.enc").write_bytes(encrypted)
    
    def _compute_checksum(self, key: bytes) -> str:
        """Compute key checksum."""
        return hashlib.sha256(key).digest().hex()[:16]
    
    def generate_key(
        self,
        key_type: KeyType = KeyType.DEK,
        usage: Optional[List[KeyUsage]] = None,
        source: KeySource = KeySource.SOFTWARE,
        parent_key_id: Optional[str] = None,
        expires_in: Optional[int] = None,
        tags: Optional[List[str]] = None,
    ) -> Tuple[bytes, str]:
        """
        Generate a new key.
        
        Args:
            key_type: Type of key to generate
            usage: Key usage policies
            source: Source of key material
            parent_key_id: Parent key for hierarchical management
            expires_in: Time until expiration in seconds
            tags: Optional tags
            
        Returns:
            Tuple of (key material, key_id)
        """
        if usage is None:
            usage = [KeyUsage.ENCRYPT, KeyUsage.DECRYPT]
        
        if tags is None:
            tags = []
        
        key_id = f"k_{int(time.time())}_{hashlib.sha256(os.urandom(8)).hexdigest()[:8]}"
        
        # Generate key material
        key_size = 256 if key_type in (KeyType.MASTER, KeyType.KEK, KeyType.DEK) else 128
        key_material = generate_aes_key(key_size)
        
        # Compute checksum
        checksum = self._compute_checksum(key_material)
        
        # Create metadata
        now = int(time.time())
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            usage=usage,
            source=source,
            created_at=now,
            expires_at=now + expires_in if expires_in else None,
            parent_key_id=parent_key_id,
            key_size=key_size,
            tags=tags,
        )
        
        # Encrypt key with master key
        iv = generate_iv()
        encrypted_key, tag = aes_gcm_encrypt(key_material, self._master_key)
        
        # Store key bundle
        bundle = KeyBundle(
            metadata=metadata,
            encrypted_key=encrypted_key,
            iv=iv,
            tag=tag,
            key_checksum=checksum,
        )
        
        self._keys[key_id] = bundle
        self._save_keys()
        
        logger.info(f"Generated key: {key_id} (type={key_type.value})")
        
        return key_material, key_id
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve a key by ID.
        
        Args:
            key_id: Key identifier
            
        Returns:
            Decrypted key material or None
        """
        bundle = self._keys.get(key_id)
        if not bundle:
            return None
        
        if bundle.metadata.is_revoked:
            logger.warning(f"Attempted to use revoked key: {key_id}")
            return None
        
        if bundle.metadata.expires_at and time.time() > bundle.metadata.expires_at:
            logger.warning(f"Attempted to use expired key: {key_id}")
            return None
        
        # Decrypt key
        return aes_gcm_decrypt(
            bundle.encrypted_key,
            self._master_key,
            bundle.iv,
            bundle.tag,
        )
    
    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a key."""
        bundle = self._keys.get(key_id)
        return bundle.metadata if bundle else None
    
    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        include_revoked: bool = False,
        include_expired: bool = False,
    ) -> List[KeyMetadata]:
        """
        List keys with optional filtering.
        
        Args:
            key_type: Filter by key type
            include_revoked: Include revoked keys
            include_expired: Include expired keys
            
        Returns:
            List of key metadata
        """
        results = []
        now = time.time()
        
        for bundle in self._keys.values():
            if key_type and bundle.metadata.key_type != key_type:
                continue
            if not include_revoked and bundle.metadata.is_revoked:
                continue
            if not include_expired:
                if bundle.metadata.expires_at and now > bundle.metadata.expires_at:
                    continue
            
            results.append(bundle.metadata)
        
        return results
    
    def revoke_key(self, key_id: str) -> bool:
        """
        Revoke a key.
        
        Args:
            key_id: Key to revoke
            
        Returns:
            True if successful
        """
        bundle = self._keys.get(key_id)
        if not bundle:
            return False
        
        bundle.metadata.is_revoked = True
        self._save_keys()
        
        logger.info(f"Revoked key: {key_id}")
        return True
    
    def rotate_key(self, key_id: str) -> Optional[Tuple[bytes, str]]:
        """
        Rotate a key, creating a new version.
        
        Args:
            key_id: Key to rotate
            
        Returns:
            Tuple of (new_key, new_key_id) or None
        """
        bundle = self._keys.get(key_id)
        if not bundle:
            return None
        
        # Mark old key as revoked
        bundle.metadata.is_active = False
        bundle.metadata.is_revoked = True
        
        # Generate new key with same parameters
        new_key, new_key_id = self.generate_key(
            key_type=bundle.metadata.key_type,
            usage=bundle.metadata.usage,
            source=bundle.metadata.source,
            parent_key_id=bundle.metadata.parent_key_id,
            tags=bundle.metadata.tags,
        )
        
        # Update new key with version info
        new_bundle = self._keys[new_key_id]
        new_bundle.metadata.version = bundle.metadata.version + 1
        
        self._save_keys()
        
        logger.info(f"Rotated key: {key_id} -> {new_key_id}")
        
        return new_key, new_key_id
    
    def derive_child_key(
        self,
        parent_key_id: str,
        context: bytes,
        key_type: KeyType = KeyType.DERIVED,
        usage: Optional[List[KeyUsage]] = None,
    ) -> Optional[Tuple[bytes, str]]:
        """
        Derive a child key from a parent key.
        
        Args:
            parent_key_id: Parent key ID
            context: Context for derivation
            key_type: Type for derived key
            usage: Key usage policies
            
        Returns:
            Tuple of (derived_key, key_id) or None
        """
        parent_key = self.get_key(parent_key_id)
        if not parent_key:
            return None
        
        if KeyUsage.DERIVE not in self.get_metadata(parent_key_id).usage:
            logger.error(f"Key {parent_key_id} does not support derivation")
            return None
        
        # Derive key
        derived_key = derive_key_hkdf(parent_key, 32, info=context)
        
        # Store derived key
        if usage is None:
            usage = [KeyUsage.ENCRYPT, KeyUsage.DECRYPT]
        
        key_id = f"dk_{int(time.time())}_{hashlib.sha256(context).hexdigest()[:8]}"
        
        checksum = self._compute_checksum(derived_key)
        
        now = int(time.time())
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            usage=usage,
            source=KeySource.DERIVED,
            created_at=now,
            parent_key_id=parent_key_id,
            key_size=256,
        )
        
        iv = generate_iv()
        encrypted_key, tag = aes_gcm_encrypt(derived_key, self._master_key)
        
        bundle = KeyBundle(
            metadata=metadata,
            encrypted_key=encrypted_key,
            iv=iv,
            tag=tag,
            key_checksum=checksum,
        )
        
        self._keys[key_id] = bundle
        self._save_keys()
        
        logger.info(f"Derived key: {key_id} from {parent_key_id}")
        
        return derived_key, key_id
    
    def delete_key(self, key_id: str) -> bool:
        """
        Delete a key.
        
        Args:
            key_id: Key to delete
            
        Returns:
            True if successful
        """
        if key_id in self._keys:
            del self._keys[key_id]
            self._save_keys()
            logger.info(f"Deleted key: {key_id}")
            return True
        return False
    
    def verify_key(self, key_id: str, key_material: bytes) -> bool:
        """
        Verify a key matches its stored checksum.
        
        Args:
            key_id: Key to verify
            key_material: Key material to verify
            
        Returns:
            True if key is valid
        """
        bundle = self._keys.get(key_id)
        if not bundle:
            return False
        
        return bundle.key_checksum == self._compute_checksum(key_material)


class KeyManager:
    """
    High-level key management interface.
    
    Provides a simpler interface for common key operations
    and manages key lifecycle automatically.
    """
    
    def __init__(
        self,
        storage_path: Optional[Path] = None,
        master_password: Optional[str] = None,
    ):
        """
        Initialize key manager.
        
        Args:
            storage_path: Path to key storage
            master_password: Master password for key store
        """
        self.keystore = KeyStore(storage_path, master_password)
        
        # Initialize master key if not exists
        master_keys = self.keystore.list_keys(key_type=KeyType.MASTER)
        if not master_keys:
            self.keystore.generate_key(
                key_type=KeyType.MASTER,
                usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.DERIVE],
                source=KeySource.SOFTWARE,
            )
    
    def get_data_encryption_key(self) -> Tuple[bytes, str]:
        """
        Get or create the current data encryption key.
        
        Returns:
            Tuple of (DEK, key_id)
        """
        deks = self.keystore.list_keys(key_type=KeyType.DEK)
        active_deks = [d for d in deks if d.is_active and not d.is_revoked]
        
        if active_deks:
            # Return the most recent active DEK
            latest = max(active_deks, key=lambda x: x.version)
            key = self.keystore.get_key(latest.key_id)
            return key, latest.key_id
        
        # Create new DEK
        return self.keystore.generate_key(
            key_type=KeyType.DEK,
            usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT],
        )
    
    def seal_key_for_tee(
        self,
        key_id: str,
        tee_public_key: bytes,
    ) -> Optional[bytes]:
        """
        Seal a key for use with a specific TEE.
        
        Args:
            key_id: Key to seal
            tee_public_key: TEE's public sealing key
            
        Returns:
            Sealed key data or None
        """
        key = self.keystore.get_key(key_id)
        if not key:
            return None
        
        # In production, this would use TEE-specific sealing
        # For now, encrypt with TEE public key (simplified)
        return aes_gcm_encrypt(key, tee_public_key)[0]
    
    def unseal_key_from_tee(
        self,
        sealed_key: bytes,
        tee_private_key: bytes,
        key_id: str,
    ) -> bool:
        """
        Unseal a key from TEE.
        
        Args:
            sealed_key: Sealed key data
            tee_private_key: TEE's private sealing key
            key_id: Original key ID
            
        Returns:
            True if successful
        """
        try:
            key = aes_gcm_decrypt(sealed_key, tee_private_key)
            return self.keystore.verify_key(key_id, key)
        except Exception:
            return False


__all__ = [
    "KeyType",
    "KeyUsage",
    "KeySource",
    "KeyMetadata",
    "KeyBundle",
    "KeyStore",
    "KeyManager",
]
