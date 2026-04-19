"""
Specter Security Package
========================
Security primitives for confidential computing.
"""

from .encryption import (
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
    EncryptedData,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    derive_key_hkdf,
    derive_key_pbkdf2,
    derive_key_scrypt,
    secure_random,
    secure_random_hex,
    generate_aes_key,
    generate_iv,
    generate_salt,
)

from .key_management import (
    KeyType,
    KeyUsage,
    KeySource,
    KeyMetadata,
    KeyBundle,
    KeyStore,
    KeyManager,
)

from .attestation import (
    AttestationStatus,
    AttestationReport,
    AttestationVerifier,
    TrustPolicy,
    VerificationError,
    verify_with_intel_dcap,
    verify_with_azure_attestation,
)


class SecureEnclave:
    """
    High-level secure enclave interface.
    
    Combines TEE, encryption, key management, and attestation
    into a single, easy-to-use interface.
    """
    
    def __init__(
        self,
        tee_type: str = "auto",
        tee_config: dict = None,
        master_password: str = None,
    ):
        """
        Initialize secure enclave.
        
        Args:
            tee_type: TEE type ("sgx", "sev", "auto", "none")
            tee_config: TEE configuration
            master_password: Password for key storage
        """
        from specter.tee import create_tee
        
        self.tee = create_tee(tee_type, tee_config or {})
        self.tee.initialize()
        
        self.key_manager = KeyManager(master_password=master_password)
        self.attestation_verifier = AttestationVerifier()
        
        self._enclave_context = None
        self._initialized = False
    
    def create_enclave(
        self,
        enclave_path: str,
        expected_identity: dict = None,
    ) -> bool:
        """
        Create and attest an enclave.
        
        Args:
            enclave_path: Path to enclave binary
            expected_identity: Expected enclave identity for verification
            
        Returns:
            True if successful
        """
        try:
            # Create enclave
            self._enclave_context = self.tee.create_enclave(enclave_path)
            
            # Generate attestation
            report_data = b"enclave_attestation_" + os.urandom(32)
            evidence = self.tee.generate_attestation_evidence(
                report_data,
                self._enclave_context.handle,
            )
            
            # Verify attestation
            if expected_identity:
                verification = self.attestation_verifier.verify_attestation(
                    evidence,
                    expected_identity,
                )
                if not verification.is_valid():
                    raise VerificationError(
                        f"Attestation failed: {verification.errors}"
                    )
            
            self._initialized = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to create enclave: {e}")
            return False
    
    def encrypt_model_weights(
        self,
        weights: bytes,
        key: bytes = None,
    ) -> Tuple[bytes, str]:
        """
        Encrypt model weights.
        
        Args:
            weights: Model weight data
            key: Optional encryption key
            
        Returns:
            Tuple of (encrypted_weights, key_id)
        """
        if key is None:
            key, key_id = self.key_manager.get_data_encryption_key()
        else:
            key_id = "user_provided"
        
        return self.tee.encrypt_in_enclave(weights, key), key_id
    
    def decrypt_model_weights(
        self,
        encrypted_weights: bytes,
        key_id: str,
    ) -> bytes:
        """
        Decrypt model weights.
        
        Args:
            encrypted_weights: Encrypted weight data
            key_id: Key ID used for encryption
            
        Returns:
            Decrypted weights
        """
        key = self.key_manager.keystore.get_key(key_id)
        if not key:
            raise KeyError(f"Key not found: {key_id}")
        
        return self.tee.decrypt_in_enclave(encrypted_weights, key)
    
    def seal_data(
        self,
        data: bytes,
        target_identity: dict = None,
    ) -> bytes:
        """
        Seal data for storage.
        
        Args:
            data: Data to seal
            target_identity: Optional target enclave identity
            
        Returns:
            Sealed data
        """
        key, key_id = self.key_manager.get_data_encryption_key()
        
        sealed = self.tee.encrypt_in_enclave(data, key)
        
        # Add key binding if target identity specified
        if target_identity:
            # In production, bind to specific enclave identity
            pass
        
        return sealed
    
    def unseal_data(self, sealed_data: bytes) -> bytes:
        """Unseal data."""
        key, key_id = self.key_manager.get_data_encryption_key()
        return self.tee.decrypt_in_enclave(sealed_data, key)
    
    def shutdown(self):
        """Shutdown the secure enclave."""
        if self._enclave_context:
            self.tee.destroy_enclave(self._enclave_context.handle)
        self.tee.shutdown()


import os
import logging
from typing import Tuple

logger = logging.getLogger(__name__)


__all__ = [
    # Encryption
    "EncryptionError",
    "DecryptionError",
    "KeyDerivationError",
    "EncryptedData",
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
    # Key Management
    "KeyType",
    "KeyUsage",
    "KeySource",
    "KeyMetadata",
    "KeyBundle",
    "KeyStore",
    "KeyManager",
    # Attestation
    "AttestationStatus",
    "AttestationReport",
    "AttestationVerifier",
    "TrustPolicy",
    "VerificationError",
    "verify_with_intel_dcap",
    "verify_with_azure_attestation",
    # High-level interface
    "SecureEnclave",
]
