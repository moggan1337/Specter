"""
Specter - Confidential Computing AI Framework
==============================================

A comprehensive framework for running AI/ML workloads in Trusted Execution
Environments (TEEs) like Intel SGX and AMD SEV.

Features:
- Hardware-backed security for AI models
- Encrypted model weights at rest and in transit
- Remote attestation for verifiability
- Privacy-preserving machine learning
- Federated learning primitives

Quick Start:
    >>> from specter import Specter
    >>> specter = Specter(tee_type="sgx")
    >>> specter.initialize()
    >>> # Encrypt and run models securely
"""

__version__ = "1.0.0"
__author__ = "Specter Team"
__license__ = "MIT"

import logging
from typing import Optional, Dict, Any

# Import core modules
from .tee import create_tee, TEEType, TEEBase, TEEInfo, AttestationEvidence
from .security import (
    KeyManager,
    KeyStore,
    AttestationVerifier,
    AttestationReport,
    SecureEnclave,
    # Encryption
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    generate_aes_key,
    # Key derivation
    derive_key_hkdf,
    derive_key_pbkdf2,
)
from .ml import (
    SecureModelWrapper,
    FederatedLearningCoordinator,
    PrivacyPreservingAnalysis,
    EncryptedModel,
    InferenceRequest,
    InferenceResponse,
)
from .api import SpecterClient, create_client
from .utils import (
    SpecterConfig,
    setup_logging,
    get_system_info,
    SpecterError,
)


logger = logging.getLogger(__name__)


class Specter:
    """
    Main Specter framework interface.
    
    Provides a unified API for confidential computing with AI/ML workloads.
    
    Example:
        >>> specter = Specter(tee_type="auto")
        >>> specter.initialize()
        >>> # Create secure enclave and run inference
        >>> specter.shutdown()
    """
    
    def __init__(
        self,
        tee_type: str = "auto",
        config: Optional[Dict[str, Any]] = None,
        master_password: Optional[str] = None,
        log_level: str = "INFO",
    ):
        """
        Initialize Specter framework.
        
        Args:
            tee_type: TEE type ("sgx", "sev", "auto", "none")
            config: Optional configuration dictionary
            master_password: Optional master password for key storage
            log_level: Logging level
        """
        self.config = config or {}
        self._tee_type = tee_type
        self._initialized = False
        
        # Setup logging
        setup_logging(level=log_level)
        
        # Create TEE
        self._tee = create_tee(tee_type, self.config)
        
        # Create key manager
        self._key_manager = KeyManager(master_password=master_password)
        
        # Create secure model wrapper
        self._model_wrapper: Optional[SecureModelWrapper] = None
        
        # Create federated learning coordinator
        self._fl_coordinator: Optional[FederatedLearningCoordinator] = None
        
        # Create attestation verifier
        self._attestation_verifier = AttestationVerifier()
        
        logger.info(f"Specter initialized with TEE type: {tee_type}")
    
    def initialize(self) -> bool:
        """
        Initialize the Specter framework.
        
        Returns:
            True if initialization successful
        """
        if self._initialized:
            logger.warning("Specter already initialized")
            return True
        
        try:
            # Initialize TEE
            self._tee.initialize()
            
            # Create model wrapper
            self._model_wrapper = SecureModelWrapper(
                self._tee,
                self._key_manager,
            )
            
            # Create FL coordinator
            self._fl_coordinator = FederatedLearningCoordinator(
                self._tee,
                self._key_manager,
            )
            
            self._initialized = True
            logger.info("Specter framework initialized successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Specter: {e}")
            raise
    
    def shutdown(self):
        """Shutdown the Specter framework."""
        if not self._initialized:
            return
        
        self._tee.shutdown()
        self._initialized = False
        
        logger.info("Specter framework shutdown complete")
    
    @property
    def tee(self) -> TEEBase:
        """Get the TEE instance."""
        return self._tee
    
    @property
    def key_manager(self) -> KeyManager:
        """Get the key manager."""
        return self._key_manager
    
    @property
    def model_wrapper(self) -> SecureModelWrapper:
        """Get the secure model wrapper."""
        if not self._model_wrapper:
            raise RuntimeError("Framework not initialized")
        return self._model_wrapper
    
    @property
    def fl_coordinator(self) -> FederatedLearningCoordinator:
        """Get the federated learning coordinator."""
        if not self._fl_coordinator:
            raise RuntimeError("Framework not initialized")
        return self._fl_coordinator
    
    @property
    def attestation_verifier(self) -> AttestationVerifier:
        """Get the attestation verifier."""
        return self._attestation_verifier
    
    def create_secure_enclave(self, enclave_path: str) -> Any:
        """
        Create a secure enclave.
        
        Args:
            enclave_path: Path to enclave binary
            
        Returns:
            Enclave context
        """
        if not self._initialized:
            self.initialize()
        
        return self._tee.create_enclave(enclave_path)
    
    def encrypt_data(
        self,
        data: bytes,
        key_id: Optional[str] = None,
    ) -> tuple:
        """
        Encrypt data securely.
        
        Args:
            data: Data to encrypt
            key_id: Optional key ID
            
        Returns:
            Tuple of (encrypted_data, key_id)
        """
        if not self._initialized:
            self.initialize()
        
        key, used_key_id = self._key_manager.get_data_encryption_key()
        
        encrypted = self._tee.encrypt_in_enclave(data, key)
        
        return encrypted, used_key_id if key_id is None else key_id
    
    def decrypt_data(
        self,
        encrypted_data: bytes,
        key_id: str,
    ) -> bytes:
        """
        Decrypt data securely.
        
        Args:
            encrypted_data: Encrypted data
            key_id: Key ID
            
        Returns:
            Decrypted data
        """
        if not self._initialized:
            self.initialize()
        
        key = self._key_manager.keystore.get_key(key_id)
        if not key:
            raise KeyError(f"Key not found: {key_id}")
        
        return self._tee.decrypt_in_enclave(encrypted_data, key)
    
    def encrypt_model(
        self,
        model_id: str,
        weights: bytes,
        architecture: Dict[str, Any],
    ) -> EncryptedModel:
        """
        Encrypt and store a model.
        
        Args:
            model_id: Model identifier
            weights: Model weights
            architecture: Model architecture
            
        Returns:
            Encrypted model
        """
        if not self._initialized:
            self.initialize()
        
        return self._model_wrapper.encrypt_and_store_model(
            model_id=model_id,
            weights=weights,
            architecture=architecture,
        )
    
    def run_secure_inference(
        self,
        model_id: str,
        input_data: bytes,
        enclave_context: Any = None,
    ) -> InferenceResponse:
        """
        Run secure inference.
        
        Args:
            model_id: Model to use
            input_data: Input data
            enclave_context: Optional enclave context
            
        Returns:
            Inference response
        """
        if not self._initialized:
            self.initialize()
        
        return self._model_wrapper.run_inference(
            model_id=model_id,
            input_data=input_data,
            enclave_context=enclave_context,
        )
    
    def __enter__(self):
        """Context manager entry."""
        self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.shutdown()
        return False


# Convenience function
def create_specter(
    tee_type: str = "auto",
    **kwargs,
) -> Specter:
    """
    Create a Specter instance.
    
    Args:
        tee_type: TEE type
        **kwargs: Additional arguments for Specter
        
    Returns:
        Specter instance
    """
    return Specter(tee_type=tee_type, **kwargs)


# CLI entry point
def main():
    """CLI entry point."""
    from specter.api.cli import main as cli_main
    cli_main()


__all__ = [
    # Version
    "__version__",
    # Core
    "Specter",
    "create_specter",
    # TEE
    "create_tee",
    "TEEType",
    "TEEBase",
    "TEEInfo",
    "AttestationEvidence",
    # Security
    "KeyManager",
    "KeyStore",
    "AttestationVerifier",
    "AttestationReport",
    "SecureEnclave",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "generate_aes_key",
    "derive_key_hkdf",
    "derive_key_pbkdf2",
    # ML
    "SecureModelWrapper",
    "FederatedLearningCoordinator",
    "PrivacyPreservingAnalysis",
    "EncryptedModel",
    "InferenceRequest",
    "InferenceResponse",
    # API
    "SpecterClient",
    "create_client",
    # Utils
    "SpecterConfig",
    "setup_logging",
    "get_system_info",
    "SpecterError",
    # CLI
    "main",
]
