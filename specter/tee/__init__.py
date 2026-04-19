"""
Specter TEE Package
===================
Trusted Execution Environment implementations.
"""

from .base import (
    TEEType,
    TEEBase,
    TEEInfo,
    AttestationEvidence,
    EnclaveIdentity,
    EnclaveContext,
    MemoryRegion,
    QuoteType,
    calculate_hash,
    bytes_to_hex,
    hex_to_bytes,
)

from .sgx import IntelSGX, get_sgx_instance
from .sev import AMDSEV, get_sev_instance, SEVPolicy, SEVVMContext

# Try to import hardware-specific modules
try:
    from .sgx import SGXError, SGXNotAvailableError, EnclaveLoadError, AttestationError as SGXAttestationError
except ImportError:
    SGXError = Exception
    SGXNotAvailableError = Exception
    EnclaveLoadError = Exception
    SGXAttestationError = Exception

try:
    from .sev import SEVError, SEVNotAvailableError, VMCreateError, AttestationError as SEVAttestationError
except ImportError:
    SEVError = Exception
    SEVNotAvailableError = Exception
    VMCreateError = Exception
    SEVAttestationError = Exception


def create_tee(
    tee_type: str = "auto",
    config: dict = None
) -> TEEBase:
    """
    Create a TEE instance based on the specified type or auto-detect.
    
    Args:
        tee_type: Type of TEE ("sgx", "sev", "auto", "none")
        config: Optional configuration dictionary
        
    Returns:
        TEEBase implementation instance
        
    Raises:
        ValueError: If specified TEE type is not available
    """
    config = config or {}
    
    if tee_type == "auto":
        # Try to detect available TEE
        if _is_sgx_available():
            return IntelSGX(config)
        elif _is_sev_available():
            return AMDSEV(config)
        else:
            # Return a no-op TEE for development
            return create_tee("none", config)
    
    elif tee_type == "sgx":
        if not _is_sgx_available() and not config.get("simulation_mode"):
            raise ValueError("Intel SGX not available on this platform")
        return IntelSGX(config)
    
    elif tee_type == "sev":
        if not _is_sev_available():
            raise ValueError("AMD SEV not available on this platform")
        return AMDSEV(config)
    
    elif tee_type == "none":
        return NoOpTEE(config)
    
    else:
        raise ValueError(f"Unknown TEE type: {tee_type}")


def _is_sgx_available() -> bool:
    """Check if Intel SGX is available."""
    try:
        sgx = IntelSGX()
        return sgx.is_available()
    except Exception:
        return False


def _is_sev_available() -> bool:
    """Check if AMD SEV is available."""
    try:
        sev = AMDSEV()
        return sev.is_available()
    except Exception:
        return False


class NoOpTEE(TEEBase):
    """
    No-operation TEE for development and testing.
    
    Provides the same interface as real TEE implementations
    but without any actual hardware security.
    """
    
    @property
    def tee_type(self) -> TEEType:
        return TEEType.NONE
    
    def initialize(self) -> bool:
        self._initialized = True
        self._tee_info = TEEInfo(
            tee_type=TEEType.NONE,
            version="1.0.0-noop",
            capabilities=["development", "testing"],
            is_debug_enabled=True,
            is_production=False,
        )
        return True
    
    def shutdown(self) -> bool:
        self._initialized = False
        return True
    
    def is_available(self) -> bool:
        return True
    
    def get_tee_info(self) -> TEEInfo:
        if not self._initialized:
            self.initialize()
        return self._tee_info
    
    def create_enclave(self, enclave_path: str, input_params: dict = None):
        return EnclaveContext(
            handle="noop_enclave",
            tee_type=TEEType.NONE,
            memory_regions=[],
            entry_points={},
        )
    
    def destroy_enclave(self, enclave_handle) -> bool:
        return True
    
    def generate_attestation_evidence(self, report_data: bytes, enclave_handle=None):
        import os
        import time
        return AttestationEvidence(
            quote=os.urandom(512),
            quote_type=QuoteType.SGX_ECDSA,
            report_data=report_data,
            signature=os.urandom(64),
            certificate_chain=[os.urandom(64)],
            timestamp=int(time.time()),
            raw_measurements={},
        )
    
    def verify_attestation_evidence(self, evidence, **kwargs):
        return True, "No-op TEE always verifies"
    
    def encrypt_in_enclave(self, plaintext: bytes, key: bytes, enclave_handle=None):
        from specter.security.encryption import aes_gcm_encrypt
        import os
        iv = os.urandom(12)
        ciphertext, tag = aes_gcm_encrypt(plaintext, key, iv)
        return iv + ciphertext + tag
    
    def decrypt_in_enclave(self, ciphertext: bytes, key: bytes, enclave_handle=None):
        from specter.security.encryption import aes_gcm_decrypt
        iv = ciphertext[:12]
        tag = ciphertext[-16:]
        return aes_gcm_decrypt(ciphertext[12:-16], key, iv, tag)
    
    def derive_key(self, master_key: bytes, key_type: str, context: bytes = None):
        import hashlib
        import hmac
        info = f"noop-{key_type}".encode() + (context or b'')
        return hmac.new(master_key, info, hashlib.sha256).digest()


__all__ = [
    # Base classes
    "TEEBase",
    "TEEType",
    "TEEInfo",
    "AttestationEvidence",
    "EnclaveIdentity",
    "EnclaveContext",
    "MemoryRegion",
    "QuoteType",
    # Implementations
    "IntelSGX",
    "AMDSEV",
    "SEVPolicy",
    "SEVVMContext",
    "NoOpTEE",
    # Factory functions
    "create_tee",
    "get_sgx_instance",
    "get_sev_instance",
    # Utilities
    "calculate_hash",
    "bytes_to_hex",
    "hex_to_bytes",
    # Exceptions
    "SGXError",
    "SGXNotAvailableError",
    "EnclaveLoadError",
    "SGXAttestationError",
    "SEVError",
    "SEVNotAvailableError",
    "VMCreateError",
    "SEVAttestationError",
]
