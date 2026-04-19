"""
Specter TEE Base Module
=======================
Abstract interface for Trusted Execution Environments.
Provides unified API for Intel SGX and AMD SEV.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import hashlib
import struct


class TEEType(Enum):
    """Supported TEE types."""
    INTEL_SGX = "intel_sgx"
    AMD_SEV = "amd_sev"
    ARM_TRUSTZONE = "arm_trustzone"
    NONE = "none"  # For testing/development


class QuoteType(Enum):
    """Attestation quote types."""
    SGX_EPID = "sgx_epid"
    SGX_ECDSA = "sgx_ecdsa"
    SEV_SNP = "sev_snp"


@dataclass
class TEEInfo:
    """Information about the TEE environment."""
    tee_type: TEEType
    version: str
    capabilities: List[str]
    mr_enclave: Optional[bytes] = None
    mr_signer: Optional[bytes] = None
    product_id: Optional[int] = None
    security_version: Optional[int] = None
    is_debug_enabled: bool = False
    is_production: bool = False


@dataclass
class AttestationEvidence:
    """Attestation evidence from TEE."""
    quote: bytes
    quote_type: QuoteType
    report_data: bytes
    signature: bytes
    certificate_chain: List[bytes]
    timestamp: int
    raw_measurements: Dict[str, bytes]


@dataclass
class EnclaveIdentity:
    """Identity of an enclave."""
    mr_enclave: bytes
    mr_signer: bytes
    product_id: int
    security_version: int
    attributes: Dict[str, bool]


class TEEBase(ABC):
    """
    Abstract base class for Trusted Execution Environment implementations.
    
    This class defines the interface that all TEE implementations must follow.
    It provides methods for enclave lifecycle management, attestation,
    memory operations, and key derivation.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the TEE environment.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self._initialized = False
        self._enclave_handle = None
        self._tee_info: Optional[TEEInfo] = None
    
    @property
    @abstractmethod
    def tee_type(self) -> TEEType:
        """Return the type of TEE."""
        pass
    
    @abstractmethod
    def initialize(self) -> bool:
        """
        Initialize the TEE environment.
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    def shutdown(self) -> bool:
        """
        Shutdown the TEE environment.
        
        Returns:
            True if shutdown successful, False otherwise
        """
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if TEE is available on this platform.
        
        Returns:
            True if TEE is available, False otherwise
        """
        pass
    
    @abstractmethod
    def get_tee_info(self) -> TEEInfo:
        """
        Get information about the TEE environment.
        
        Returns:
            TEEInfo object with platform details
        """
        pass
    
    @abstractmethod
    def create_enclave(
        self,
        enclave_path: str,
        input_params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Create and initialize an enclave.
        
        Args:
            enclave_path: Path to the enclave binary
            input_params: Optional parameters for enclave initialization
            
        Returns:
            Enclave handle or context
        """
        pass
    
    @abstractmethod
    def destroy_enclave(self, enclave_handle: Any) -> bool:
        """
        Destroy an enclave.
        
        Args:
            enclave_handle: Handle to the enclave to destroy
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def generate_attestation_evidence(
        self,
        report_data: bytes,
        enclave_handle: Optional[Any] = None
    ) -> AttestationEvidence:
        """
        Generate attestation evidence for an enclave.
        
        Args:
            report_data: Data to include in the attestation report
            enclave_handle: Optional enclave handle (uses self if not provided)
            
        Returns:
            AttestationEvidence containing the quote and supporting data
        """
        pass
    
    @abstractmethod
    def verify_attestation_evidence(
        self,
        evidence: AttestationEvidence,
        expected_mrenclave: Optional[bytes] = None,
        expected_mrsigner: Optional[bytes] = None,
        expected_product_id: Optional[int] = None,
        expected_security_version: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Verify attestation evidence.
        
        Args:
            evidence: AttestationEvidence to verify
            expected_mrenclave: Expected enclave measurement
            expected_mrsigner: Expected signer measurement
            expected_product_id: Expected product ID
            expected_security_version: Expected security version
            
        Returns:
            Tuple of (is_valid, reason)
        """
        pass
    
    @abstractmethod
    def encrypt_in_enclave(
        self,
        plaintext: bytes,
        key: bytes,
        enclave_handle: Optional[Any] = None
    ) -> bytes:
        """
        Encrypt data within the enclave.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key
            enclave_handle: Optional enclave handle
            
        Returns:
            Encrypted data
        """
        pass
    
    @abstractmethod
    def decrypt_in_enclave(
        self,
        ciphertext: bytes,
        key: bytes,
        enclave_handle: Optional[Any] = None
    ) -> bytes:
        """
        Decrypt data within the enclave.
        
        Args:
            ciphertext: Data to decrypt
            key: Decryption key
            enclave_handle: Optional enclave handle
            
        Returns:
            Decrypted data
        """
        pass
    
    @abstractmethod
    def derive_key(
        self,
        master_key: bytes,
        key_type: str,
        context: Optional[bytes] = None
    ) -> bytes:
        """
        Derive a key within the enclave.
        
        Args:
            master_key: Master key for derivation
            key_type: Type of key to derive
            context: Optional context for derivation
            
        Returns:
            Derived key
        """
        pass
    
    def ocall(self, function_id: int, input_data: bytes) -> bytes:
        """
        Make an outside call (OCALL) from the enclave.
        
        Args:
            function_id: ID of the function to call
            input_data: Input data for the call
            
        Returns:
            Output data from the call
        """
        raise NotImplementedError("OCALLs must be implemented by subclass")
    
    def ecall(self, function_id: int, input_data: bytes) -> bytes:
        """
        Make an enclave call (ECALL) into the enclave.
        
        Args:
            function_id: ID of the function to call
            input_data: Input data for the call
            
        Returns:
            Output data from the call
        """
        raise NotImplementedError("ECALLs must be implemented by subclass")


class MemoryRegion:
    """Represents a memory region within an enclave."""
    
    def __init__(self, address: int, size: int, permissions: int = 0x7):  # RWX default
        self.address = address
        self.size = size
        self.permissions = permissions  # Read=4, Write=2, Execute=1
    
    def __repr__(self) -> str:
        return f"MemoryRegion(addr=0x{self.address:x}, size={self.size}, perms={self.permissions})"


class EnclaveContext:
    """Context for an active enclave."""
    
    def __init__(
        self,
        handle: Any,
        tee_type: TEEType,
        memory_regions: List[MemoryRegion],
        entry_points: Dict[str, int],
        identity: Optional[EnclaveIdentity] = None
    ):
        self.handle = handle
        self.tee_type = tee_type
        self.memory_regions = memory_regions
        self.entry_points = entry_points
        self.identity = identity
        self.is_initialized = False
        self.is_debug_mode = False
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass  # Cleanup handled by TEE implementation


def calculate_hash(data: bytes, algorithm: str = "sha256") -> bytes:
    """
    Calculate hash of data.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm to use
        
    Returns:
        Hash digest
    """
    if algorithm == "sha256":
        return hashlib.sha256(data).digest()
    elif algorithm == "sha384":
        return hashlib.sha384(data).digest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str.replace(" ", "").replace("0x", ""))


def bytes_to_hex(data: bytes, prefix: str = "0x", separator: str = "") -> str:
    """Convert bytes to hex string."""
    hex_str = data.hex()
    if separator:
        chunks = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
        return prefix + separator.join(chunks)
    return prefix + hex_str
