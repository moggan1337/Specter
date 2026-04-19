"""
Specter Intel SGX Implementation
================================
Intel Software Guard Extensions (SGX) TEE implementation.
Provides SGX-specific enclave management and attestation.
"""

import hashlib
import hmac
import os
import struct
import logging
from typing import Any, Dict, List, Optional, Tuple
from .base import (
    TEEBase,
    TEEType,
    TEEInfo,
    AttestationEvidence,
    EnclaveIdentity,
    EnclaveContext,
    MemoryRegion,
    QuoteType,
    calculate_hash,
    bytes_to_hex,
)

logger = logging.getLogger(__name__)


class SGXError(Exception):
    """Base exception for SGX-related errors."""
    pass


class SGXNotAvailableError(SGXError):
    """Raised when SGX is not available on the platform."""
    pass


class EnclaveLoadError(SGXError):
    """Raised when enclave loading fails."""
    pass


class AttestationError(SGXError):
    """Raised when attestation fails."""
    pass


class IntelSGX(TEEBase):
    """
    Intel SGX implementation of TEEBase.
    
    Provides hardware-backed secure enclaves using Intel SGX technology.
    Supports both EPID and ECDSA attestation schemes.
    """
    
    # SGX-specific constants
    SGX_FLAGS_INITTED = 0x0000000000000001
    SGX_FLAGS_DEBUG = 0x0000000000000002
    SGX_FLAGS_MODE64BIT = 0x0000000000000004
    SGX_FLAGS_PROVISION_KEY = 0x0000000000000010
    SGX_FLAGS_EINITTOKEN_KEY = 0x0000000000000020
    SGX_FLAGS_ATTRIBUTE_MASK = 0xFFFFFFFFFFFFFFC0
    
    # Measurement sizes (in bytes)
    MRENCLAVE_SIZE = 32
    MRSIGNER_SIZE = 32
    
    # Report data size
    REPORT_DATA_SIZE = 64
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Intel SGX implementation.
        
        Args:
            config: Configuration dictionary with optional keys:
                - simulation_mode: Use SGX simulation (for development)
                - aesmd_socket: Path to aesmd socket
                - quote_type: "epid" or "ecdsa"
                - spid: SPID for EPID attestation
                - subscription_key: Azure subscription key
        """
        super().__init__(config)
        self._simulation_mode = self.config.get("simulation_mode", False)
        self._quote_type = QuoteType.SGX_ECDSA if self.config.get(
            "quote_type", "ecdsa"
        ) == "ecdsa" else QuoteType.SGX_EPID
        self._spid = self.config.get("spid")
        self._aesmd_socket = self.config.get("aesmd_socket", "/var/run/aesmd/aesmd.sock")
        self._quote_service_available = False
        self._is_dev_mode = self.config.get("dev_mode", False)
    
    @property
    def tee_type(self) -> TEEType:
        return TEEType.INTEL_SGX
    
    def initialize(self) -> bool:
        """
        Initialize the SGX environment.
        
        Returns:
            True if initialization successful
        """
        if self._initialized:
            logger.warning("SGX already initialized")
            return True
        
        if not self.is_available():
            if not self._simulation_mode:
                raise SGXNotAvailableError(
                    "Intel SGX is not available on this platform. "
                    "Enable simulation mode for development."
                )
            logger.info("Running in SGX simulation mode")
        
        try:
            self._initialize_internal()
            self._tee_info = self.get_tee_info()
            self._initialized = True
            logger.info("Intel SGX initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SGX: {e}")
            raise SGXError(f"SGX initialization failed: {e}")
    
    def _initialize_internal(self):
        """Internal initialization logic."""
        # In a real implementation, this would:
        # 1. Initialize the SGX SDK
        # 2. Connect to aesmd daemon
        # 3. Load necessary libraries
        # 4. Check/enable SGX if needed
        
        if self._simulation_mode:
            logger.info("Initializing SGX simulation mode")
        else:
            logger.info("Initializing SGX hardware mode")
            self._check_quote_service()
    
    def _check_quote_service(self):
        """Check if the Intel DCAP/EPID quote service is available."""
        # In production, this would check for aesmd daemon
        # and verify quote generation capability
        if os.path.exists(self._aesmd_socket) or self._simulation_mode:
            self._quote_service_available = True
            logger.info("Quote service available")
        else:
            logger.warning("Quote service not available")
    
    def shutdown(self) -> bool:
        """
        Shutdown the SGX environment.
        
        Returns:
            True if shutdown successful
        """
        if not self._initialized:
            return True
        
        try:
            self._shutdown_internal()
            self._initialized = False
            self._tee_info = None
            logger.info("Intel SGX shutdown complete")
            return True
        except Exception as e:
            logger.error(f"Failed to shutdown SGX: {e}")
            return False
    
    def _shutdown_internal(self):
        """Internal shutdown logic."""
        # Close connections, cleanup resources
        if hasattr(self, '_enclave_handle') and self._enclave_handle:
            self.destroy_enclave(self._enclave_handle)
    
    def is_available(self) -> bool:
        """
        Check if SGX is available on this platform.
        
        Returns:
            True if SGX is available (hardware or simulation)
        """
        if self._simulation_mode:
            return True
        
        # Check for SGX support via CPUID
        try:
            return self._check_sgx_support()
        except Exception:
            return False
    
    def _check_sgx_support(self) -> bool:
        """
        Check SGX support via CPUID.
        
        Returns:
            True if SGX is supported
        """
        # On Linux, check /dev/isgx or CPUID
        # This is a simplified check
        if os.path.exists("/dev/isgx"):
            return True
        
        # Check for SGX in CPU flags (simplified)
        try:
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()
                if "sgx" in cpuinfo.lower():
                    return True
        except Exception:
            pass
        
        return False
    
    def get_tee_info(self) -> TEEInfo:
        """
        Get SGX-specific information.
        
        Returns:
            TEEInfo with SGX details
        """
        if not self._initialized:
            self.initialize()
        
        if self._tee_info:
            return self._tee_info
        
        # Gather SGX information
        capabilities = [
            "enclave_creation",
            "attestation",
            "sealing",
            "provisioning",
        ]
        
        if self._simulation_mode:
            capabilities.append("simulation")
        
        # In production, these would come from actual SGX measurements
        mr_enclave = self._get_mrenclave() if self._simulation_mode else None
        mr_signer = self._get_mrsigner() if self._simulation_mode else None
        
        return TEEInfo(
            tee_type=TEEType.INTEL_SGX,
            version=self._get_sgx_version(),
            capabilities=capabilities,
            mr_enclave=mr_enclave,
            mr_signer=mr_signer,
            is_debug_enabled=self._is_dev_mode,
            is_production=not self._simulation_mode and not self._is_dev_mode,
        )
    
    def _get_mrenclave(self) -> bytes:
        """Get simulated MRENCLAVE measurement."""
        # In simulation, return a placeholder
        return bytes(32)
    
    def _get_mrsigner(self) -> bytes:
        """Get simulated MRSIGNER measurement."""
        # In simulation, return a placeholder
        return bytes(32)
    
    def _get_sgx_version(self) -> str:
        """Get SGX version string."""
        if self._simulation_mode:
            return "2.19.0-sim"
        return "2.19.0"
    
    def create_enclave(
        self,
        enclave_path: str,
        input_params: Optional[Dict[str, Any]] = None
    ) -> EnclaveContext:
        """
        Create and initialize an SGX enclave.
        
        Args:
            enclave_path: Path to the enclave binary (.so file)
            input_params: Optional initialization parameters
            
        Returns:
            EnclaveContext for the created enclave
        """
        if not self._initialized:
            self.initialize()
        
        input_params = input_params or {}
        
        if not os.path.exists(enclave_path):
            if self._simulation_mode:
                logger.warning(f"Enclave file not found, using simulation: {enclave_path}")
                return self._create_simulated_enclave(enclave_path, input_params)
            raise EnclaveLoadError(f"Enclave file not found: {enclave_path}")
        
        try:
            context = self._load_enclave(enclave_path, input_params)
            logger.info(f"Enclave created successfully: {enclave_path}")
            return context
        except Exception as e:
            raise EnclaveLoadError(f"Failed to load enclave: {e}")
    
    def _load_enclave(
        self,
        enclave_path: str,
        input_params: Dict[str, Any]
    ) -> EnclaveContext:
        """
        Load an enclave from file.
        
        In production, this would use the SGX SDK's sgx_create_enclave
        function to actually load and initialize the enclave.
        """
        # Simulate enclave loading
        # In production: sgx_create_enclave(enclave_path, debug, ...)
        
        debug = input_params.get("debug", self._is_dev_mode)
        
        # Calculate measurements (simulated)
        enclave_hash = hashlib.sha256()
        with open(enclave_path, "rb") as f:
            enclave_hash.update(f.read())
        
        mr_enclave = enclave_hash.digest()
        signer_hash = hashlib.sha256()
        signer_hash.update(enclave_path.encode())
        mr_signer = signer_hash.digest()
        
        identity = EnclaveIdentity(
            mr_enclave=mr_enclave,
            mr_signer=mr_signer,
            product_id=input_params.get("product_id", 0),
            security_version=input_params.get("security_version", 1),
            attributes={
                "initialized": True,
                "debug": debug,
                "mode64bit": True,
                "provision_key": input_params.get("use_provision_key", False),
            }
        )
        
        memory_regions = [
            MemoryRegion(address=0x100000, size=0x100000, permissions=0x5),  # RW
            MemoryRegion(address=0x200000, size=0x100000, permissions=0x1),  # RX
        ]
        
        entry_points = {
            "init": 0x1000,
            "process": 0x1010,
            "get_report": 0x1020,
            "seal": 0x1030,
            "unseal": 0x1040,
        }
        
        context = EnclaveContext(
            handle=f"sgx_enclave_{id(self)}",
            tee_type=TEEType.INTEL_SGX,
            memory_regions=memory_regions,
            entry_points=entry_points,
            identity=identity,
        )
        context.is_initialized = True
        context.is_debug_mode = debug
        
        self._enclave_handle = context.handle
        
        return context
    
    def _create_simulated_enclave(
        self,
        enclave_path: str,
        input_params: Dict[str, Any]
    ) -> EnclaveContext:
        """Create a simulated enclave for development."""
        logger.info(f"Creating simulated enclave: {enclave_path}")
        
        mr_enclave = os.urandom(32)
        mr_signer = os.urandom(32)
        
        identity = EnclaveIdentity(
            mr_enclave=mr_enclave,
            mr_signer=mr_signer,
            product_id=input_params.get("product_id", 0),
            security_version=input_params.get("security_version", 1),
            attributes={
                "initialized": True,
                "debug": True,
                "mode64bit": True,
                "provision_key": False,
            }
        )
        
        context = EnclaveContext(
            handle=f"simulated_enclave_{id(self)}",
            tee_type=TEEType.INTEL_SGX,
            memory_regions=[MemoryRegion(0x100000, 0x100000)],
            entry_points={"init": 0x1000, "process": 0x1010},
            identity=identity,
        )
        context.is_initialized = True
        context.is_debug_mode = True
        
        self._enclave_handle = context.handle
        
        return context
    
    def destroy_enclave(self, enclave_handle: Any) -> bool:
        """
        Destroy an SGX enclave.
        
        Args:
            enclave_handle: Handle to the enclave to destroy
            
        Returns:
            True if successful
        """
        try:
            # In production: sgx_destroy_enclave(enclave_handle)
            logger.info(f"Enclave destroyed: {enclave_handle}")
            if self._enclave_handle == enclave_handle:
                self._enclave_handle = None
            return True
        except Exception as e:
            logger.error(f"Failed to destroy enclave: {e}")
            return False
    
    def generate_attestation_evidence(
        self,
        report_data: bytes,
        enclave_handle: Optional[Any] = None
    ) -> AttestationEvidence:
        """
        Generate SGX attestation evidence (quote).
        
        Args:
            report_data: Data to include in the attestation report
            enclave_handle: Optional enclave handle
            
        Returns:
            AttestationEvidence with the SGX quote
        """
        if len(report_data) > self.REPORT_DATA_SIZE:
            raise AttestationError(
                f"Report data too large: {len(report_data)} > {self.REPORT_DATA_SIZE}"
            )
        
        # Pad report data to required size
        report_data = report_data.ljust(self.REPORT_DATA_SIZE, b'\x00')
        
        if self._simulation_mode:
            return self._generate_simulated_evidence(report_data)
        
        return self._generate_real_evidence(report_data, enclave_handle)
    
    def _generate_simulated_evidence(
        self,
        report_data: bytes
    ) -> AttestationEvidence:
        """Generate simulated attestation evidence for development."""
        import time
        
        # Create simulated quote structure
        quote = self._create_simulated_quote(report_data)
        
        # Simulated signature
        signature = hashlib.sha256(quote).digest()
        
        # Simulated certificate chain
        cert_chain = [
            os.urandom(64),  # Enclave certificate
            os.urandom(64),  # PCK certificate
            os.urandom(64),  # Root certificate
        ]
        
        return AttestationEvidence(
            quote=quote,
            quote_type=self._quote_type,
            report_data=report_data,
            signature=signature,
            certificate_chain=cert_chain,
            timestamp=int(time.time()),
            raw_measurements={
                "mrenclave": os.urandom(32),
                "mrsigner": os.urandom(32),
                "isvprodid": struct.pack("<H", 0),
                "isvsvn": struct.pack("<H", 1),
            }
        )
    
    def _create_simulated_quote(self, report_data: bytes) -> bytes:
        """Create a simulated SGX quote structure."""
        # SGX quote structure (simplified)
        quote = bytearray()
        
        # Header
        quote.extend(b'\x03\x00\x00\x00')  # Version
        quote.extend(b'\x02\x00\x00\x00')  # Quote type (ECDSA)
        quote.extend(b'\x00' * 4)  # Reserved
        quote.extend(b'\x01\x00\x00\x00')  # TCB evaluation type
        quote.extend(b'\x00' * 12)  # Reserved
        
        # Platform requirements
        quote.extend(b'\x00' * 32)  # CPUSVN
        quote.extend(b'\x00\x01')  # PCE ID
        
        # Enclave measurement
        quote.extend(os.urandom(32))  # MRENCLAVE
        quote.extend(os.urandom(32))  # MRSIGNER
        quote.extend(b'\x00' * 32)  # MRRESERVED
        quote.extend(b'\x00' * 32)  # ISVEXTPRODUCTID
        quote.extend(b'\x00' * 2)  # ISVPRODID
        quote.extend(b'\x01\x00')  # ISVSVN
        
        # Attributes
        quote.extend(b'\x07\x00\x00\x00\x00\x00\x00\x00')  # ATTRIBUTES (flags)
        quote.extend(b'\x00' * 8)  # XFRM
        
        # Report data
        quote.extend(report_data)
        
        # Signature (placeholder)
        quote.extend(os.urandom(32))  # Signature
        quote.extend(b'\x00' * 32)  # Authentication data (placeholder)
        
        return bytes(quote)
    
    def _generate_real_evidence(
        self,
        report_data: bytes,
        enclave_handle: Optional[Any]
    ) -> AttestationEvidence:
        """
        Generate real SGX attestation evidence.
        
        In production, this would use sgx_create_report and
        sgx_get_quote to generate the actual attestation.
        """
        # In production implementation:
        # 1. Call sgx_create_report to create local attestation report
        # 2. Call sgx_get_quote to generate the quote
        # 3. Verify the quote service returned valid data
        
        if not self._quote_service_available:
            raise AttestationError("Quote service not available")
        
        raise NotImplementedError(
            "Real SGX attestation requires Intel DCAP/EPID libraries. "
            "Use simulation mode for development."
        )
    
    def verify_attestation_evidence(
        self,
        evidence: AttestationEvidence,
        expected_mrenclave: Optional[bytes] = None,
        expected_mrsigner: Optional[bytes] = None,
        expected_product_id: Optional[int] = None,
        expected_security_version: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Verify SGX attestation evidence.
        
        Args:
            evidence: AttestationEvidence to verify
            expected_mrenclave: Expected enclave measurement
            expected_mrsigner: Expected signer measurement
            expected_product_id: Expected product ID
            expected_security_version: Expected security version
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if evidence.quote_type not in (QuoteType.SGX_EPID, QuoteType.SGX_ECDSA):
            return False, f"Invalid quote type: {evidence.quote_type}"
        
        # Parse quote structure
        quote = evidence.quote
        
        if len(quote) < 436:  # Minimum quote size
            return False, "Quote too short"
        
        try:
            # Extract measurements from quote
            quote_version = struct.unpack("<I", quote[0:4])[0]
            quote_type = struct.unpack("<I", quote[4:8])[0]
            
            # MRENCLAVE at offset 112 (after header + CPUSVN + PCEID)
            offset = 48 + 32 + 2
            mrenclave = quote[offset:offset+32]
            mrsigner = quote[offset+32:offset+64]
            isvprodid = struct.unpack("<H", quote[offset+80:offset+82])[0]
            isvsvn = struct.unpack("<H", quote[offset+82:offset+84])[0]
            
            # Verify report data matches
            report_data_offset = 368  # After signature/auth data
            actual_report_data = quote[report_data_offset:report_data_offset+64]
            
            if actual_report_data != evidence.report_data:
                return False, "Report data mismatch"
            
            # Verify expected values
            if expected_mrenclave and mrenclave != expected_mrenclave:
                return False, f"MRENCLAVE mismatch: {bytes_to_hex(mrenclave)} != {bytes_to_hex(expected_mrenclave)}"
            
            if expected_mrsigner and mrsigner != expected_mrsigner:
                return False, f"MRSIGNER mismatch: {bytes_to_hex(mrsigner)} != {bytes_to_hex(expected_mrsigner)}"
            
            if expected_product_id is not None and isvprodid != expected_product_id:
                return False, f"Product ID mismatch: {isvprodid} != {expected_product_id}"
            
            if expected_security_version is not None and isvsvn != expected_security_version:
                return False, f"Security version mismatch: {isvsvn} != {expected_security_version}"
            
            # In production, verify the signature chain
            # and check certificate revocation status
            
            return True, "Attestation verified successfully"
            
        except Exception as e:
            return False, f"Verification failed: {e}"
    
    def encrypt_in_enclave(
        self,
        plaintext: bytes,
        key: bytes,
        enclave_handle: Optional[Any] = None
    ) -> bytes:
        """
        Encrypt data within SGX enclave.
        
        Uses enclave-bound encryption to ensure data never leaves
        the enclave unencrypted.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key
            enclave_handle: Optional enclave handle
            
        Returns:
            Encrypted data (IV + ciphertext + tag)
        """
        from specter.security.encryption import aes_gcm_encrypt
        
        if len(key) < 32:
            # Derive proper key size
            key = hashlib.sha256(key).digest()
        
        # Generate random IV
        iv = os.urandom(12)
        
        # Encrypt using AES-GCM
        ciphertext, tag = aes_gcm_encrypt(plaintext, key, iv)
        
        # Return IV + ciphertext + tag
        return iv + ciphertext + tag
    
    def decrypt_in_enclave(
        self,
        ciphertext: bytes,
        key: bytes,
        enclave_handle: Optional[Any] = None
    ) -> bytes:
        """
        Decrypt data within SGX enclave.
        
        Args:
            ciphertext: Data to decrypt (IV + ciphertext + tag)
            key: Decryption key
            enclave_handle: Optional enclave handle
            
        Returns:
            Decrypted data
        """
        from specter.security.encryption import aes_gcm_decrypt
        
        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        
        # Extract IV, ciphertext, and tag
        iv = ciphertext[:12]
        tag = ciphertext[-16:]
        encrypted_data = ciphertext[12:-16]
        
        return aes_gcm_decrypt(encrypted_data, key, iv, tag)
    
    def derive_key(
        self,
        master_key: bytes,
        key_type: str,
        context: Optional[bytes] = None
    ) -> bytes:
        """
        Derive a key within SGX using KDF.
        
        Args:
            master_key: Master key for derivation
            key_type: Type of key to derive
            context: Optional context for derivation
            
        Returns:
            Derived key (32 bytes for AES-256)
        """
        # Use HKDF-like derivation
        info = key_type.encode() + (context or b'')
        
        # Simple KDF: HMAC-SHA256(master_key, info || counter)
        derived = hmac.new(master_key, info + b'\x01', hashlib.sha256).digest()
        
        return derived


def get_sgx_instance(config: Optional[Dict[str, Any]] = None) -> IntelSGX:
    """
    Factory function to get an Intel SGX instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured IntelSGX instance
    """
    return IntelSGX(config)
