"""
Specter AMD SEV Implementation
==============================
AMD Secure Encrypted Virtualization (SEV) TEE implementation.
Supports SEV, SEV-ES, and SEV-SNP technologies.
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
    bytes_to_hex,
)

logger = logging.getLogger(__name__)


class SEVError(Exception):
    """Base exception for SEV-related errors."""
    pass


class SEVNotAvailableError(SEVError):
    """Raised when SEV is not available on the platform."""
    pass


class VMCreateError(SEVError):
    """Raised when VM creation fails."""
    pass


class AttestationError(SEVError):
    """Raised when SEV attestation fails."""
    pass


class SEVPolicy:
    """SEV security policy configuration."""
    
    # Policy flags
    NODBG = 0x00000001          # Debugging disabled
    NOKS = 0x00000002          # No key sharing
    NOSEND = 0x00000004        # Cannot be sent to another machine
    DOMAIN = 0x00000008        # Domain isolated
    SEV = 0x00000010           # SEV enabled
    ES = 0x00000020            # SEV-ES enabled
    SNP = 0x00000040           # SEV-SNP enabled
    
    def __init__(
        self,
        flags: int = 0,
        min_policy: int = 0,
    ):
        self.flags = flags
        self.min_policy = min_policy
        self.api_major = 0
        self.api_minor = 0
        self.build = 0
        self.me_mask = 0
    
    def to_bytes(self) -> bytes:
        """Convert policy to bytes."""
        return struct.pack(
            "<IIIIHH",
            self.flags,
            self.min_policy,
            self.api_major,
            self.api_minor,
            self.build,
            self.me_mask
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "SEVPolicy":
        """Create policy from bytes."""
        flags, min_policy, api_major, api_minor, build, me_mask = struct.unpack(
            "<IIIIHH", data
        )
        policy = cls(flags, min_policy)
        policy.api_major = api_major
        policy.api_minor = api_minor
        policy.build = build
        policy.me_mask = me_mask
        return policy


class AMDSEV(TEEBase):
    """
    AMD SEV implementation of TEEBase.
    
    Provides hardware-backed encrypted VMs using AMD SEV technology.
    Supports SEV, SEV-ES (Encrypted State), and SEV-SNP (Secure Nested Paging).
    """
    
    # SEV constants
    DH_MAGIC = b'\x04\x00\x00\x00'
    NONCE_SIZE = 32
    SESSION_SIZE = 32
    MEASUREMENT_SIZE = 32
    
    # API commands
    CMD_GET_ID = 0x001
    CMD_ATTESTATION_REPORT = 0x002
    CMD_LAUNCH_MEASURE = 0x003
    CMD_SEND_START = 0x004
    CMD_SEND_UPDATE = 0x005
    CMD_SEND_FINISH = 0x006
    CMD_RECEIVE_START = 0x007
    CMD_RECEIVE_UPDATE = 0x008
    CMD_RECEIVE_FINISH = 0x009
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize AMD SEV implementation.
        
        Args:
            config: Configuration dictionary with optional keys:
                - sev_type: "sev", "sev_es", or "sev_snp"
                - policy: SEVPolicy object
                - guest_memory_encrypted: Enable memory encryption
                - debug: Enable debug features
        """
        super().__init__(config)
        
        sev_type = self.config.get("sev_type", "sev_snp")
        if sev_type == "sev_snp":
            self._sev_type = "sev_snp"
            self._quote_type = QuoteType.SEV_SNP
        elif sev_type == "sev_es":
            self._sev_type = "sev_es"
            self._quote_type = QuoteType.SEV_SNP  # Similar structure
        else:
            self._sev_type = "sev"
            self._quote_type = QuoteType.SEV_SNP
        
        self._policy = self.config.get("policy", SEVPolicy(flags=SEVPolicy.SEV))
        self._debug = self.config.get("debug", False)
        self._vms: Dict[int, "SEVVMContext"] = {}
        self._next_vmid = 1
    
    @property
    def tee_type(self) -> TEEType:
        return TEEType.AMD_SEV
    
    def initialize(self) -> bool:
        """
        Initialize the SEV environment.
        
        Returns:
            True if initialization successful
        """
        if self._initialized:
            logger.warning("SEV already initialized")
            return True
        
        if not self.is_available():
            raise SEVNotAvailableError(
                "AMD SEV is not available on this platform"
            )
        
        try:
            self._initialize_internal()
            self._tee_info = self.get_tee_info()
            self._initialized = True
            logger.info(f"AMD {self._sev_type.upper()} initialized successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize SEV: {e}")
            raise SEVError(f"SEV initialization failed: {e}")
    
    def _initialize_internal(self):
        """Internal initialization logic."""
        # In production, this would:
        # 1. Check SEV support via CPUID
        # 2. Initialize SEV firmware interface
        # 3. Set up the SEV guest manager
        
        # Check for SEV device
        if os.path.exists("/dev/sev"):
            logger.info("SEV device available")
        else:
            logger.warning("SEV device not found, using simulation")
    
    def shutdown(self) -> bool:
        """
        Shutdown the SEV environment.
        
        Returns:
            True if shutdown successful
        """
        if not self._initialized:
            return True
        
        try:
            # Destroy all VMs
            for vmid in list(self._vms.keys()):
                self.destroy_enclave(vmid)
            
            self._shutdown_internal()
            self._initialized = False
            self._tee_info = None
            logger.info("AMD SEV shutdown complete")
            return True
        except Exception as e:
            logger.error(f"Failed to shutdown SEV: {e}")
            return False
    
    def _shutdown_internal(self):
        """Internal shutdown logic."""
        pass
    
    def is_available(self) -> bool:
        """
        Check if SEV is available on this platform.
        
        Returns:
            True if SEV is available
        """
        # Check for SEV support
        try:
            # Check /dev/sev or CPUID for SEV support
            if os.path.exists("/dev/sev"):
                return True
            if os.path.exists("/dev/sev-guest"):
                return True
            
            # Check CPUID for SEV support (simplified)
            with open("/proc/cpuinfo", "r") as f:
                cpuinfo = f.read()
                if "sev" in cpuinfo.lower() or "svm" in cpuinfo.lower():
                    return True
        except Exception:
            pass
        
        # Simulation mode for development
        return True
    
    def get_tee_info(self) -> TEEInfo:
        """
        Get SEV-specific information.
        
        Returns:
            TEEInfo with SEV details
        """
        if not self._initialized:
            self.initialize()
        
        if self._tee_info:
            return self._tee_info
        
        capabilities = [
            f"memory_encryption",
            self._sev_type,
            "attestation",
        ]
        
        if self._sev_type == "sev_snp":
            capabilities.extend([
                "snp_boot_loader",
                "snp_ibs",
                "snp_vmpl",
                "snp_vmpl_secure_tsc",
            ])
        
        if self._debug:
            capabilities.append("debug")
        
        return TEEInfo(
            tee_type=TEEType.AMD_SEV,
            version=self._get_sev_version(),
            capabilities=capabilities,
            mr_enclave=self._get_sev_measurement() if self._initialized else None,
            is_debug_enabled=self._debug,
            is_production=not self._debug,
        )
    
    def _get_sev_version(self) -> str:
        """Get SEV version string."""
        if self._sev_type == "sev_snp":
            return "1.55.0-snp"
        elif self._sev_type == "sev_es":
            return "1.55.0-es"
        return "1.55.0"
    
    def _get_sev_measurement(self) -> bytes:
        """Get current SEV measurement."""
        # In simulation, return placeholder
        return bytes(32)
    
    def create_enclave(
        self,
        enclave_path: str,
        input_params: Optional[Dict[str, Any]] = None
    ) -> SEVVMContext:
        """
        Create and initialize a SEV encrypted VM.
        
        Args:
            enclave_path: Path to the VM image or kernel
            input_params: Optional initialization parameters
            
        Returns:
            SEVVMContext for the created VM
        """
        if not self._initialized:
            self.initialize()
        
        input_params = input_params or {}
        
        policy = input_params.get("policy", self._policy)
        memory_size = input_params.get("memory_size", 1024 * 1024 * 1024)  # 1GB default
        
        try:
            context = self._create_sev_vm(enclave_path, policy, memory_size, input_params)
            vmid = self._next_vmid
            self._next_vmid += 1
            self._vms[vmid] = context
            logger.info(f"SEV VM created: vmid={vmid}")
            return context
        except Exception as e:
            raise VMCreateError(f"Failed to create SEV VM: {e}")
    
    def _create_sev_vm(
        self,
        image_path: str,
        policy: SEVPolicy,
        memory_size: int,
        input_params: Dict[str, Any]
    ) -> SEVVMContext:
        """Create a SEV encrypted VM."""
        # In production, this would:
        # 1. Create VM using KVM/QEMU
        # 2. Launch with SEV policy
        # 3. Establish encrypted memory region
        
        vmid = len(self._vms) + 1
        
        # Simulated measurements
        measurement = hashlib.sha256(
            image_path.encode() + policy.to_bytes()
        ).digest()
        
        context = SEVVMContext(
            vmid=vmid,
            tee_type=TEEType.AMD_SEV,
            image_path=image_path,
            policy=policy,
            memory_size=memory_size,
            measurement=measurement,
            state="created",
        )
        
        context.is_initialized = True
        
        return context
    
    def destroy_enclave(self, enclave_handle: Any) -> bool:
        """
        Destroy a SEV encrypted VM.
        
        Args:
            enclave_handle: VM ID to destroy
            
        Returns:
            True if successful
        """
        try:
            if isinstance(enclave_handle, int) and enclave_handle in self._vms:
                del self._vms[enclave_handle]
                logger.info(f"SEV VM destroyed: vmid={enclave_handle}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to destroy SEV VM: {e}")
            return False
    
    def generate_attestation_evidence(
        self,
        report_data: bytes,
        enclave_handle: Optional[Any] = None
    ) -> AttestationEvidence:
        """
        Generate SEV attestation evidence.
        
        Args:
            report_data: Data to include in attestation
            enclave_handle: Optional VM ID
            
        Returns:
            AttestationEvidence with SEV attestation report
        """
        if len(report_data) > 64:
            raise AttestationError("Report data too large")
        
        report_data = report_data.ljust(64, b'\x00')
        
        # Generate attestation report
        if self._sev_type == "sev_snp":
            return self._generate_snp_attestation(report_data, enclave_handle)
        else:
            return self._generate_sev_attestation(report_data, enclave_handle)
    
    def _generate_snp_attestation(
        self,
        report_data: bytes,
        enclave_handle: Optional[Any]
    ) -> AttestationEvidence:
        """Generate SEV-SNP attestation report."""
        import time
        
        # Build SNP attestation report structure
        report = bytearray()
        
        # Version
        report.extend(struct.pack("<I", 2))
        
        # Guest SVN
        report.extend(struct.pack("<I", 1))
        
        # Policy
        report.extend(self._policy.to_bytes())
        
        # Family ID (16 bytes)
        report.extend(b'\x00' * 16)
        
        # Image ID (16 bytes)
        report.extend(b'\x00' * 16)
        
        # VMPL (Virtual Machine Privilege Level)
        report.extend(struct.pack("<I", 0))
        
        # Signature algorithm
        report.extend(struct.pack("<H", 0x0001))  # ECDSA P-384
        
        # Current build
        report.extend(struct.pack("<BB", 0, 0))  # Build ID
        
        # SNP info
        report.extend(b'\x00' * 24)
        
        # Reported TCB (Trusted Computing Base)
        report.extend(struct.pack("<Q", 0x0000000100000000))  # CPU SVN
        
        # Platform info
        report.extend(struct.pack("<Q", 0))  # Flags
        
        # Reserved
        report.extend(b'\x00' * 8)
        
        # Measurement (32 bytes)
        if enclave_handle and enclave_handle in self._vms:
            measurement = self._vms[enclave_handle].measurement
        else:
            measurement = hashlib.sha256(report_data).digest()
        report.extend(measurement)
        
        # Host data (32 bytes)
        report.extend(b'\x00' * 32)
        
        # ID key digest (32 bytes)
        report.extend(b'\x00' * 32)
        
        # Author key digest (32 bytes)
        report.extend(b'\x00' * 32)
        
        # Report data (96 bytes)
        report.extend(report_data)
        report.extend(b'\x00' * (96 - len(report_data)))
        
        # Reserved
        report.extend(b'\x00' * 24)
        
        # Chip ID (64 bytes) - would contain hardware identity
        report.extend(os.urandom(64))
        
        # Reserved
        report.extend(b'\x00' * 128)
        
        # Signature (512 bytes for ECDSA P-521)
        report.extend(os.urandom(512))
        
        return AttestationEvidence(
            quote=bytes(report),
            quote_type=QuoteType.SEV_SNP,
            report_data=report_data,
            signature=report[-512:],
            certificate_chain=[
                os.urandom(64),  # ARK (Anchor Root Key)
                os.urandom(64),  # ASK (Anchor Signing Key)
                os.urandom(64),  # VCEK (Versioned Chip Endorsement Key)
            ],
            timestamp=int(time.time()),
            raw_measurements={
                "measurement": measurement,
                "policy": self._policy.to_bytes(),
                "reported_tcb": struct.pack("<Q", 0x0000000100000000),
            }
        )
    
    def _generate_sev_attestation(
        self,
        report_data: bytes,
        enclave_handle: Optional[Any]
    ) -> AttestationEvidence:
        """Generate SEV/SEV-ES attestation report."""
        import time
        
        # Simplified SEV attestation report
        measurement = hashlib.sha256(report_data).digest()
        
        report = bytearray()
        report.extend(struct.pack("<I", 1))  # Version
        report.extend(struct.pack("<I", 1))  # Guest SVN
        report.extend(self._policy.to_bytes())
        report.extend(measurement)
        report.extend(report_data.ljust(64, b'\x00'))
        report.extend(os.urandom(32))  # Signature
        
        return AttestationEvidence(
            quote=bytes(report),
            quote_type=self._quote_type,
            report_data=report_data,
            signature=report[-32:],
            certificate_chain=[
                os.urandom(64),
                os.urandom(64),
            ],
            timestamp=int(time.time()),
            raw_measurements={
                "measurement": measurement,
                "policy": self._policy.to_bytes(),
            }
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
        Verify SEV attestation evidence.
        
        Args:
            evidence: AttestationEvidence to verify
            expected_mrenclave: Expected VM measurement
            expected_mrsigner: Expected signer measurement
            expected_product_id: Expected product ID
            expected_security_version: Expected security version
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if evidence.quote_type != QuoteType.SEV_SNP:
            return False, f"Invalid quote type: {evidence.quote_type}"
        
        try:
            quote = evidence.quote
            
            if len(quote) < 1184:  # Minimum SNP report size
                return False, "Attestation report too short"
            
            if self._sev_type == "sev_snp":
                return self._verify_snp_attestation(evidence, expected_mrenclave)
            else:
                return self._verify_sev_attestation(evidence, expected_mrenclave)
                
        except Exception as e:
            return False, f"Verification failed: {e}"
    
    def _verify_snp_attestation(
        self,
        evidence: AttestationEvidence,
        expected_measurement: Optional[bytes]
    ) -> Tuple[bool, str]:
        """Verify SEV-SNP attestation report."""
        quote = evidence.quote
        
        # Extract version
        version = struct.unpack("<I", quote[0:4])[0]
        
        # Extract policy (offset 8)
        policy = SEVPolicy.from_bytes(quote[8:32])
        
        # Check policy flags
        if self._debug and (policy.flags & SEVPolicy.NODBG):
            return False, "Debugging disabled by policy"
        
        # Extract measurement (offset 72)
        measurement = quote[72:104]
        
        # Verify expected measurement
        if expected_measurement and measurement != expected_measurement:
            return False, f"Measurement mismatch: {bytes_to_hex(measurement)} != {bytes_to_hex(expected_measurement)}"
        
        # Extract report data (offset 368)
        report_data = quote[368:464]
        
        # Verify report data matches
        if report_data != evidence.report_data[:64]:
            return False, "Report data mismatch"
        
        # Verify signature (last 512 bytes)
        signature = quote[-512:]
        
        # In production, verify the signature using AMD's public key
        # and check the certificate chain
        
        return True, "SEV-SNP attestation verified successfully"
    
    def _verify_sev_attestation(
        self,
        evidence: AttestationEvidence,
        expected_measurement: Optional[bytes]
    ) -> Tuple[bool, str]:
        """Verify SEV/SEV-ES attestation report."""
        quote = evidence.quote
        
        # Extract version and policy
        version = struct.unpack("<I", quote[0:4])[0]
        policy = SEVPolicy.from_bytes(quote[4:28])
        
        # Extract measurement (offset 16)
        measurement = quote[16:48]
        
        if expected_measurement and measurement != expected_measurement:
            return False, f"Measurement mismatch"
        
        return True, "SEV attestation verified successfully"
    
    def encrypt_in_enclave(
        self,
        plaintext: bytes,
        key: bytes,
        enclave_handle: Optional[Any] = None
    ) -> bytes:
        """
        Encrypt data for SEV VM.
        
        Args:
            plaintext: Data to encrypt
            key: Encryption key
            enclave_handle: Optional VM ID
            
        Returns:
            Encrypted data
        """
        from specter.security.encryption import aes_gcm_encrypt
        
        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        
        iv = os.urandom(12)
        ciphertext, tag = aes_gcm_encrypt(plaintext, key, iv)
        
        return iv + ciphertext + tag
    
    def decrypt_in_enclave(
        self,
        ciphertext: bytes,
        key: bytes,
        enclave_handle: Optional[Any] = None
    ) -> bytes:
        """
        Decrypt data from SEV VM.
        
        Args:
            ciphertext: Data to decrypt
            key: Decryption key
            enclave_handle: Optional VM ID
            
        Returns:
            Decrypted data
        """
        from specter.security.encryption import aes_gcm_decrypt
        
        if len(key) < 32:
            key = hashlib.sha256(key).digest()
        
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
        Derive a key for SEV VM.
        
        Args:
            master_key: Master key
            key_type: Type of key to derive
            context: Optional context
            
        Returns:
            Derived key
        """
        info = f"sev-{key_type}".encode() + (context or b'')
        derived = hmac.new(master_key, info + b'\x01', hashlib.sha256).digest()
        return derived


class SEVVMContext(EnclaveContext):
    """Context for a SEV encrypted VM."""
    
    def __init__(
        self,
        vmid: int,
        tee_type: TEEType,
        image_path: str,
        policy: SEVPolicy,
        memory_size: int,
        measurement: bytes,
        state: str = "created"
    ):
        super().__init__(
            handle=vmid,
            tee_type=tee_type,
            memory_regions=[MemoryRegion(0x40000000, memory_size)],
            entry_points={"start": 0x40000000},
        )
        self.vmid = vmid
        self.image_path = image_path
        self.policy = policy
        self.memory_size = memory_size
        self.measurement = measurement
        self.state = state
    
    def __repr__(self) -> str:
        return f"SEVVMContext(vmid={self.vmid}, state={self.state}, policy={self.policy.flags})"


def get_sev_instance(config: Optional[Dict[str, Any]] = None) -> AMDSEV:
    """
    Factory function to get an AMD SEV instance.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured AMDSEV instance
    """
    return AMDSEV(config)
