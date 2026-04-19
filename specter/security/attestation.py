"""
Specter Attestation Module
===========================
Remote attestation verification for TEE environments.
Supports Intel SGX and AMD SEV attestation quote verification.
"""

import os
import time
import json
import hashlib
import struct
import logging
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from urllib.request import urlopen, Request
from urllib.error import URLError

from specter.tee.base import AttestationEvidence, QuoteType, bytes_to_hex

logger = logging.getLogger(__name__)


class AttestationStatus(Enum):
    """Attestation verification status."""
    VERIFIED = "verified"
    INVALID = "invalid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    PENDING = "pending"


class VerificationError(Exception):
    """Raised when attestation verification fails."""
    pass


@dataclass
class AttestationReport:
    """Complete attestation verification report."""
    status: AttestationStatus
    quote_type: str
    enclave_identity: Dict[str, Any]
    measurements: Dict[str, str]
    platform_info: Dict[str, Any]
    certificate_chain: List[str]
    verification_time: int
    expiry_time: Optional[int] = None
    policy_evaluation: Optional[Dict[str, Any]] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_evidence: Optional[Dict[str, Any]] = None
    
    def is_valid(self) -> bool:
        """Check if attestation is valid."""
        return self.status == AttestationStatus.VERIFIED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "status": self.status.value,
            "quote_type": self.quote_type,
            "enclave_identity": self.enclave_identity,
            "measurements": self.measurements,
            "platform_info": self.platform_info,
            "certificate_chain": self.certificate_chain,
            "verification_time": self.verification_time,
            "expiry_time": self.expiry_time,
            "policy_evaluation": self.policy_evaluation,
            "warnings": self.warnings,
            "errors": self.errors,
        }


class AttestationVerifier:
    """
    Remote attestation verification for TEE environments.
    
    Verifies attestation quotes from:
    - Intel SGX (EPID and ECDSA)
    - AMD SEV-SNP
    """
    
    # Intel SGX quote structure offsets
    SGX_QUOTE_HEADER_SIZE = 48
    SGX_QUOTE_BODY_SIZE = 320
    SGX_QUOTE_SIGNATURE_OFFSET = 384
    
    # Quote types
    SGX_QUOTE_TYPE_EPID = 0
    SGX_QUOTE_TYPE_ECDSA = 2
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        trust_policy: Optional["TrustPolicy"] = None,
    ):
        """
        Initialize attestation verifier.
        
        Args:
            config: Configuration dictionary
            trust_policy: Trust policy for verification
        """
        self.config = config or {}
        self.trust_policy = trust_policy or TrustPolicy()
        
        # Certificate verification endpoints
        self._sgx_ca_url = self.config.get(
            "sgx_ca_url",
            "https://api.trustedservices.intel.com/sgx/certification/v4"
        )
        self._azure_attestation_url = self.config.get(
            "azure_attestation_url",
            "https://attest.azure.com"
        )
        
        # Cache for verification results
        self._verification_cache: Dict[str, Tuple[AttestationReport, int]] = {}
        self._cache_ttl = self.config.get("cache_ttl", 3600)  # 1 hour
    
    def verify_attestation(
        self,
        evidence: AttestationEvidence,
        expected_identity: Optional[Dict[str, Any]] = None,
    ) -> AttestationReport:
        """
        Verify attestation evidence.
        
        Args:
            evidence: Attestation evidence to verify
            expected_identity: Expected enclave identity
            
        Returns:
            AttestationReport with verification results
        """
        # Check cache
        cache_key = self._get_cache_key(evidence)
        if cache_key in self._verification_cache:
            cached_report, cached_time = self._verification_cache[cache_key]
            if time.time() - cached_time < self._cache_ttl:
                logger.debug("Using cached attestation verification")
                return cached_report
        
        # Route to appropriate verifier
        if evidence.quote_type == QuoteType.SGX_EPID:
            report = self._verify_sgx_epid(evidence, expected_identity)
        elif evidence.quote_type == QuoteType.SGX_ECDSA:
            report = self._verify_sgx_ecdsa(evidence, expected_identity)
        elif evidence.quote_type == QuoteType.SEV_SNP:
            report = self._verify_sev_snp(evidence, expected_identity)
        else:
            report = AttestationReport(
                status=AttestationStatus.INVALID,
                quote_type=evidence.quote_type.value,
                enclave_identity={},
                measurements={},
                platform_info={},
                certificate_chain=[],
                verification_time=int(time.time()),
                errors=[f"Unknown quote type: {evidence.quote_type}"],
            )
        
        # Cache result
        self._verification_cache[cache_key] = (report, int(time.time()))
        
        return report
    
    def _get_cache_key(self, evidence: AttestationEvidence) -> str:
        """Generate cache key for evidence."""
        return hashlib.sha256(evidence.quote + evidence.report_data).hexdigest()
    
    def _verify_sgx_epid(
        self,
        evidence: AttestationEvidence,
        expected_identity: Optional[Dict[str, Any]]
    ) -> AttestationReport:
        """Verify Intel SGX EPID attestation."""
        warnings = []
        errors = []
        
        try:
            quote = evidence.quote
            
            # Parse quote header
            if len(quote) < 48:
                errors.append("Quote too short")
                return self._create_report(
                    AttestationStatus.INVALID, evidence, warnings, errors
                )
            
            version = struct.unpack("<I", quote[0:4])[0]
            quote_type = struct.unpack("<I", quote[4:8])[0]
            
            if quote_type != self.SGX_QUOTE_TYPE_EPID:
                errors.append(f"Invalid quote type: {quote_type}")
            
            # Extract enclave identity
            offset = self.SGX_QUOTE_HEADER_SIZE
            mrenclave = quote[offset+32:offset+64]
            mrsigner = quote[offset+64:offset+96]
            isvprodid = struct.unpack("<H", quote[offset+112:offset+114])[0]
            isvsvn = struct.unpack("<H", quote[offset+114:offset+116])[0]
            
            enclave_identity = {
                "mrenclave": bytes_to_hex(mrenclave),
                "mrsigner": bytes_to_hex(mrsigner),
                "isvprodid": isvprodid,
                "isvsvn": isvsvn,
            }
            
            measurements = {
                "mrenclave": bytes_to_hex(mrenclave),
                "mrsigner": bytes_to_hex(mrsigner),
            }
            
            # Verify report data
            report_data_offset = 368
            actual_report_data = quote[report_data_offset:report_data_offset+64]
            
            if actual_report_data != evidence.report_data:
                errors.append("Report data mismatch")
            
            # Verify signature
            signature_valid = self._verify_epid_signature(evidence)
            if not signature_valid:
                errors.append("EPID signature verification failed")
            
            # Verify against expected identity
            if expected_identity:
                id_errors = self._verify_identity(enclave_identity, expected_identity)
                errors.extend(id_errors)
            
            # Check policy
            policy_result = self.trust_policy.evaluate(enclave_identity)
            if not policy_result["allowed"]:
                errors.append(f"Trust policy rejected: {policy_result['reason']}")
            
            status = AttestationStatus.VERIFIED if not errors else AttestationStatus.INVALID
            
            return AttestationReport(
                status=status,
                quote_type="sgx_epid",
                enclave_identity=enclave_identity,
                measurements=measurements,
                platform_info=self._extract_platform_info(quote),
                certificate_chain=[bytes_to_hex(c) for c in evidence.certificate_chain],
                verification_time=int(time.time()),
                policy_evaluation=policy_result,
                warnings=warnings,
                errors=errors,
                raw_evidence={
                    "version": version,
                    "quote_type": quote_type,
                    "timestamp": evidence.timestamp,
                },
            )
            
        except Exception as e:
            logger.error(f"EPID verification error: {e}")
            errors.append(str(e))
            return self._create_report(
                AttestationStatus.UNKNOWN, evidence, warnings, errors
            )
    
    def _verify_sgx_ecdsa(
        self,
        evidence: AttestationEvidence,
        expected_identity: Optional[Dict[str, Any]]
    ) -> AttestationReport:
        """Verify Intel SGX ECDSA attestation."""
        warnings = []
        errors = []
        
        try:
            quote = evidence.quote
            
            if len(quote) < 48:
                errors.append("Quote too short")
                return self._create_report(
                    AttestationStatus.INVALID, evidence, warnings, errors
                )
            
            version = struct.unpack("<I", quote[0:4])[0]
            quote_type = struct.unpack("<I", quote[4:8])[0]
            
            if quote_type != self.SGX_QUOTE_TYPE_ECDSA:
                errors.append(f"Invalid quote type: {quote_type}")
            
            # Extract identity
            offset = self.SGX_QUOTE_HEADER_SIZE
            mrenclave = quote[offset+32:offset+64]
            mrsigner = quote[offset+64:offset+96]
            isvprodid = struct.unpack("<H", quote[offset+112:offset+114])[0]
            isvsvn = struct.unpack("<H", quote[offset+114:offset+116])[0]
            
            enclave_identity = {
                "mrenclave": bytes_to_hex(mrenclave),
                "mrsigner": bytes_to_hex(mrsigner),
                "isvprodid": isvprodid,
                "isvsvn": isvsvn,
            }
            
            measurements = {
                "mrenclave": bytes_to_hex(mrenclave),
                "mrsigner": bytes_to_hex(mrsigner),
            }
            
            # Verify report data
            report_data_offset = 368
            actual_report_data = quote[report_data_offset:report_data_offset+64]
            
            if actual_report_data != evidence.report_data:
                errors.append("Report data mismatch")
            
            # In production, verify ECDSA signature using Intel DCAP
            # For now, check signature presence
            if len(evidence.signature) < 64:
                errors.append("Invalid ECDSA signature")
            
            # Verify against expected identity
            if expected_identity:
                id_errors = self._verify_identity(enclave_identity, expected_identity)
                errors.extend(id_errors)
            
            # Check policy
            policy_result = self.trust_policy.evaluate(enclave_identity)
            if not policy_result["allowed"]:
                errors.append(f"Trust policy rejected: {policy_result['reason']}")
            
            status = AttestationStatus.VERIFIED if not errors else AttestationStatus.INVALID
            
            return AttestationReport(
                status=status,
                quote_type="sgx_ecdsa",
                enclave_identity=enclave_identity,
                measurements=measurements,
                platform_info=self._extract_platform_info(quote),
                certificate_chain=[bytes_to_hex(c) for c in evidence.certificate_chain],
                verification_time=int(time.time()),
                policy_evaluation=policy_result,
                warnings=warnings,
                errors=errors,
                raw_evidence={
                    "version": version,
                    "quote_type": quote_type,
                    "timestamp": evidence.timestamp,
                },
            )
            
        except Exception as e:
            logger.error(f"ECDSA verification error: {e}")
            errors.append(str(e))
            return self._create_report(
                AttestationStatus.UNKNOWN, evidence, warnings, errors
            )
    
    def _verify_sev_snp(
        self,
        evidence: AttestationEvidence,
        expected_identity: Optional[Dict[str, Any]]
    ) -> AttestationReport:
        """Verify AMD SEV-SNP attestation."""
        warnings = []
        errors = []
        
        try:
            quote = evidence.quote
            
            if len(quote) < 1184:  # SNP report size
                errors.append("SNP report too short")
                return self._create_report(
                    AttestationStatus.INVALID, evidence, warnings, errors
                )
            
            # Parse SNP report structure
            version = struct.unpack("<I", quote[0:4])[0]
            guest_svn = struct.unpack("<I", quote[4:8])[0]
            
            # Policy (offset 8)
            policy_bytes = quote[8:32]
            
            # Measurement (offset 72)
            measurement = quote[72:104]
            
            # Report data (offset 368)
            report_data = quote[368:464]
            
            enclave_identity = {
                "guest_svn": guest_svn,
                "measurement": bytes_to_hex(measurement),
                "policy": bytes_to_hex(policy_bytes),
            }
            
            measurements = {
                "measurement": bytes_to_hex(measurement),
            }
            
            # Verify report data matches
            if report_data != evidence.report_data[:64]:
                errors.append("Report data mismatch")
            
            # Verify policy flags
            policy_flags = struct.unpack("<I", policy_bytes[0:4])[0]
            if policy_flags & 0x00000001:  # NODBG
                warnings.append("Debugging is disabled by policy")
            
            # Verify signature (simplified)
            if len(evidence.signature) < 64:
                errors.append("Invalid SNP signature")
            
            # Verify against expected identity
            if expected_identity:
                if "measurement" in expected_identity:
                    expected_meas = bytes.fromhex(expected_identity["measurement"])
                    if measurement != expected_meas:
                        errors.append("Measurement mismatch")
                
                if "policy" in expected_identity:
                    expected_policy = bytes.fromhex(expected_identity["policy"])
                    if policy_bytes != expected_policy:
                        errors.append("Policy mismatch")
            
            # Check policy
            policy_result = self.trust_policy.evaluate(enclave_identity)
            if not policy_result["allowed"]:
                errors.append(f"Trust policy rejected: {policy_result['reason']}")
            
            status = AttestationStatus.VERIFIED if not errors else AttestationStatus.INVALID
            
            return AttestationReport(
                status=status,
                quote_type="sev_snp",
                enclave_identity=enclave_identity,
                measurements=measurements,
                platform_info={
                    "guest_svn": guest_svn,
                    "policy_flags": policy_flags,
                },
                certificate_chain=[bytes_to_hex(c) for c in evidence.certificate_chain],
                verification_time=int(time.time()),
                policy_evaluation=policy_result,
                warnings=warnings,
                errors=errors,
                raw_evidence={
                    "version": version,
                    "timestamp": evidence.timestamp,
                },
            )
            
        except Exception as e:
            logger.error(f"SEV-SNP verification error: {e}")
            errors.append(str(e))
            return self._create_report(
                AttestationStatus.UNKNOWN, evidence, warnings, errors
            )
    
    def _verify_epid_signature(self, evidence: AttestationEvidence) -> bool:
        """
        Verify EPID signature.
        
        In production, this would contact Intel's EPID verification service.
        """
        # Simplified check - verify signature exists and is non-zero
        if len(evidence.signature) < 4:
            return False
        
        # Check signature is not all zeros
        return any(b != 0 for b in evidence.signature)
    
    def _extract_platform_info(self, quote: bytes) -> Dict[str, Any]:
        """Extract platform information from quote."""
        try:
            # CPUSVN at offset 32
            cpusvn = quote[32:48]
            
            # PCE ID at offset 48
            pce_id = struct.unpack("<H", quote[48:50])[0]
            
            return {
                "cpusvn": bytes_to_hex(cpusvn),
                "pce_id": pce_id,
            }
        except Exception:
            return {}
    
    def _verify_identity(
        self,
        actual: Dict[str, Any],
        expected: Dict[str, Any]
    ) -> List[str]:
        """Verify enclave identity against expected values."""
        errors = []
        
        if "mrenclave" in expected:
            if actual.get("mrenclave", "").lower() != expected["mrenclave"].lower():
                errors.append(
                    f"MRENCLAVE mismatch: {actual.get('mrenclave')} != {expected['mrenclave']}"
                )
        
        if "mrsigner" in expected:
            if actual.get("mrsigner", "").lower() != expected["mrsigner"].lower():
                errors.append(
                    f"MRSIGNER mismatch: {actual.get('mrsigner')} != {expected['mrsigner']}"
                )
        
        if "isvprodid" in expected:
            if actual.get("isvprodid") != expected["isvprodid"]:
                errors.append(
                    f"ISVPRODID mismatch: {actual.get('isvprodid')} != {expected['isvprodid']}"
                )
        
        if "isvsvn" in expected:
            if actual.get("isvsvn") < expected["isvsvn"]:
                errors.append(
                    f"ISVSVN too low: {actual.get('isvsvn')} < {expected['isvsvn']}"
                )
        
        return errors
    
    def _create_report(
        self,
        status: AttestationStatus,
        evidence: AttestationEvidence,
        warnings: List[str],
        errors: List[str],
    ) -> AttestationReport:
        """Create an attestation report."""
        return AttestationReport(
            status=status,
            quote_type=evidence.quote_type.value,
            enclave_identity={},
            measurements={},
            platform_info={},
            certificate_chain=[bytes_to_hex(c) for c in evidence.certificate_chain],
            verification_time=int(time.time()),
            warnings=warnings,
            errors=errors,
        )
    
    async def verify_async(
        self,
        evidence: AttestationEvidence,
        expected_identity: Optional[Dict[str, Any]] = None,
    ) -> AttestationReport:
        """
        Async version of verify_attestation.
        
        For production use with network-based verification.
        """
        return self.verify_attestation(evidence, expected_identity)


class TrustPolicy:
    """
    Trust policy for attestation verification.
    
    Defines rules for accepting or rejecting attestations
    based on enclave identity and platform state.
    """
    
    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize trust policy.
        
        Args:
            rules: List of policy rules
        """
        self.rules = rules or self._default_rules()
        self._custom_verifiers: Dict[str, Callable] = {}
    
    def _default_rules(self) -> List[Dict[str, Any]]:
        """Get default trust policy rules."""
        return [
            {
                "name": "require_production_mode",
                "condition": "is_debug == false",
                "action": "allow",
                "description": "Require production (non-debug) enclaves",
            },
            {
                "name": "minimum_security_version",
                "condition": "isvsvn >= 1",
                "action": "allow",
                "description": "Minimum security version",
            },
            {
                "name": "allowed_signers",
                "condition": "mrsigner in allowed_signers",
                "action": "allow",
                "description": "Enclave must be signed by trusted party",
            },
        ]
    
    def add_rule(self, rule: Dict[str, Any]):
        """Add a policy rule."""
        self.rules.append(rule)
    
    def add_custom_verifier(self, name: str, verifier: Callable):
        """Add a custom verification function."""
        self._custom_verifiers[name] = verifier
    
    def evaluate(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate identity against policy.
        
        Args:
            identity: Enclave identity dictionary
            
        Returns:
            Evaluation result with 'allowed' and 'reason' keys
        """
        for rule in self.rules:
            result = self._evaluate_rule(rule, identity)
            if not result["passed"]:
                return {
                    "allowed": False,
                    "reason": f"Rule '{rule.get('name', 'unknown')}' failed: {result['reason']}",
                    "rule": rule.get("name"),
                }
        
        return {
            "allowed": True,
            "reason": "All policy rules passed",
            "rules_checked": len(self.rules),
        }
    
    def _evaluate_rule(
        self,
        rule: Dict[str, Any],
        identity: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Evaluate a single rule."""
        condition = rule.get("condition", "")
        
        try:
            # Simple condition evaluation
            if "is_debug == false" in condition:
                if identity.get("is_debug", False):
                    return {"passed": False, "reason": "Debug mode enabled"}
            
            if "isvsvn >=" in condition:
                threshold = int(condition.split(">=")[1].strip())
                isvsvn = identity.get("isvsvn", 0)
                if isvsvn < threshold:
                    return {"passed": False, "reason": f"ISVSVN {isvsvn} < {threshold}"}
            
            if "mrsigner in allowed_signers" in condition:
                # Check if signer is in allowed list
                mrsigner = identity.get("mrsigner", "").lower()
                allowed = self._get_allowed_signers()
                if allowed and mrsigner not in [s.lower() for s in allowed]:
                    return {"passed": False, "reason": "Untrusted signer"}
            
            return {"passed": True, "reason": ""}
            
        except Exception as e:
            return {"passed": False, "reason": str(e)}
    
    def _get_allowed_signers(self) -> List[str]:
        """Get list of allowed MRSIGNER values."""
        # In production, load from configuration
        return []


async def verify_with_intel_dcap(
    quote: bytes,
    nonce: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Verify quote using Intel DCAP service.
    
    Args:
        quote: SGX quote to verify
        nonce: Optional nonce for freshness
        
    Returns:
        Verification result
    """
    # In production, this would call Intel DCAP API
    # https://api.trustedservices.intel.com/sgx/certification/v4/
    raise NotImplementedError("Intel DCAP verification requires API integration")


async def verify_with_azure_attestation(
    attestation_token: str,
) -> Dict[str, Any]:
    """
    Verify attestation using Azure Attestation.
    
    Args:
        attestation_token: JWT token from Azure Attestation
        
    Returns:
        Verification result
    """
    # In production, verify JWT signature
    raise NotImplementedError("Azure Attestation verification requires API integration")


__all__ = [
    "AttestationStatus",
    "AttestationReport",
    "AttestationVerifier",
    "TrustPolicy",
    "VerificationError",
    "verify_with_intel_dcap",
    "verify_with_azure_attestation",
]
