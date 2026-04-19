"""
Specter Test Suite
==================
"""

import pytest
import os
import sys
import json
import hashlib
import time
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestTEE:
    """Tests for TEE module."""
    
    def test_create_tee_auto(self):
        """Test auto TEE creation."""
        from specter.tee import create_tee, TEEType
        
        tee = create_tee("auto")
        assert tee is not None
        assert tee.tee_type in (TEEType.INTEL_SGX, TEEType.AMD_SEV, TEEType.NONE)
    
    def test_create_tee_none(self):
        """Test no-op TEE creation."""
        from specter.tee import create_tee, TEEType
        
        tee = create_tee("none")
        assert tee.tee_type == TEEType.NONE
        assert tee.is_available()
    
    def test_tee_initialization(self):
        """Test TEE initialization."""
        from specter.tee import create_tee
        
        tee = create_tee("none")
        result = tee.initialize()
        assert result is True
        assert tee._initialized is True
    
    def test_tee_shutdown(self):
        """Test TEE shutdown."""
        from specter.tee import create_tee
        
        tee = create_tee("none")
        tee.initialize()
        result = tee.shutdown()
        assert result is True


class TestSecurity:
    """Tests for security module."""
    
    def test_aes_gcm_encrypt_decrypt(self):
        """Test AES-GCM encryption and decryption."""
        from specter.security import aes_gcm_encrypt, aes_gcm_decrypt
        
        plaintext = b"Hello, Specter!"
        key = os.urandom(32)
        iv = os.urandom(12)
        
        ciphertext, tag = aes_gcm_encrypt(plaintext, key, iv)
        decrypted = aes_gcm_decrypt(ciphertext, key, iv, tag)
        
        assert decrypted == plaintext
    
    def test_aes_cbc_encrypt_decrypt(self):
        """Test AES-CBC encryption and decryption."""
        from specter.security import aes_cbc_encrypt, aes_cbc_decrypt
        
        plaintext = b"Hello, Specter! This is a longer message."
        key = os.urandom(32)
        iv = os.urandom(16)
        
        ciphertext, returned_iv = aes_cbc_encrypt(plaintext, key, iv)
        decrypted = aes_cbc_decrypt(ciphertext, key, returned_iv)
        
        assert decrypted == plaintext
    
    def test_key_generation(self):
        """Test key generation."""
        from specter.security import generate_aes_key
        
        key = generate_aes_key(256)
        assert len(key) == 32
        
        key128 = generate_aes_key(128)
        assert len(key128) == 16
    
    def test_hkdf_key_derivation(self):
        """Test HKDF key derivation."""
        from specter.security import derive_key_hkdf, secure_random
        
        master = secure_random(32)
        derived = derive_key_hkdf(master, 32, info=b"test")
        
        assert len(derived) == 32
        assert derived != master
    
    def test_key_store(self):
        """Test key store operations."""
        from specter.security import KeyStore, KeyType, KeyUsage
        
        store = KeyStore()  # In-memory for testing
        
        key, key_id = store.generate_key(
            key_type=KeyType.DEK,
            usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT],
        )
        
        assert len(key) > 0
        assert key_id.startswith("k_")
        
        # Retrieve key
        retrieved = store.get_key(key_id)
        assert retrieved == key
    
    def test_key_rotation(self):
        """Test key rotation."""
        from specter.security import KeyStore, KeyType
        
        store = KeyStore()
        
        key1, key_id1 = store.generate_key(key_type=KeyType.DEK)
        
        result = store.rotate_key(key_id1)
        assert result is not None
        
        new_key, new_id = result
        assert new_id != key_id1


class TestAttestation:
    """Tests for attestation module."""
    
    def test_attestation_evidence_generation(self):
        """Test attestation evidence generation."""
        from specter.tee import create_tee
        
        tee = create_tee("none")
        tee.initialize()
        
        report_data = b"test_report_data"
        evidence = tee.generate_attestation_evidence(report_data)
        
        assert evidence is not None
        assert len(evidence.quote) > 0
        assert evidence.report_data == report_data
    
    def test_attestation_verification(self):
        """Test attestation verification."""
        from specter.tee import create_tee
        from specter.security import AttestationVerifier
        
        tee = create_tee("none")
        tee.initialize()
        
        report_data = b"test_report_data"
        evidence = tee.generate_attestation_evidence(report_data)
        
        verifier = AttestationVerifier()
        report = verifier.verify_attestation(evidence)
        
        assert report is not None


class TestML:
    """Tests for ML module."""
    
    def test_encrypted_model(self):
        """Test encrypted model storage."""
        from specter.ml import EncryptedModel
        from specter.security import secure_random
        
        model = EncryptedModel(
            model_id="test_model",
            encrypted_weights=secure_random(1024),
            model_architecture={"layers": 3},
            encryption_metadata={"key_id": "k_123"},
            checksum="abc123",
        )
        
        # Convert to dict
        data = model.to_dict()
        assert data["model_id"] == "test_model"
    
    def test_inference_request(self):
        """Test inference request."""
        from specter.ml import InferenceRequest
        
        request = InferenceRequest(
            model_id="test",
            input_data=b"test",
            input_shape=(1, 10),
            encryption_key_id="k_123",
        )
        
        assert request.model_id == "test"
        assert request.request_id is not None


class TestAPI:
    """Tests for API module."""
    
    def test_client_config(self):
        """Test client configuration."""
        from specter.api import ClientConfig
        
        config = ClientConfig(
            base_url="http://localhost:8080",
            api_key="test_key",
            timeout=30,
        )
        
        headers = config.to_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test_key"


class TestUtils:
    """Tests for utilities."""
    
    def test_config_creation(self):
        """Test configuration creation."""
        from specter.utils import SpecterConfig
        
        config = SpecterConfig(
            tee_type="auto",
            enable_encryption=True,
        )
        
        assert config.tee_type == "auto"
        assert config.enable_encryption is True
    
    def test_file_hash(self):
        """Test file hash computation."""
        from specter.utils import compute_bytes_hash
        
        data = b"test data"
        hash1 = compute_bytes_hash(data)
        hash2 = compute_bytes_hash(data)
        
        assert hash1 == hash2
        
        hash3 = compute_bytes_hash(b"different data")
        assert hash3 != hash1
    
    def test_secure_compare(self):
        """Test secure comparison."""
        from specter.utils import secure_compare
        
        a = b"test123"
        b_str = b"test123"
        c = b"test456"
        
        assert secure_compare(a, b_str) is True
        assert secure_compare(a, c) is False
    
    def test_system_info(self):
        """Test system info retrieval."""
        from specter.utils import get_system_info
        
        info = get_system_info()
        
        assert "platform" in info
        assert "python_version" in info


class TestIntegration:
    """Integration tests."""
    
    def test_specter_initialization(self):
        """Test full Specter initialization."""
        from specter import Specter
        
        specter = Specter(tee_type="none", log_level="ERROR")
        specter.initialize()
        
        assert specter._initialized is True
        assert specter.tee is not None
        assert specter.key_manager is not None
        
        specter.shutdown()
    
    def test_context_manager(self):
        """Test context manager usage."""
        from specter import Specter
        
        with Specter(tee_type="none", log_level="ERROR") as specter:
            assert specter._initialized is True
        
        # After context, should be shutdown
        assert specter._initialized is False
    
    def test_encrypt_decrypt_cycle(self):
        """Test complete encrypt/decrypt cycle."""
        from specter import Specter
        
        with Specter(tee_type="none", log_level="ERROR") as specter:
            original_data = b"Sensitive ML model weights"
            
            encrypted, key_id = specter.encrypt_data(original_data)
            decrypted = specter.decrypt_data(encrypted, key_id)
            
            assert decrypted == original_data
            assert encrypted != original_data


# Pytest configuration
def pytest_configure(config):
    """Pytest configuration."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
