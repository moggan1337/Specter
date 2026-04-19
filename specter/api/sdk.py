"""
Specter API Module
===================
REST API, Python SDK, and CLI for Specter framework.
"""

import os
import sys
import json
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

import requests

logger = logging.getLogger(__name__)


# Configuration
DEFAULT_API_HOST = "localhost"
DEFAULT_API_PORT = 8080
DEFAULT_BASE_URL = f"http://{DEFAULT_API_HOST}:{DEFAULT_API_PORT}/api/v1"


class APIError(Exception):
    """Base exception for API errors."""
    pass


class AuthenticationError(APIError):
    """Raised when authentication fails."""
    pass


class ResourceNotFoundError(APIError):
    """Raised when a resource is not found."""
    pass


@dataclass
class ClientConfig:
    """Configuration for Specter client."""
    base_url: str = DEFAULT_BASE_URL
    api_key: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    
    def to_headers(self) -> Dict[str, str]:
        """Convert to HTTP headers."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SpecterSDK/1.0.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers


class SpecterClient:
    """
    Python SDK client for Specter.
    
    Provides a high-level interface for interacting with Specter services.
    """
    
    def __init__(self, config: Optional[ClientConfig] = None):
        """
        Initialize Specter client.
        
        Args:
            config: Client configuration
        """
        self.config = config or ClientConfig()
        self._session = requests.Session()
        self._session.headers.update(self.config.to_headers())
    
    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Make an API request."""
        url = f"{self.config.base_url}{endpoint}"
        
        for attempt in range(self.config.max_retries):
            try:
                response = self._session.request(
                    method,
                    url,
                    json=data,
                    params=params,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                )
                
                if response.status_code == 401:
                    raise AuthenticationError("Invalid API key")
                elif response.status_code == 404:
                    raise ResourceNotFoundError(f"Resource not found: {endpoint}")
                elif response.status_code >= 400:
                    raise APIError(f"API error: {response.status_code} - {response.text}")
                
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if attempt == self.config.max_retries - 1:
                    raise APIError(f"Request failed: {e}")
                time.sleep(2 ** attempt)
        
        raise APIError("Request failed after retries")
    
    # Health & Info
    def health_check(self) -> Dict[str, Any]:
        """Check API health."""
        return self._request("GET", "/health")
    
    def get_info(self) -> Dict[str, Any]:
        """Get service information."""
        return self._request("GET", "/info")
    
    # TEE Operations
    def get_tee_info(self) -> Dict[str, Any]:
        """Get TEE information."""
        return self._request("GET", "/tee/info")
    
    def check_tee_availability(self) -> Dict[str, Any]:
        """Check TEE availability."""
        return self._request("GET", "/tee/availability")
    
    # Enclave Operations
    def create_enclave(
        self,
        enclave_path: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a new enclave.
        
        Args:
            enclave_path: Path to enclave binary
            config: Optional enclave configuration
            
        Returns:
            Enclave information
        """
        data = {
            "enclave_path": enclave_path,
            "config": config or {},
        }
        return self._request("POST", "/enclaves", data)
    
    def get_enclave(self, enclave_id: str) -> Dict[str, Any]:
        """Get enclave information."""
        return self._request("GET", f"/enclaves/{enclave_id}")
    
    def list_enclaves(self) -> List[Dict[str, Any]]:
        """List all enclaves."""
        return self._request("GET", "/enclaves")
    
    def destroy_enclave(self, enclave_id: str) -> Dict[str, Any]:
        """Destroy an enclave."""
        return self._request("DELETE", f"/enclaves/{enclave_id}")
    
    # Attestation Operations
    def generate_attestation(
        self,
        enclave_id: str,
        report_data: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate attestation evidence for an enclave.
        
        Args:
            enclave_id: Enclave identifier
            report_data: Optional report data
            
        Returns:
            Attestation evidence
        """
        data = {}
        if report_data:
            data["report_data"] = report_data
        
        return self._request("POST", f"/enclaves/{enclave_id}/attest", data)
    
    def verify_attestation(
        self,
        evidence: Dict[str, Any],
        expected_identity: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Verify attestation evidence.
        
        Args:
            evidence: Attestation evidence to verify
            expected_identity: Expected enclave identity
            
        Returns:
            Verification result
        """
        data = {
            "evidence": evidence,
            "expected_identity": expected_identity,
        }
        return self._request("POST", "/attestation/verify", data)
    
    # Key Operations
    def generate_key(
        self,
        key_type: str = "data_encryption",
        usage: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a new key.
        
        Args:
            key_type: Type of key
            usage: Key usage policies
            
        Returns:
            Key information (without the actual key material)
        """
        data = {
            "key_type": key_type,
            "usage": usage or ["encrypt", "decrypt"],
        }
        return self._request("POST", "/keys", data)
    
    def get_key_info(self, key_id: str) -> Dict[str, Any]:
        """Get key information (without key material)."""
        return self._request("GET", f"/keys/{key_id}")
    
    def list_keys(
        self,
        key_type: Optional[str] = None,
        include_revoked: bool = False,
    ) -> List[Dict[str, Any]]:
        """List keys."""
        params = {
            "include_revoked": include_revoked,
        }
        if key_type:
            params["key_type"] = key_type
        
        return self._request("GET", "/keys", params=params)
    
    def revoke_key(self, key_id: str) -> Dict[str, Any]:
        """Revoke a key."""
        return self._request("POST", f"/keys/{key_id}/revoke")
    
    def rotate_key(self, key_id: str) -> Dict[str, Any]:
        """Rotate a key."""
        return self._request("POST", f"/keys/{key_id}/rotate")
    
    # Model Operations
    def upload_model(
        self,
        model_id: str,
        weights_path: str,
        architecture: Dict[str, Any],
        key_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Upload and encrypt a model.
        
        Args:
            model_id: Model identifier
            weights_path: Path to model weights
            architecture: Model architecture
            key_id: Optional key ID for encryption
            
        Returns:
            Upload result
        """
        with open(weights_path, "rb") as f:
            weights_data = f.read()
        
        data = {
            "model_id": model_id,
            "architecture": architecture,
            "weights": weights_data.hex(),
            "key_id": key_id,
        }
        
        return self._request("POST", "/models", data)
    
    def get_model(self, model_id: str) -> Dict[str, Any]:
        """Get model information."""
        return self._request("GET", f"/models/{model_id}")
    
    def list_models(self) -> List[Dict[str, Any]]:
        """List models."""
        return self._request("GET", "/models")
    
    def delete_model(self, model_id: str) -> Dict[str, Any]:
        """Delete a model."""
        return self._request("DELETE", f"/models/{model_id}")
    
    # Inference Operations
    def run_inference(
        self,
        model_id: str,
        input_data: Union[str, bytes],
        return_attestation: bool = True,
    ) -> Dict[str, Any]:
        """
        Run secure inference.
        
        Args:
            model_id: Model to use
            input_data: Input data (file path or bytes)
            return_attestation: Include attestation evidence
            
        Returns:
            Inference result
        """
        if isinstance(input_data, str):
            with open(input_data, "rb") as f:
                input_bytes = f.read()
        else:
            input_bytes = input_data
        
        data = {
            "model_id": model_id,
            "input_data": input_bytes.hex(),
            "return_attestation": return_attestation,
        }
        
        return self._request("POST", "/inference", data)
    
    # Federated Learning Operations
    def fl_register_client(
        self,
        client_id: str,
        client_info: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Register a federated learning client."""
        data = {
            "client_id": client_id,
            "client_info": client_info,
        }
        return self._request("POST", "/fl/clients/register", data)
    
    def fl_get_model(self, client_id: str) -> Dict[str, Any]:
        """Get global model for client."""
        return self._request("GET", f"/fl/clients/{client_id}/model")
    
    def fl_submit_update(
        self,
        client_id: str,
        gradients: str,
        attestation: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit gradient update."""
        data = {
            "gradients": gradients,
            "attestation": attestation,
        }
        return self._request("POST", f"/fl/clients/{client_id}/update", data)
    
    def fl_get_status(self) -> Dict[str, Any]:
        """Get federated learning status."""
        return self._request("GET", "/fl/status")
    
    def fl_trigger_aggregation(self) -> Dict[str, Any]:
        """Trigger aggregation of updates."""
        return self._request("POST", "/fl/aggregate")
    
    def close(self):
        """Close the client session."""
        self._session.close()


# High-level convenience functions
def create_client(
    api_key: Optional[str] = None,
    base_url: str = DEFAULT_BASE_URL,
) -> SpecterClient:
    """
    Create a Specter client.
    
    Args:
        api_key: Optional API key
        base_url: Base URL for API
        
    Returns:
        Configured SpecterClient
    """
    config = ClientConfig(
        base_url=base_url,
        api_key=api_key,
    )
    return SpecterClient(config)


__all__ = [
    "ClientConfig",
    "SpecterClient",
    "APIError",
    "AuthenticationError",
    "ResourceNotFoundError",
    "create_client",
    "DEFAULT_BASE_URL",
]
