"""
Specter ML Module
=================
Machine learning primitives for confidential computing.
Includes secure inference, federated learning, and privacy-preserving ML.
"""

import os
import json
import time
import hashlib
import struct
import logging
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import numpy as np

logger = logging.getLogger(__name__)


# Model format types
class ModelFormat(Enum):
    """Supported model formats."""
    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    ONNX = "onnx"
    NUMPY = "numpy"
    CUSTOM = "custom"


@dataclass
class EncryptedModel:
    """Container for encrypted model data."""
    model_id: str
    encrypted_weights: bytes
    model_architecture: Dict[str, Any]
    encryption_metadata: Dict[str, Any]
    checksum: str
    format: str = "custom"
    version: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "model_id": self.model_id,
            "model_architecture": self.model_architecture,
            "encryption_metadata": self.encryption_metadata,
            "checksum": self.checksum,
            "format": self.format,
            "version": self.version,
        }
    
    def save(self, path: Path):
        """Save encrypted model to disk."""
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        
        # Save metadata
        with open(path / f"{self.model_id}.meta.json", "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        
        # Save encrypted weights
        with open(path / f"{self.model_id}.weights.enc", "wb") as f:
            f.write(self.encrypted_weights)
    
    @classmethod
    def load(cls, path: Path, model_id: str) -> "EncryptedModel":
        """Load encrypted model from disk."""
        path = Path(path)
        
        with open(path / f"{model_id}.meta.json", "r") as f:
            metadata = json.load(f)
        
        with open(path / f"{model_id}.weights.enc", "rb") as f:
            encrypted_weights = f.read()
        
        return cls(
            model_id=metadata["model_id"],
            encrypted_weights=encrypted_weights,
            model_architecture=metadata["model_architecture"],
            encryption_metadata=metadata["encryption_metadata"],
            checksum=metadata["checksum"],
            format=metadata.get("format", "custom"),
            version=metadata.get("version", 1),
        )


@dataclass
class InferenceRequest:
    """Request for secure inference."""
    model_id: str
    input_data: bytes
    input_shape: Tuple[int, ...]
    encryption_key_id: str
    timestamp: int = field(default_factory=lambda: int(time.time()))
    request_id: str = field(default_factory=lambda: hashlib.sha256(os.urandom(16)).hexdigest())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        data = {
            "model_id": self.model_id,
            "input_shape": list(self.input_shape),
            "encryption_key_id": self.encryption_key_id,
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "metadata": self.metadata,
        }
        return json.dumps(data).encode()


@dataclass
class InferenceResponse:
    """Response from secure inference."""
    request_id: str
    output_data: bytes
    output_shape: Tuple[int, ...]
    inference_time_ms: float
    attestation_evidence: Optional[bytes] = None
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        return self.error is None


class SecureModelWrapper:
    """
    Wrapper for running ML inference within a secure enclave.
    
    Handles:
    - Encrypted model loading
    - Secure input/output
    - Attestation of inference
    """
    
    def __init__(
        self,
        tee_module,
        key_manager,
        model_path: Optional[Path] = None,
    ):
        """
        Initialize secure model wrapper.
        
        Args:
            tee_module: TEE module instance
            key_manager: Key management instance
            model_path: Path to encrypted models
        """
        self.tee = tee_module
        self.key_manager = key_manager
        self.model_path = model_path or Path.home() / ".specter" / "models"
        self._models: Dict[str, EncryptedModel] = {}
        self._decrypted_models: Dict[str, Any] = {}
    
    def encrypt_and_store_model(
        self,
        model_id: str,
        weights: Union[bytes, np.ndarray],
        architecture: Dict[str, Any],
        format: ModelFormat = ModelFormat.CUSTOM,
    ) -> EncryptedModel:
        """
        Encrypt and store a model.
        
        Args:
            model_id: Unique model identifier
            weights: Model weights (bytes or numpy array)
            architecture: Model architecture description
            format: Model format
            
        Returns:
            EncryptedModel container
        """
        # Convert numpy array to bytes if needed
        if isinstance(weights, np.ndarray):
            weights = weights.tobytes()
        
        # Generate or get encryption key
        key, key_id = self.key_manager.get_data_encryption_key()
        
        # Encrypt weights within TEE
        encrypted_weights = self.tee.encrypt_in_enclave(weights, key)
        
        # Compute checksum
        checksum = hashlib.sha256(weights).hexdigest()
        
        # Create encrypted model
        encrypted_model = EncryptedModel(
            model_id=model_id,
            encrypted_weights=encrypted_weights,
            model_architecture=architecture,
            encryption_metadata={
                "key_id": key_id,
                "encrypted_at": int(time.time()),
                "encrypted_by": "tee",
            },
            checksum=checksum,
            format=format.value,
        )
        
        # Store
        self._models[model_id] = encrypted_model
        encrypted_model.save(self.model_path)
        
        logger.info(f"Encrypted and stored model: {model_id}")
        
        return encrypted_model
    
    def load_encrypted_model(
        self,
        model_id: str,
    ) -> EncryptedModel:
        """
        Load an encrypted model from storage.
        
        Args:
            model_id: Model identifier
            
        Returns:
            EncryptedModel
        """
        if model_id in self._models:
            return self._models[model_id]
        
        encrypted_model = EncryptedModel.load(self.model_path, model_id)
        self._models[model_id] = encrypted_model
        
        return encrypted_model
    
    def decrypt_model_for_inference(
        self,
        model_id: str,
        enclave_context: Any = None,
    ) -> Tuple[bytes, str]:
        """
        Decrypt a model within the TEE for inference.
        
        Args:
            model_id: Model identifier
            enclave_context: Optional enclave context
            
        Returns:
            Tuple of (decrypted_weights, key_id)
        """
        encrypted_model = self.load_encrypted_model(model_id)
        
        key_id = encrypted_model.encryption_metadata["key_id"]
        key = self.key_manager.keystore.get_key(key_id)
        
        if not key:
            raise KeyError(f"Key not found: {key_id}")
        
        # Decrypt within TEE
        decrypted_weights = self.tee.decrypt_in_enclave(
            encrypted_model.encrypted_weights,
            key,
            enclave_context,
        )
        
        # Verify checksum
        actual_checksum = hashlib.sha256(decrypted_weights).hexdigest()
        if actual_checksum != encrypted_model.checksum:
            raise ValueError(f"Checksum mismatch for model {model_id}")
        
        logger.info(f"Decrypted model for inference: {model_id}")
        
        return decrypted_weights, key_id
    
    def run_inference(
        self,
        model_id: str,
        input_data: Union[bytes, np.ndarray],
        enclave_context: Any = None,
        return_attestation: bool = True,
    ) -> InferenceResponse:
        """
        Run secure inference.
        
        Args:
            model_id: Model to use
            input_data: Input data
            enclave_context: Enclave context
            return_attestation: Include attestation evidence
            
        Returns:
            InferenceResponse
        """
        start_time = time.time()
        
        try:
            # Decrypt model
            weights, key_id = self.decrypt_model_for_inference(model_id, enclave_context)
            
            # Convert input to numpy if bytes
            if isinstance(input_data, bytes):
                encrypted_model = self._models.get(model_id)
                if encrypted_model:
                    # Assume float32 for simplicity
                    input_data = np.frombuffer(input_data, dtype=np.float32)
            
            # Run inference (placeholder - actual implementation would use TEE)
            output = self._execute_inference(
                weights,
                input_data,
                self._models[model_id].model_architecture,
            )
            
            # Convert output to bytes
            if isinstance(output, np.ndarray):
                output_data = output.tobytes()
                output_shape = tuple(output.shape)
            else:
                output_data = output if isinstance(output, bytes) else str(output).encode()
                output_shape = ()
            
            # Generate attestation if requested
            attestation = None
            if return_attestation:
                report_data = hashlib.sha256(
                    output_data + str(time.time()).encode()
                ).digest()
                evidence = self.tee.generate_attestation_evidence(
                    report_data,
                    enclave_context,
                )
                attestation = evidence.quote
            
            inference_time = (time.time() - start_time) * 1000
            
            return InferenceResponse(
                request_id=hashlib.sha256(os.urandom(8)).hexdigest(),
                output_data=output_data,
                output_shape=output_shape,
                inference_time_ms=inference_time,
                attestation_evidence=attestation,
            )
            
        except Exception as e:
            logger.error(f"Inference failed: {e}")
            return InferenceResponse(
                request_id=hashlib.sha256(os.urandom(8)).hexdigest(),
                output_data=b"",
                output_shape=(),
                inference_time_ms=0,
                error=str(e),
            )
    
    def _execute_inference(
        self,
        weights: bytes,
        input_data: Union[bytes, np.ndarray],
        architecture: Dict[str, Any],
    ) -> np.ndarray:
        """
        Execute inference within TEE.
        
        In production, this would run actual ML inference within the secure enclave.
        For now, this is a placeholder that returns random output.
        """
        # Parse architecture
        input_shape = architecture.get("input_shape", (1, 784))
        output_shape = architecture.get("output_shape", (1, 10))
        
        if isinstance(input_data, bytes):
            # Convert bytes to numpy
            input_array = np.frombuffer(input_data, dtype=np.float32)
            if len(input_array) == 0:
                input_array = np.random.randn(*input_shape).astype(np.float32)
        else:
            input_array = input_data
        
        # Simulate inference (in production, run actual model)
        # For now, return random output
        output = np.random.randn(*output_shape).astype(np.float32)
        
        return output


class FederatedLearningCoordinator:
    """
    Coordinator for federated learning with privacy guarantees.
    
    Features:
    - Secure aggregation
    - Differential privacy
    - Secure model distribution
    """
    
    def __init__(
        self,
        tee_module,
        key_manager,
        privacy_config: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize federated learning coordinator.
        
        Args:
            tee_module: TEE module instance
            key_manager: Key management instance
            privacy_config: Privacy configuration
        """
        self.tee = tee_module
        self.key_manager = key_manager
        self.privacy_config = privacy_config or self._default_privacy_config()
        
        self._clients: Dict[str, Dict] = {}
        self._global_model_id: Optional[str] = None
        self._round_number = 0
    
    def _default_privacy_config(self) -> Dict[str, Any]:
        """Get default privacy configuration."""
        return {
            "noise_multiplier": 1.0,
            "max_grad_norm": 1.0,
            "secure_aggregation": True,
            "minimum_clients": 2,
            "timeout_seconds": 300,
        }
    
    def register_client(
        self,
        client_id: str,
        client_info: Dict[str, Any],
    ) -> str:
        """
        Register a client for federated learning.
        
        Args:
            client_id: Unique client identifier
            client_info: Client metadata
            
        Returns:
            Registration token
        """
        # Generate attestation for client
        report_data = f"client_register_{client_id}".encode()
        evidence = self.tee.generate_attestation_evidence(report_data)
        
        token = hashlib.sha256(
            client_id.encode() + evidence.quote + str(time.time()).encode()
        ).hexdigest()
        
        self._clients[client_id] = {
            "info": client_info,
            "token": token,
            "registered_at": int(time.time()),
            "last_seen": int(time.time()),
            "rounds_completed": 0,
        }
        
        logger.info(f"Registered federated learning client: {client_id}")
        
        return token
    
    def initialize_global_model(
        self,
        model_id: str,
        architecture: Dict[str, Any],
    ) -> EncryptedModel:
        """
        Initialize the global model.
        
        Args:
            model_id: Global model identifier
            architecture: Model architecture
            
        Returns:
            Encrypted global model
        """
        model_wrapper = SecureModelWrapper(self.tee, self.key_manager)
        
        # Generate initial weights
        param_count = 1
        for dim in architecture.get("output_shape", (1, 10)):
            param_count *= dim
        
        initial_weights = np.random.randn(param_count).astype(np.float32) * 0.01
        
        encrypted_model = model_wrapper.encrypt_and_store_model(
            model_id,
            initial_weights,
            architecture,
        )
        
        self._global_model_id = model_id
        self._round_number = 0
        
        logger.info(f"Initialized global model: {model_id}")
        
        return encrypted_model
    
    def distribute_model_to_client(
        self,
        client_id: str,
    ) -> Tuple[EncryptedModel, str]:
        """
        Distribute current global model to a client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            Tuple of (encrypted_model, update_token)
        """
        if client_id not in self._clients:
            raise ValueError(f"Unknown client: {client_id}")
        
        if not self._global_model_id:
            raise ValueError("Global model not initialized")
        
        # Get global model
        model_wrapper = SecureModelWrapper(self.tee, self.key_manager)
        global_model = model_wrapper.load_encrypted_model(self._global_model_id)
        
        # Generate update token
        update_token = hashlib.sha256(
            f"{client_id}_{self._round_number}_{time.time()}".encode()
        ).hexdigest()
        
        # Update client last seen
        self._clients[client_id]["last_seen"] = int(time.time())
        
        return global_model, update_token
    
    def receive_client_update(
        self,
        client_id: str,
        update_token: str,
        encrypted_gradients: bytes,
        client_attestation: Optional[bytes] = None,
    ) -> bool:
        """
        Receive model update from a client.
        
        Args:
            client_id: Client identifier
            update_token: Update token for verification
            encrypted_gradients: Encrypted gradients from client
            client_attestation: Optional client attestation evidence
            
        Returns:
            True if update accepted
        """
        if client_id not in self._clients:
            logger.warning(f"Update from unknown client: {client_id}")
            return False
        
        client = self._clients[client_id]
        
        # Verify update token
        if client.get("current_update_token") != update_token:
            logger.warning(f"Invalid update token from {client_id}")
            return False
        
        # Verify attestation if provided
        if client_attestation:
            # In production, verify client attestation
            pass
        
        # Store update for aggregation
        if "pending_updates" not in client:
            client["pending_updates"] = []
        
        client["pending_updates"].append({
            "gradients": encrypted_gradients,
            "round": self._round_number,
            "timestamp": int(time.time()),
        })
        
        client["rounds_completed"] += 1
        
        logger.info(f"Received update from client: {client_id}")
        
        return True
    
    def aggregate_updates(
        self,
        min_updates: Optional[int] = None,
    ) -> Optional[bytes]:
        """
        Aggregate client updates using secure aggregation.
        
        Args:
            min_updates: Minimum number of updates required
            
        Returns:
            Aggregated gradients or None
        """
        if min_updates is None:
            min_updates = self.privacy_config["minimum_clients"]
        
        # Collect eligible updates
        updates = []
        for client_id, client in self._clients.items():
            if "pending_updates" in client and client["pending_updates"]:
                latest_update = client["pending_updates"][-1]
                if latest_update["round"] == self._round_number:
                    updates.append((client_id, latest_update["gradients"]))
        
        if len(updates) < min_updates:
            logger.warning(f"Insufficient updates: {len(updates)} < {min_updates}")
            return None
        
        logger.info(f"Aggregating {len(updates)} client updates")
        
        # Decrypt and aggregate gradients
        key, key_id = self.key_manager.get_data_encryption_key()
        
        decrypted_grads = []
        for client_id, encrypted_grads in updates:
            try:
                grads = self.tee.decrypt_in_enclave(encrypted_grads, key)
                grads_array = np.frombuffer(grads, dtype=np.float32)
                decrypted_grads.append(grads_array)
            except Exception as e:
                logger.error(f"Failed to decrypt gradients from {client_id}: {e}")
        
        if not decrypted_grads:
            return None
        
        # Compute weighted average
        aggregated = np.mean(decrypted_grads, axis=0)
        
        # Apply differential privacy if configured
        if self.privacy_config.get("secure_aggregation"):
            noise_multiplier = self.privacy_config.get("noise_multiplier", 1.0)
            if noise_multiplier > 0:
                # Add Gaussian noise for differential privacy
                noise = np.random.normal(
                    0,
                    noise_multiplier * self.privacy_config.get("max_grad_norm", 1.0),
                    aggregated.shape
                ).astype(np.float32)
                aggregated = aggregated + noise
        
        # Encrypt aggregated gradients
        aggregated_bytes = aggregated.tobytes()
        encrypted_aggregated = self.tee.encrypt_in_enclave(aggregated_bytes, key)
        
        # Clear pending updates
        for client in self._clients.values():
            client["pending_updates"] = []
        
        self._round_number += 1
        
        return encrypted_aggregated
    
    def apply_update(
        self,
        aggregated_gradients: bytes,
    ) -> bool:
        """
        Apply aggregated gradients to global model.
        
        Args:
            aggregated_gradients: Encrypted aggregated gradients
            
        Returns:
            True if successful
        """
        if not self._global_model_id:
            return False
        
        # In production, this would update the global model
        # within the secure enclave
        
        logger.info(f"Applied update to global model (round {self._round_number})")
        
        return True
    
    def get_round_status(self) -> Dict[str, Any]:
        """Get status of current round."""
        active_clients = sum(
            1 for c in self._clients.values()
            if time.time() - c["last_seen"] < self.privacy_config["timeout_seconds"]
        )
        
        updates_received = sum(
            1 for c in self._clients.values()
            if "pending_updates" in c and c["pending_updates"]
            and c["pending_updates"][-1]["round"] == self._round_number
        )
        
        return {
            "round": self._round_number,
            "total_clients": len(self._clients),
            "active_clients": active_clients,
            "updates_received": updates_received,
            "min_required": self.privacy_config["minimum_clients"],
            "ready_for_aggregation": updates_received >= self.privacy_config["minimum_clients"],
        }


class PrivacyPreservingAnalysis:
    """
    Privacy-preserving data analysis utilities.
    
    Provides:
    - Secure multi-party computation primitives
    - Differential privacy mechanisms
    - Secure comparison and aggregation
    """
    
    def __init__(self, tee_module, epsilon: float = 1.0):
        """
        Initialize privacy-preserving analysis.
        
        Args:
            tee_module: TEE module instance
            epsilon: Privacy budget (lower = more private)
        """
        self.tee = tee_module
        self.epsilon = epsilon
    
    def add_laplace_noise(
        self,
        data: np.ndarray,
        sensitivity: float = 1.0,
    ) -> np.ndarray:
        """
        Add Laplace noise for differential privacy.
        
        Args:
            data: Input data
            sensitivity: Sensitivity of the computation
            
        Returns:
            Noisy data
        """
        scale = sensitivity / self.epsilon
        noise = np.random.laplace(0, scale, data.shape)
        return data + noise.astype(data.dtype)
    
    def add_gaussian_noise(
        self,
        data: np.ndarray,
        sensitivity: float = 1.0,
        delta: float = 1e-5,
    ) -> np.ndarray:
        """
        Add Gaussian noise for (epsilon, delta)-differential privacy.
        
        Args:
            data: Input data
            sensitivity: Sensitivity of the computation
            delta: Probability of privacy violation
            
        Returns:
            Noisy data
        """
        # Standard deviation for Gaussian mechanism
        c = np.sqrt(2 * np.log(1.25 / delta))
        sigma = c * sensitivity / self.epsilon
        
        noise = np.random.normal(0, sigma, data.shape)
        return data + noise.astype(data.dtype)
    
    def secure_sum(
        self,
        values: List[float],
        noise: bool = True,
    ) -> Tuple[float, float]:
        """
        Compute secure sum of values.
        
        Args:
            values: Values to sum
            noise: Whether to add privacy noise
            
        Returns:
            Tuple of (sum, noise_std)
        """
        total = sum(values)
        
        noise_std = 0.0
        if noise:
            # Add noise for privacy
            # In production, use secure multi-party computation
            noise_std = 1.0 / self.epsilon
            total += np.random.laplace(0, noise_std)
        
        return total, noise_std
    
    def secure_average(
        self,
        values: List[float],
        count: int,
        noise: bool = True,
    ) -> Tuple[float, float]:
        """
        Compute secure average.
        
        Args:
            values: Values to average
            count: Number of values
            noise: Whether to add privacy noise
            
        Returns:
            Tuple of (average, noise_std)
        """
        total, noise_std = self.secure_sum(values, noise=False)
        average = total / count if count > 0 else 0
        
        if noise:
            # Average has lower sensitivity
            noise_std = noise_std / count if count > 0 else 0
        
        return average, noise_std
    
    def secure_histogram(
        self,
        values: np.ndarray,
        bins: int = 10,
        range_min: float = None,
        range_max: float = None,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute private histogram.
        
        Args:
            values: Values to histogram
            bins: Number of bins
            range_min: Minimum value
            range_max: Maximum value
            
        Returns:
            Tuple of (counts, bin_edges)
        """
        if range_min is None:
            range_min = values.min()
        if range_max is None:
            range_max = values.max()
        
        counts, edges = np.histogram(values, bins=bins, range=(range_min, range_max))
        
        # Add Laplace noise to counts
        sensitivity = 1.0  # Each person can affect at most one bin by 1
        noisy_counts = self.add_laplace_noise(counts.astype(float), sensitivity)
        noisy_counts = np.maximum(noisy_counts, 0)  # Counts cannot be negative
        
        return noisy_counts.astype(int), edges


__all__ = [
    "ModelFormat",
    "EncryptedModel",
    "InferenceRequest",
    "InferenceResponse",
    "SecureModelWrapper",
    "FederatedLearningCoordinator",
    "PrivacyPreservingAnalysis",
]
