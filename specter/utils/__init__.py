"""
Specter Utilities Module
========================
Common utilities for the Specter framework.
"""

import os
import sys
import json
import logging
import hashlib
from typing import Any, Dict, Optional, Union
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SpecterConfig:
    """Configuration for Specter framework."""
    # TEE Configuration
    tee_type: str = "auto"
    tee_config: Dict[str, Any] = None
    
    # Storage Configuration
    storage_path: Path = None
    model_storage_path: Path = None
    key_storage_path: Path = None
    
    # Security Configuration
    master_password: Optional[str] = None
    enable_encryption: bool = True
    
    # API Configuration
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    api_key: Optional[str] = None
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
    # Federated Learning Configuration
    fl_min_clients: int = 2
    fl_timeout: int = 300
    
    def __post_init__(self):
        """Post-initialization setup."""
        home = Path.home()
        
        if self.storage_path is None:
            self.storage_path = home / ".specter"
        
        if self.model_storage_path is None:
            self.model_storage_path = self.storage_path / "models"
        
        if self.key_storage_path is None:
            self.key_storage_path = self.storage_path / "keystore"
        
        # Create directories
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.model_storage_path.mkdir(parents=True, exist_ok=True)
        self.key_storage_path.mkdir(parents=True, exist_ok=True)
    
    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "SpecterConfig":
        """Load configuration from file."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> "SpecterConfig":
        """Load configuration from environment variables."""
        return cls(
            tee_type=os.environ.get("SPECTER_TEE_TYPE", "auto"),
            master_password=os.environ.get("SPECTER_MASTER_PASSWORD"),
            api_host=os.environ.get("SPECTER_API_HOST", "0.0.0.0"),
            api_port=int(os.environ.get("SPECTER_API_PORT", "8080")),
            api_key=os.environ.get("SPECTER_API_KEY"),
            log_level=os.environ.get("SPECTER_LOG_LEVEL", "INFO"),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {}
        for key, value in self.__dict__.items():
            if isinstance(value, Path):
                result[key] = str(value)
            else:
                result[key] = value
        return result
    
    def save(self, path: Union[str, Path]):
        """Save configuration to file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """
    Setup logging configuration.
    
    Args:
        level: Log level
        log_file: Optional log file path
        format_string: Optional format string
        
    Returns:
        Configured logger
    """
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    if log_file:
        log_file = Path(log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format_string,
        handlers=handlers,
    )
    
    return logging.getLogger("specter")


def compute_file_hash(
    path: Union[str, Path],
    algorithm: str = "sha256",
) -> str:
    """
    Compute hash of a file.
    
    Args:
        path: File path
        algorithm: Hash algorithm
        
    Returns:
        Hex digest of file hash
    """
    hasher = hashlib.new(algorithm)
    
    with open(path, "rb") as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    
    return hasher.hexdigest()


def compute_bytes_hash(
    data: bytes,
    algorithm: str = "sha256",
) -> str:
    """
    Compute hash of bytes.
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm
        
    Returns:
        Hex digest
    """
    return hashlib.new(algorithm, data).hexdigest()


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of bytes.
    
    Args:
        a: First bytes
        b: Second bytes
        
    Returns:
        True if equal
    """
    import hmac
    return hmac.compare_digest(a, b)


def get_system_info() -> Dict[str, Any]:
    """
    Get system information.
    
    Returns:
        Dictionary with system details
    """
    import platform
    import multiprocessing
    
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": multiprocessing.cpu_count(),
        "python_version": sys.version,
    }
    
    # Check for TEE support
    try:
        if os.path.exists("/dev/isgx"):
            info["sgx_available"] = True
        if os.path.exists("/dev/sev"):
            info["sev_available"] = True
        if os.path.exists("/dev/sev-guest"):
            info["sev_snp_available"] = True
    except Exception:
        pass
    
    return info


def validate_model_architecture(architecture: Dict[str, Any]) -> bool:
    """
    Validate model architecture dictionary.
    
    Args:
        architecture: Architecture dictionary
        
    Returns:
        True if valid
    """
    required_fields = ["input_shape", "output_shape"]
    
    for field in required_fields:
        if field not in architecture:
            logger.error(f"Missing required field: {field}")
            return False
    
    return True


class ProgressTracker:
    """Track progress of long-running operations."""
    
    def __init__(self, total: int, description: str = "Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = None
    
    def update(self, increment: int = 1):
        """Update progress."""
        import time
        if self.start_time is None:
            self.start_time = time.time()
        
        self.current += increment
        percent = (self.current / self.total) * 100
        
        elapsed = time.time() - self.start_time
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
        else:
            eta = 0
        
        print(f"\r{self.description}: {self.current}/{self.total} ({percent:.1f}%) ETA: {eta:.0f}s", end="")
        
        if self.current >= self.total:
            print()
    
    def finish(self):
        """Mark as finished."""
        print(f"\r{self.description}: Completed ({self.total}/{self.total})")
        self.current = self.total


class SpecterError(Exception):
    """Base exception for Specter errors."""
    pass


class TEEError(SpecterError):
    """TEE-related errors."""
    pass


class ModelError(SpecterError):
    """Model-related errors."""
    pass


class AttestationError(SpecterError):
    """Attestation-related errors."""
    pass


class KeyManagementError(SpecterError):
    """Key management errors."""
    pass


__all__ = [
    "SpecterConfig",
    "setup_logging",
    "compute_file_hash",
    "compute_bytes_hash",
    "secure_compare",
    "get_system_info",
    "validate_model_architecture",
    "ProgressTracker",
    "SpecterError",
    "TEEError",
    "ModelError",
    "AttestationError",
    "KeyManagementError",
]
