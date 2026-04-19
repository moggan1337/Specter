"""
Specter API Package
====================
REST API, Python SDK, and CLI for Specter framework.
"""

from .sdk import (
    SpecterClient,
    ClientConfig,
    create_client,
    APIError,
    AuthenticationError,
    ResourceNotFoundError,
)

from .cli import main as cli_main, build_parser

__all__ = [
    "SpecterClient",
    "ClientConfig",
    "create_client",
    "APIError",
    "AuthenticationError",
    "ResourceNotFoundError",
    "cli_main",
    "build_parser",
]
