"""
Specter CLI Module
==================
Command-line interface for Specter framework.
"""

import os
import sys
import json
import argparse
import logging
from typing import Optional, Any
from pathlib import Path

from .sdk import SpecterClient, create_client, DEFAULT_BASE_URL

logger = logging.getLogger(__name__)


def setup_logging(verbose: bool = False):
    """Setup logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def cmd_health(args):
    """Health check command."""
    client = create_client(base_url=args.url)
    try:
        result = client.health_check()
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_tee_info(args):
    """Get TEE information."""
    client = create_client(base_url=args.url)
    try:
        result = client.get_tee_info()
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_create_enclave(args):
    """Create enclave command."""
    client = create_client(base_url=args.url)
    try:
        config = {}
        if args.config:
            with open(args.config) as f:
                config = json.load(f)
        
        result = client.create_enclave(args.enclave_path, config)
        print(json.dumps(result, indent=2))
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
    finally:
        client.close()


def cmd_list_enclaves(args):
    """List enclaves command."""
    client = create_client(base_url=args.url)
    try:
        result = client.list_enclaves()
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_attest(args):
    """Generate attestation command."""
    client = create_client(base_url=args.url)
    try:
        report_data = None
        if args.report_data:
            if os.path.exists(args.report_data):
                with open(args.report_data, "rb") as f:
                    report_data = f.read().hex()
            else:
                report_data = args.report_data
        
        result = client.generate_attestation(args.enclave_id, report_data)
        print(json.dumps(result, indent=2))
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(result, f, indent=2)
    finally:
        client.close()


def cmd_verify_attestation(args):
    """Verify attestation command."""
    client = create_client(base_url=args.url)
    try:
        with open(args.evidence) as f:
            evidence = json.load(f)
        
        expected_identity = None
        if args.expected_identity:
            with open(args.expected_identity) as f:
                expected_identity = json.load(f)
        
        result = client.verify_attestation(evidence, expected_identity)
        print(json.dumps(result, indent=2))
        
        if result.get("status") == "verified":
            sys.exit(0)
        else:
            sys.exit(1)
    finally:
        client.close()


def cmd_generate_key(args):
    """Generate key command."""
    client = create_client(base_url=args.url)
    try:
        result = client.generate_key(
            key_type=args.key_type,
            usage=args.usage.split(",") if args.usage else None,
        )
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_list_keys(args):
    """List keys command."""
    client = create_client(base_url=args.url)
    try:
        result = client.list_keys(key_type=args.key_type)
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_upload_model(args):
    """Upload model command."""
    client = create_client(base_url=args.url)
    try:
        architecture = {}
        if args.architecture:
            with open(args.architecture) as f:
                architecture = json.load(f)
        
        result = client.upload_model(
            model_id=args.model_id,
            weights_path=args.weights,
            architecture=architecture,
            key_id=args.key_id,
        )
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_list_models(args):
    """List models command."""
    client = create_client(base_url=args.url)
    try:
        result = client.list_models()
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_inference(args):
    """Run inference command."""
    client = create_client(base_url=args.url)
    try:
        result = client.run_inference(
            model_id=args.model_id,
            input_data=args.input,
            return_attestation=args.attestation,
        )
        
        # Save output if specified
        if args.output:
            if result.get("output_data"):
                output_bytes = bytes.fromhex(result["output_data"])
                with open(args.output, "wb") as f:
                    f.write(output_bytes)
            print(f"Output saved to {args.output}")
        else:
            print(json.dumps(result, indent=2))
        
        # Print inference time
        if "inference_time_ms" in result:
            print(f"\nInference time: {result['inference_time_ms']:.2f} ms")
        
        if result.get("attestation_evidence") and args.verify_attestation:
            print("\nAttestation evidence included")
            
    finally:
        client.close()


def cmd_fl_register(args):
    """Register FL client command."""
    client = create_client(base_url=args.url)
    try:
        client_info = {}
        if args.client_info:
            with open(args.client_info) as f:
                client_info = json.load(f)
        
        result = client.fl_register_client(args.client_id, client_info)
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_fl_status(args):
    """Get FL status command."""
    client = create_client(base_url=args.url)
    try:
        result = client.fl_get_status()
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def cmd_fl_aggregate(args):
    """Trigger FL aggregation command."""
    client = create_client(base_url=args.url)
    try:
        result = client.fl_trigger_aggregation()
        print(json.dumps(result, indent=2))
    finally:
        client.close()


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Specter - Confidential Computing AI Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        help="API base URL",
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Health command
    health_parser = subparsers.add_parser("health", help="Check API health")
    health_parser.set_defaults(func=cmd_health)
    
    # TEE commands
    tee_parser = subparsers.add_parser("tee-info", help="Get TEE information")
    tee_parser.set_defaults(func=cmd_tee_info)
    
    # Enclave commands
    enclave_create = subparsers.add_parser("enclave-create", help="Create enclave")
    enclave_create.add_argument("enclave_path", help="Path to enclave binary")
    enclave_create.add_argument("--config", help="Enclave configuration file")
    enclave_create.add_argument("--output", "-o", help="Output file for result")
    enclave_create.set_defaults(func=cmd_create_enclave)
    
    enclave_list = subparsers.add_parser("enclave-list", help="List enclaves")
    enclave_list.set_defaults(func=cmd_list_enclaves)
    
    # Attestation commands
    attest_parser = subparsers.add_parser("attest", help="Generate attestation")
    attest_parser.add_argument("enclave_id", help="Enclave ID")
    attest_parser.add_argument("--report-data", help="Report data (string or file)")
    attest_parser.add_argument("--output", "-o", help="Output file for result")
    attest_parser.set_defaults(func=cmd_attest)
    
    verify_parser = subparsers.add_parser("verify", help="Verify attestation")
    verify_parser.add_argument("evidence", help="Evidence file")
    verify_parser.add_argument("--expected-identity", help="Expected identity file")
    verify_parser.set_defaults(func=cmd_verify_attestation)
    
    # Key commands
    key_gen = subparsers.add_parser("key-generate", help="Generate key")
    key_gen.add_argument("--key-type", default="data_encryption", help="Key type")
    key_gen.add_argument("--usage", help="Comma-separated key usage")
    key_gen.set_defaults(func=cmd_generate_key)
    
    key_list = subparsers.add_parser("key-list", help="List keys")
    key_list.add_argument("--key-type", help="Filter by key type")
    key_list.set_defaults(func=cmd_list_keys)
    
    # Model commands
    model_upload = subparsers.add_parser("model-upload", help="Upload model")
    model_upload.add_argument("model_id", help="Model ID")
    model_upload.add_argument("weights", help="Path to model weights")
    model_upload.add_argument("--architecture", help="Architecture file")
    model_upload.add_argument("--key-id", help="Encryption key ID")
    model_upload.set_defaults(func=cmd_upload_model)
    
    model_list = subparsers.add_parser("model-list", help="List models")
    model_list.set_defaults(func=cmd_list_models)
    
    # Inference commands
    inference_parser = subparsers.add_parser("inference", help="Run inference")
    inference_parser.add_argument("model_id", help="Model ID")
    inference_parser.add_argument("input", help="Input data file")
    inference_parser.add_argument("--output", "-o", help="Output file")
    inference_parser.add_argument("--attestation", action="store_true", default=True, help="Include attestation")
    inference_parser.add_argument("--no-attestation", dest="attestation", action="store_false", help="Exclude attestation")
    inference_parser.add_argument("--verify-attestation", action="store_true", help="Verify attestation")
    inference_parser.set_defaults(func=cmd_inference)
    
    # Federated Learning commands
    fl_register = subparsers.add_parser("fl-register", help="Register FL client")
    fl_register.add_argument("client_id", help="Client ID")
    fl_register.add_argument("--client-info", help="Client info file")
    fl_register.set_defaults(func=cmd_fl_register)
    
    fl_status = subparsers.add_parser("fl-status", help="Get FL status")
    fl_status.set_defaults(func=cmd_fl_status)
    
    fl_aggregate = subparsers.add_parser("fl-aggregate", help="Trigger aggregation")
    fl_aggregate.set_defaults(func=cmd_fl_aggregate)
    
    return parser


def main():
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        args.func(args)
    except Exception as e:
        logger.error(f"Command failed: {e}")
        if args.verbose:
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()


__all__ = [
    "SpecterClient",
    "create_client",
    "main",
    "build_parser",
]
