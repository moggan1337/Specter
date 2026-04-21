# Specter - Confidential Computing AI Framework

```
███████╗██╗   ██╗██████╗  █████╗ ███████╗███████╗
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔════╝
███████╗██║   ██║██████╔╝███████║███████╗███████╗
╚════██║██║   ██║██╔══██╗██╔══██║╚════██║╚════██║
███████║╚██████╔╝██████╔╝██║  ██║███████║███████║
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**Secure AI/ML in Hardware-Enforced Trusted Execution Environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)](https://www.python.org/downloads/)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

---

## 🎬 Demo
![Specter Demo](demo.gif)

*Confidential AI in trusted execution environments*

## Screenshots
| Component | Preview |
|-----------|---------|
| TEE Status | ![tee](screenshots/tee-status.png) |
| Secure Enclave | ![enclave](screenshots/secure-enclave.png) |
| Attestation | ![attest](screenshots/attestation.png) |

## Visual Description
TEE status shows SGX/SEV enclave states with measurement. Secure enclave displays protected model execution. Attestation shows remote verification with quotes.

---


## Table of Contents

1. [Overview](#overview)
2. [Security Model](#security-model)
3. [Architecture](#architecture)
4. [Getting Started](#getting-started)
   - [Installation](#installation)
   - [Quick Start](#quick-start)
5. [TEE Support](#tee-support)
   - [Intel SGX](#intel-sgx)
   - [AMD SEV](#amd-sev)
   - [Simulation Mode](#simulation-mode)
6. [Core Features](#core-features)
   - [Encrypted Model Storage](#encrypted-model-storage)
   - [Attestation](#attestation)
   - [Secure Inference](#secure-inference)
   - [Federated Learning](#federated-learning)
   - [Key Management](#key-management)
7. [API Reference](#api-reference)
   - [Python SDK](#python-sdk)
   - [REST API](#rest-api)
   - [CLI](#cli)
8. [Configuration](#configuration)
9. [Security Considerations](#security-considerations)
10. [Performance](#performance)
11. [Troubleshooting](#troubleshooting)
12. [Contributing](#contributing)
13. [License](#license)

---

## Overview

Specter is a comprehensive confidential computing framework designed specifically for AI/ML workloads. It leverages Trusted Execution Environments (TEEs) like Intel SGX and AMD SEV to provide hardware-backed security guarantees for:

- **Model Protection**: Encrypt neural network weights at rest and in transit
- **Inference Security**: Run ML inference within hardware-isolated enclaves
- **Attestation**: Verify the integrity of your secure environment remotely
- **Privacy-Preserving ML**: Implement federated learning with cryptographic guarantees
- **Key Management**: Hierarchical key management with TEE integration

### Key Benefits

- **Hardware Security**: Leverage CPU-level isolation for sensitive AI workloads
- **Remote Attestation**: Verify enclave integrity without physical access
- **Privacy by Design**: Built-in support for differential privacy and secure aggregation
- **Multi-TEE Support**: Works with Intel SGX, AMD SEV, and simulation mode
- **Easy Integration**: Python SDK, REST API, and CLI for seamless adoption

---

## Security Model

### Threat Model

Specter addresses the following threat model:

| Threat | Protection |
|--------|------------|
| Model theft | Encrypted model weights, TEE-bound keys |
| Inference manipulation | Hardware enclave isolation, attestation |
| Key extraction | Keys never leave TEE unencrypted |
| Remote attacks | Remote attestation verification |
| Insider threats | Master key protection, access controls |
| Side-channel attacks | Memory encryption (SEV), page granularity (SGX) |

### Security Guarantees

#### Confidentiality
- Model weights encrypted at rest using AES-256-GCM
- Keys protected by TEE or master password
- Memory regions encrypted by hardware (SEV) or encrypted pages (SGX)

#### Integrity
- Enclave measurement (MRENCLAVE/MRSIGNER) via attestation
- Code integrity verified through hardware measurements
- Tamper-evident logging of all operations

#### Attestation
- Hardware-generated quotes signed by CPU manufacturer
- Verification using Intel DCAP or AMD VCEK
- Optional integration with cloud attestation services (Azure Attestation)

### Trust Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│                    User/Client                          │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Remote Attestation                         │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Verify Quote Signature                          │  │
│  │  Verify Certificate Chain                        │  │
│  │  Verify Measurements (MRENCLAVE/MRSIGNER)         │  │
│  │  Verify TCB Components                           │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Specter Framework (Untrusted)              │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Key Management (encrypted KEK/DEK)              │  │
│  │  Model Storage (encrypted weights)                │  │
│  │  API/CLI Interface                                │  │
│  │  Federated Learning Coordination                 │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│              Trusted Execution Environment              │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Enclave Memory (SGX EPC / SEV Encrypted VM)     │  │
│  │  Secure Inference Engine                          │  │
│  │  Key Derivation (HKDF)                           │  │
│  │  Decrypted Model Weights                         │  │
│  │  Attestation Report Generation                   │  │
│  └─────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Architecture

### Component Overview

```
specter/
├── __init__.py           # Main package, Specter class
├── tee/                  # TEE implementations
│   ├── __init__.py       # TEE factory, exports
│   ├── base.py           # Abstract TEE interface
│   ├── sgx.py            # Intel SGX implementation
│   └── sev.py            # AMD SEV implementation
├── security/             # Security primitives
│   ├── __init__.py       # Security exports
│   ├── encryption.py     # AES-GCM/CBC, KDF
│   ├── key_management.py # Key store, rotation
│   └── attestation.py    # Quote verification
├── ml/                   # ML primitives
│   ├── __init__.py       # ML exports
│   └── secure_inference.py  # Models, FL, privacy
├── api/                  # API layer
│   ├── __init__.py       # API exports
│   ├── sdk.py            # Python SDK
│   ├── cli.py            # CLI commands
│   └── server.py         # FastAPI server
└── utils/                # Utilities
    └── __init__.py       # Config, logging, helpers
```

### Data Flow

#### Model Encryption Flow
```
1. User provides plaintext model weights
2. Specter generates or retrieves DEK
3. DEK encrypted with master key or TEE key
4. Weights encrypted within TEE using DEK
5. Encrypted weights stored to disk
6. Metadata (key_id, checksum) stored separately
```

#### Secure Inference Flow
```
1. Client requests inference
2. Server loads encrypted model
3. DEK retrieved from key store
4. Model decrypted within TEE enclave
5. Input encrypted by client
6. Inference performed on decrypted model
7. Output encrypted within TEE
8. Attestation quote optionally generated
9. Encrypted output returned to client
```

---

## Getting Started

### Installation

#### From Source
```bash
git clone https://github.com/moggan1337/Specter.git
cd Specter
pip install -e .
```

#### With Optional Dependencies
```bash
# Install with API dependencies
pip install -e ".[api]"

# Install with ML dependencies
pip install -e ".[ml]"

# Install all dependencies
pip install -e ".[dev,api,ml]"
```

#### Using pip
```bash
pip install specter-cc
```

### Quick Start

#### Basic Python Usage

```python
from specter import Specter, create_specter

# Create and initialize Specter
specter = create_specter(tee_type="auto")
specter.initialize()

# Encrypt model weights
architecture = {
    "input_shape": (1, 784),
    "output_shape": (1, 10),
    "layers": ["dense", "relu", "dense", "softmax"]
}

# Your model weights (as bytes)
model_weights = open("model.bin", "rb").read()

# Encrypt and store
encrypted_model = specter.encrypt_model(
    model_id="my_model_v1",
    weights=model_weights,
    architecture=architecture
)

print(f"Model encrypted: {encrypted_model.model_id}")
print(f"Checksum: {encrypted_model.checksum}")

# Run secure inference
response = specter.run_secure_inference(
    model_id="my_model_v1",
    input_data=input_bytes
)

print(f"Inference time: {response.inference_time_ms:.2f}ms")

# Shutdown
specter.shutdown()
```

#### Using Context Manager

```python
from specter import Specter

with Specter(tee_type="sgx", log_level="DEBUG") as specter:
    # Framework automatically initialized
    encrypted = specter.encrypt_data(b"sensitive data")
    # Framework automatically shutdown on exit
```

#### CLI Usage

```bash
# Check system capabilities
specter-cli health
specter-cli tee-info

# Generate a key
specter-cli key-generate --key-type data_encryption

# Upload and encrypt a model
specter-cli model-upload my_model model.weights --architecture arch.json

# Run inference
specter-cli inference my_model input.bin --output result.bin
```

#### REST API Usage

```bash
# Start the API server
specter-server --host 0.0.0.0 --port 8080

# Or using Python
python -m specter.api.server

# Make API requests
curl http://localhost:8080/api/v1/health

curl -X POST http://localhost:8080/api/v1/models \
  -H "Content-Type: application/json" \
  -d '{"model_id": "test", "weights": "...", "architecture": {...}}'
```

---

## TEE Support

### Intel SGX

Intel Software Guard Extensions provides hardware-isolated regions called enclaves.

#### Requirements
- 6th Gen Intel Core or newer CPU
- SGX enabled in BIOS
- Linux kernel 4.14+ with SGX support
- Intel SGX Driver (isgx or dcap)

#### Configuration

```python
from specter import Specter

specter = Specter(
    tee_type="sgx",
    config={
        "simulation_mode": False,      # Use hardware
        "quote_type": "ecdsa",          # ECDSA (DCAP) or EPID
        "spid": "YOUR_SPID",            # For EPID attestation
        "dev_mode": False,              # Production mode
    }
)
```

#### Attestation

```python
# Generate attestation
evidence = specter.tee.generate_attestation_evidence(
    report_data=b"my_app_data",
    enclave_context=enclave
)

# Verify remotely
report = specter.attestation_verifier.verify_attestation(
    evidence,
    expected_identity={
        "mrenclave": "expected_mrenclave_hash",
        "mrsigner": "expected_signer_hash",
    }
)

if report.is_valid():
    print("Attestation verified!")
else:
    print(f"Verification failed: {report.errors}")
```

### AMD SEV

AMD Secure Encrypted Virtualization encrypts entire VM memory regions.

#### Requirements
- AMD EPYC processor (Rome or newer for SEV-SNP)
- SEV/SNP enabled in BIOS
- Linux kernel 5.10+ with KVM
- SEV-SNP kernel support

#### Configuration

```python
from specter import Specter
from specter.tee.sev import SEVPolicy

specter = Specter(
    tee_type="sev",
    config={
        "sev_type": "sev_snp",          # sev, sev_es, or sev_snp
        "policy": SEVPolicy(
            flags=SEVPolicy.SEV | SEVPolicy.NODBG,
        ),
        "debug": False,
    }
)
```

### Simulation Mode

For development without TEE hardware.

```python
from specter import Specter

specter = Specter(
    tee_type="none",  # or tee_type="auto" with simulation_mode=True
    config={"simulation_mode": True}
)

# All operations work the same, but without hardware security
```

---

## Core Features

### Encrypted Model Storage

#### Supported Formats
- NumPy arrays (`.npy`, `.npz`)
- PyTorch (`.pt`, `.pth`)
- TensorFlow (`.h5`, SavedModel)
- ONNX (`.onnx`)
- Custom binary formats

#### Encryption Process

```python
# Encrypt a model
encrypted_model = specter.encrypt_model(
    model_id="classifier_v1",
    weights=torch_model.state_dict(),  # or bytes
    architecture={
        "framework": "pytorch",
        "input_shape": [1, 3, 224, 224],
        "output_shape": [1, 1000],
        "layers": [...],
    }
)

# Save to disk
encrypted_model.save(Path("models/"))

# Load from disk
loaded = EncryptedModel.load(Path("models/"), "classifier_v1")
```

#### Model Verification

```python
# Verify model integrity
decrypted_weights = specter.model_wrapper.decrypt_model_for_inference(
    model_id="classifier_v1"
)

# Checksum is automatically verified
```

### Attestation

#### Quote Types

| Platform | Quote Type | Verification |
|----------|------------|--------------|
| Intel SGX | EPID | Intel Attestation Service |
| Intel SGX | ECDSA | Intel DCAP |
| AMD SEV | SNP | AMD ASP |

#### Verification Process

```python
from specter.security import AttestationVerifier, TrustPolicy

# Create verifier with custom policy
policy = TrustPolicy()
policy.add_rule({
    "name": "require_production",
    "condition": "is_debug == false",
    "action": "allow",
})

verifier = AttestationVerifier(trust_policy=policy)

# Verify evidence
report = verifier.verify_attestation(evidence, {
    "mrenclave": "0x1234...",
    "mrsigner": "0x5678...",
    "isvsvn": 2,  # Minimum security version
})

print(f"Status: {report.status.value}")
print(f"Verified: {report.is_valid()}")
```

### Secure Inference

#### Running Inference

```python
# With attestation
response = specter.run_secure_inference(
    model_id="classifier_v1",
    input_data=image_bytes,
)

print(f"Output: {response.output_data}")
print(f"Time: {response.inference_time_ms:.2f}ms")
print(f"Attestation: {response.attestation_evidence is not None}")
```

#### Custom Inference Pipeline

```python
# Get decrypted weights for custom processing
weights, key_id = specter.model_wrapper.decrypt_model_for_inference(
    "classifier_v1",
    enclave_context=enclave,
)

# Use weights with your ML framework
import torch
state_dict = torch.load(weights)

model = MyModel()
model.load_state_dict(state_dict)
model.eval()

# Run inference
with torch.no_grad():
    output = model(input_tensor)

# Re-encrypt output if needed
encrypted_output = specter.tee.encrypt_in_enclave(
    output.numpy().tobytes(),
    decryption_key
)
```

### Federated Learning

#### Coordinator Setup

```python
from specter.ml import FederatedLearningCoordinator

coordinator = FederatedLearningCoordinator(
    tee_module=specter.tee,
    key_manager=specter.key_manager,
    privacy_config={
        "noise_multiplier": 1.0,
        "max_grad_norm": 1.0,
        "secure_aggregation": True,
        "minimum_clients": 3,
    }
)

# Initialize global model
global_model = coordinator.initialize_global_model(
    model_id="fl_global_v1",
    architecture={"input_shape": (10,), "output_shape": (2,)}
)
```

#### Client Registration

```python
# Server: Register a client
token = coordinator.register_client(
    client_id="client_001",
    client_info={"organization": "Hospital A", "data_size": 10000}
)

# Client receives token and uses it to fetch model
model, update_token = coordinator.distribute_model_to_client("client_001")
```

#### Aggregation

```python
# After clients submit updates
aggregated = coordinator.aggregate_updates(min_updates=3)

if aggregated:
    coordinator.apply_update(aggregated)
    print(f"Round {coordinator._round_number} completed")

# Check status
status = coordinator.get_round_status()
print(f"Active clients: {status['active_clients']}")
print(f"Updates received: {status['updates_received']}")
```

### Key Management

#### Hierarchical Keys

```python
from specter.security import KeyStore, KeyType, KeyUsage, KeySource

store = KeyStore(master_password="strong_password")

# Generate master key
master_key, master_id = store.generate_key(
    key_type=KeyType.MASTER,
    usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.DERIVE],
    source=KeySource.SOFTWARE,
)

# Generate data encryption key
dek, dek_id = store.generate_key(
    key_type=KeyType.DEK,
    usage=[KeyUsage.ENCRYPT, KeyUsage.DECRYPT],
    parent_key_id=master_id,
)

# Derive child key
derived, derived_id = store.derive_child_key(
    parent_key_id=dek_id,
    context=b"session_123",
)
```

#### Key Rotation

```python
# Rotate a key
new_key, new_id = store.rotate_key(dek_id)

# Revoke a key
store.revoke_key(old_key_id)

# List keys
active_keys = store.list_keys(include_revoked=False)
```

---

## API Reference

### Python SDK

#### SpecterClient

```python
from specter.api import create_client

client = create_client(
    base_url="http://localhost:8080/api/v1",
    api_key="optional_api_key",
)

# Health check
info = client.health_check()

# TEE operations
tee_info = client.get_tee_info()

# Model operations
client.upload_model(
    model_id="my_model",
    weights_path="model.bin",
    architecture={"input_shape": [1, 10]},
)

# Run inference
result = client.run_inference(
    model_id="my_model",
    input_data="input.bin",
    return_attestation=True,
)

client.close()
```

### REST API

#### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/tee/info` | TEE information |
| POST | `/api/v1/enclaves` | Create enclave |
| GET | `/api/v1/enclaves` | List enclaves |
| POST | `/api/v1/enclaves/{id}/attest` | Generate attestation |
| POST | `/api/v1/keys` | Generate key |
| GET | `/api/v1/keys` | List keys |
| POST | `/api/v1/models` | Upload model |
| POST | `/api/v1/inference` | Run inference |
| POST | `/api/v1/fl/clients/register` | Register FL client |
| POST | `/api/v1/fl/aggregate` | Trigger aggregation |

### CLI

```bash
# Global options
--url URL           API base URL (default: http://localhost:8080/api/v1)
-v, --verbose       Enable verbose output

# Commands
specter-cli health                    # Health check
specter-cli tee-info                  # TEE information
specter-cli enclave-create PATH       # Create enclave
specter-cli attest ENCLAVE_ID         # Generate attestation
specter-cli verify EVIDENCE_FILE     # Verify attestation
specter-cli key-generate              # Generate key
specter-cli model-upload ID WEIGHTS  # Upload model
specter-cli inference ID INPUT        # Run inference
specter-cli fl-register CLIENT_ID     # Register FL client
specter-cli fl-status                 # FL status
```

---

## Configuration

### Configuration File

```json
{
  "tee_type": "auto",
  "tee_config": {
    "simulation_mode": false,
    "quote_type": "ecdsa"
  },
  "storage_path": "/var/lib/specter",
  "model_storage_path": "/var/lib/specter/models",
  "key_storage_path": "/var/lib/specter/keystore",
  "enable_encryption": true,
  "api_host": "0.0.0.0",
  "api_port": 8080,
  "log_level": "INFO",
  "fl_min_clients": 2,
  "fl_timeout": 300
}
```

### Environment Variables

```bash
export SPECTER_TEE_TYPE=auto
export SPECTER_MASTER_PASSWORD=your_password
export SPECTER_API_HOST=0.0.0.0
export SPECTER_API_PORT=8080
export SPECTER_API_KEY=your_api_key
export SPECTER_LOG_LEVEL=INFO
```

---

## Security Considerations

### Production Checklist

- [ ] Enable TEE hardware (SGX/SEV) in BIOS
- [ ] Use production quote verification (DCAP/VCEK)
- [ ] Secure master password storage
- [ ] Enable debug mode only in development
- [ ] Rotate keys regularly
- [ ] Monitor attestation reports
- [ ] Use secure network connections (TLS)
- [ ] Implement proper access controls

### Known Limitations

1. **Memory Limits**: SGX has limited EPC memory (128MB default)
2. **Performance Overhead**: TEE operations have 5-15% overhead
3. **Platform Specific**: Attestation quotes are platform-specific
4. **Key HSM**: Master key should be backed by HSM in production

---

## Performance

### Benchmarks

| Operation | Overhead vs Plaintext |
|-----------|----------------------|
| Model Decryption | ~10-15% |
| Inference | ~5-10% |
| Encryption | ~5-10% |
| Attestation | ~50-100ms |

### Optimization Tips

1. **Batch Operations**: Process multiple inferences together
2. **Model Quantization**: Use INT8/FP16 for faster inference
3. **Cache Decrypted Models**: Keep in enclave memory when possible
4. **Async Operations**: Use async API for better throughput

---

## Troubleshooting

### Common Issues

#### SGX Not Available
```bash
# Check SGX status
dmesg | grep -i sgx

# Enable SGX
echo 1 | sudo tee /sys/module/sgx_enclave/parameters/debug

# Check CPU support
grep sgx /proc/cpuinfo
```

#### SEV Not Available
```bash
# Check SEV status
dmesg | grep -i sev

# Check KVM support
ls /dev/kvm

# Verify AMD processor
grep -i "AMD" /proc/cpuinfo
```

#### Attestation Fails
```python
# Use simulation mode for debugging
specter = Specter(tee_type="none", config={"simulation_mode": True})

# Check certificate chain
verifier = AttestationVerifier()
# Enable debug logging
import logging
logging.getLogger("specter").setLevel(logging.DEBUG)
```

---

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

```bash
# Development setup
git clone https://github.com/moggan1337/Specter.git
cd Specter
pip install -e ".[dev,api,ml]"

# Run tests
pytest tests/

# Format code
black specter/
isort specter/
flake8 specter/
```

---

## License

MIT License

Copyright (c) 2024 Specter Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

<p align="center">
  <strong>Specter</strong> - Confidential Computing for AI/ML
</p>
