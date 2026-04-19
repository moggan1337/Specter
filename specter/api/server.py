"""
Specter REST API Server
=======================
FastAPI-based REST API for Specter framework.
"""

import os
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from specter.tee import create_tee, TEEType
from specter.security import (
    KeyManager,
    KeyType,
    AttestationVerifier,
    AttestationReport,
)
from specter.ml import SecureModelWrapper, FederatedLearningCoordinator

logger = logging.getLogger(__name__)


# Request/Response Models
class CreateEnclaveRequest(BaseModel):
    enclave_path: str
    config: Optional[Dict[str, Any]] = None


class GenerateAttestationRequest(BaseModel):
    report_data: Optional[str] = None  # Hex-encoded


class VerifyAttestationRequest(BaseModel):
    evidence: Dict[str, Any]
    expected_identity: Optional[Dict[str, Any]] = None


class GenerateKeyRequest(BaseModel):
    key_type: str = "data_encryption"
    usage: Optional[List[str]] = None


class UploadModelRequest(BaseModel):
    model_id: str
    weights: str  # Hex-encoded
    architecture: Dict[str, Any]
    key_id: Optional[str] = None


class RunInferenceRequest(BaseModel):
    model_id: str
    input_data: str  # Hex-encoded
    return_attestation: bool = True


class FLRegisterRequest(BaseModel):
    client_id: str
    client_info: Dict[str, Any]


class FLUpdateRequest(BaseModel):
    gradients: str  # Hex-encoded
    attestation: Optional[str] = None


# Global state
app_state: Dict[str, Any] = {}


def get_tee():
    """Get TEE instance."""
    if "tee" not in app_state:
        app_state["tee"] = create_tee("auto", {"simulation_mode": True})
        app_state["tee"].initialize()
    return app_state["tee"]


def get_key_manager():
    """Get key manager instance."""
    if "key_manager" not in app_state:
        app_state["key_manager"] = KeyManager()
    return app_state["key_manager"]


def get_model_wrapper():
    """Get secure model wrapper."""
    if "model_wrapper" not in app_state:
        tee = get_tee()
        key_manager = get_key_manager()
        app_state["model_wrapper"] = SecureModelWrapper(tee, key_manager)
    return app_state["model_wrapper"]


def get_fl_coordinator():
    """Get federated learning coordinator."""
    if "fl_coordinator" not in app_state:
        tee = get_tee()
        key_manager = get_key_manager()
        app_state["fl_coordinator"] = FederatedLearningCoordinator(tee, key_manager)
    return app_state["fl_coordinator"]


def get_attestation_verifier():
    """Get attestation verifier."""
    if "attestation_verifier" not in app_state:
        app_state["attestation_verifier"] = AttestationVerifier()
    return app_state["attestation_verifier"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager."""
    logger.info("Starting Specter API server")
    yield
    # Cleanup
    if "tee" in app_state:
        app_state["tee"].shutdown()
    logger.info("Specter API server stopped")


# Create FastAPI app
app = FastAPI(
    title="Specter API",
    description="Confidential Computing AI Framework",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health & Info Endpoints
@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
    }


@app.get("/api/v1/info")
async def get_info():
    """Get service information."""
    tee = get_tee()
    tee_info = tee.get_tee_info()
    
    return {
        "service": "Specter",
        "version": "1.0.0",
        "tee_type": tee_info.tee_type.value,
        "tee_available": tee.is_available(),
        "capabilities": tee_info.capabilities,
    }


# TEE Endpoints
@app.get("/api/v1/tee/info")
async def get_tee_info():
    """Get TEE information."""
    tee = get_tee()
    info = tee.get_tee_info()
    
    return {
        "tee_type": info.tee_type.value,
        "version": info.version,
        "capabilities": info.capabilities,
        "is_debug_enabled": info.is_debug_enabled,
        "is_production": info.is_production,
    }


@app.get("/api/v1/tee/availability")
async def check_tee_availability():
    """Check TEE availability."""
    tee = get_tee()
    
    return {
        "available": tee.is_available(),
        "tee_type": tee.tee_type.value,
    }


# Enclave Endpoints
@app.post("/api/v1/enclaves")
async def create_enclave(request: CreateEnclaveRequest):
    """Create a new enclave."""
    tee = get_tee()
    
    try:
        context = tee.create_enclave(request.enclave_path, request.config)
        
        enclave_id = hashlib.sha256(
            f"{request.enclave_path}{time.time()}".encode()
        ).hexdigest()[:16]
        
        app_state["enclaves"] = app_state.get("enclaves", {})
        app_state["enclaves"][enclave_id] = {
            "id": enclave_id,
            "path": request.enclave_path,
            "context": context,
            "created_at": int(time.time()),
        }
        
        return {
            "enclave_id": enclave_id,
            "path": request.enclave_path,
            "created_at": int(time.time()),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/enclaves")
async def list_enclaves():
    """List all enclaves."""
    enclaves = app_state.get("enclaves", {})
    
    return [
        {
            "enclave_id": e["id"],
            "path": e["path"],
            "created_at": e["created_at"],
        }
        for e in enclaves.values()
    ]


@app.get("/api/v1/enclaves/{enclave_id}")
async def get_enclave(enclave_id: str):
    """Get enclave information."""
    enclaves = app_state.get("enclaves", {})
    
    if enclave_id not in enclaves:
        raise HTTPException(status_code=404, detail="Enclave not found")
    
    return {
        "enclave_id": enclaves[enclave_id]["id"],
        "path": enclaves[enclave_id]["path"],
        "created_at": enclaves[enclave_id]["created_at"],
    }


@app.delete("/api/v1/enclaves/{enclave_id}")
async def destroy_enclave(enclave_id: str):
    """Destroy an enclave."""
    enclaves = app_state.get("enclaves", {})
    
    if enclave_id not in enclaves:
        raise HTTPException(status_code=404, detail="Enclave not found")
    
    tee = get_tee()
    tee.destroy_enclave(enclaves[enclave_id]["context"].handle)
    del enclaves[enclave_id]
    
    return {"status": "destroyed", "enclave_id": enclave_id}


@app.post("/api/v1/enclaves/{enclave_id}/attest")
async def generate_attestation(enclave_id: str, request: GenerateAttestationRequest):
    """Generate attestation evidence."""
    enclaves = app_state.get("enclaves", {})
    
    if enclave_id not in enclaves:
        raise HTTPException(status_code=404, detail="Enclave not found")
    
    tee = get_tee()
    context = enclaves[enclave_id]["context"]
    
    report_data = b""
    if request.report_data:
        report_data = bytes.fromhex(request.report_data)
    
    evidence = tee.generate_attestation_evidence(report_data, context.handle)
    
    return {
        "enclave_id": enclave_id,
        "quote_type": evidence.quote_type.value,
        "quote": evidence.quote.hex(),
        "report_data": evidence.report_data.hex(),
        "signature": evidence.signature.hex(),
        "certificate_chain": [c.hex() for c in evidence.certificate_chain],
        "timestamp": evidence.timestamp,
    }


# Attestation Endpoints
@app.post("/api/v1/attestation/verify")
async def verify_attestation(request: VerifyAttestationRequest):
    """Verify attestation evidence."""
    from specter.tee.base import AttestationEvidence, QuoteType
    
    verifier = get_attestation_verifier()
    
    evidence = AttestationEvidence(
        quote=bytes.fromhex(request.evidence["quote"]),
        quote_type=QuoteType(request.evidence["quote_type"]),
        report_data=bytes.fromhex(request.evidence["report_data"]),
        signature=bytes.fromhex(request.evidence["signature"]),
        certificate_chain=[
            bytes.fromhex(c) for c in request.evidence["certificate_chain"]
        ],
        timestamp=request.evidence["timestamp"],
        raw_measurements={},
    )
    
    result = verifier.verify_attestation(evidence, request.expected_identity)
    
    return result.to_dict()


# Key Management Endpoints
@app.post("/api/v1/keys")
async def generate_key(request: GenerateKeyRequest):
    """Generate a new key."""
    key_manager = get_key_manager()
    
    usage = None
    if request.usage:
        from specter.security import KeyUsage
        usage = [KeyUsage(u) for u in request.usage]
    
    key_type = KeyType(request.key_type)
    key, key_id = key_manager.keystore.generate_key(
        key_type=key_type,
        usage=usage,
    )
    
    return {
        "key_id": key_id,
        "key_type": key_type.value,
        "created_at": int(time.time()),
    }


@app.get("/api/v1/keys")
async def list_keys(key_type: Optional[str] = None, include_revoked: bool = False):
    """List keys."""
    key_manager = get_key_manager()
    
    k_type = KeyType(key_type) if key_type else None
    keys = key_manager.keystore.list_keys(
        key_type=k_type,
        include_revoked=include_revoked,
    )
    
    return [k.to_dict() for k in keys]


@app.get("/api/v1/keys/{key_id}")
async def get_key_info(key_id: str):
    """Get key information."""
    key_manager = get_key_manager()
    metadata = key_manager.keystore.get_metadata(key_id)
    
    if not metadata:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return metadata.to_dict()


@app.post("/api/v1/keys/{key_id}/revoke")
async def revoke_key(key_id: str):
    """Revoke a key."""
    key_manager = get_key_manager()
    success = key_manager.keystore.revoke_key(key_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return {"status": "revoked", "key_id": key_id}


@app.post("/api/v1/keys/{key_id}/rotate")
async def rotate_key(key_id: str):
    """Rotate a key."""
    key_manager = get_key_manager()
    result = key_manager.keystore.rotate_key(key_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Key not found")
    
    new_key, new_key_id = result
    return {
        "old_key_id": key_id,
        "new_key_id": new_key_id,
    }


# Model Endpoints
@app.post("/api/v1/models")
async def upload_model(request: UploadModelRequest):
    """Upload and encrypt a model."""
    model_wrapper = get_model_wrapper()
    
    weights = bytes.fromhex(request.weights)
    
    model = model_wrapper.encrypt_and_store_model(
        model_id=request.model_id,
        weights=weights,
        architecture=request.architecture,
    )
    
    return {
        "model_id": model.model_id,
        "checksum": model.checksum,
        "format": model.format,
        "encryption_metadata": model.encryption_metadata,
    }


@app.get("/api/v1/models")
async def list_models():
    """List models."""
    model_wrapper = get_model_wrapper()
    return list(model_wrapper._models.keys())


@app.get("/api/v1/models/{model_id}")
async def get_model(model_id: str):
    """Get model information."""
    model_wrapper = get_model_wrapper()
    
    if model_id not in model_wrapper._models:
        raise HTTPException(status_code=404, detail="Model not found")
    
    model = model_wrapper._models[model_id]
    return model.to_dict()


@app.delete("/api/v1/models/{model_id}")
async def delete_model(model_id: str):
    """Delete a model."""
    model_wrapper = get_model_wrapper()
    
    if model_id in model_wrapper._models:
        del model_wrapper._models[model_id]
    
    return {"status": "deleted", "model_id": model_id}


# Inference Endpoints
@app.post("/api/v1/inference")
async def run_inference(request: RunInferenceRequest):
    """Run secure inference."""
    model_wrapper = get_model_wrapper()
    tee = get_tee()
    
    input_data = bytes.fromhex(request.input_data)
    
    # Get or create enclave context
    enclaves = app_state.get("enclaves", {})
    context = None
    if enclaves:
        context = list(enclaves.values())[0]["context"]
    
    result = model_wrapper.run_inference(
        model_id=request.model_id,
        input_data=input_data,
        enclave_context=context.handle if context else None,
        return_attestation=request.return_attestation,
    )
    
    response = {
        "request_id": result.request_id,
        "output_data": result.output_data.hex(),
        "output_shape": list(result.output_shape),
        "inference_time_ms": result.inference_time_ms,
        "error": result.error,
    }
    
    if result.attestation_evidence:
        response["attestation_evidence"] = result.attestation_evidence.hex()
    
    return response


# Federated Learning Endpoints
@app.post("/api/v1/fl/clients/register")
async def fl_register_client(request: FLRegisterRequest):
    """Register a federated learning client."""
    fl_coordinator = get_fl_coordinator()
    
    token = fl_coordinator.register_client(request.client_id, request.client_info)
    
    return {
        "client_id": request.client_id,
        "token": token,
        "registered_at": int(time.time()),
    }


@app.get("/api/v1/fl/clients/{client_id}/model")
async def fl_get_model(client_id: str):
    """Get global model for client."""
    fl_coordinator = get_fl_coordinator()
    
    try:
        model, update_token = fl_coordinator.distribute_model_to_client(client_id)
        
        return {
            "model_id": model.model_id,
            "encrypted_weights": model.encrypted_weights.hex(),
            "update_token": update_token,
            "architecture": model.model_architecture,
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/fl/clients/{client_id}/update")
async def fl_submit_update(client_id: str, request: FLUpdateRequest):
    """Submit gradient update from client."""
    fl_coordinator = get_fl_coordinator()
    
    gradients = bytes.fromhex(request.gradients)
    attestation = bytes.fromhex(request.attestation) if request.attestation else None
    
    success = fl_coordinator.receive_client_update(
        client_id=client_id,
        update_token=request.gradients[:32],  # Simplified
        encrypted_gradients=gradients,
        client_attestation=attestation,
    )
    
    return {
        "client_id": client_id,
        "accepted": success,
    }


@app.get("/api/v1/fl/status")
async def fl_get_status():
    """Get federated learning status."""
    fl_coordinator = get_fl_coordinator()
    return fl_coordinator.get_round_status()


@app.post("/api/v1/fl/aggregate")
async def fl_trigger_aggregation():
    """Trigger aggregation of updates."""
    fl_coordinator = get_fl_coordinator()
    
    aggregated = fl_coordinator.aggregate_updates()
    
    if aggregated:
        fl_coordinator.apply_update(aggregated)
        return {"status": "aggregated", "round": fl_coordinator._round_number}
    else:
        return {"status": "pending", "reason": "Insufficient updates"}


def run_server(host: str = "0.0.0.0", port: int = 8080, reload: bool = False):
    """Run the API server."""
    import uvicorn
    
    uvicorn.run(
        "specter.api.server:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    run_server()
