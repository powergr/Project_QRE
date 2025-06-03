# api_server/routers/encryption.py
from fastapi import APIRouter, Depends, HTTPException, status, Request
import base64
from typing import List, Optional

# Models from the same package (api_server)
from ..models import (
    EncryptPayloadB64, EncryptKdfPayloadB64, # Using these more specific request models
    CiphertextResponse, QNEEncryptResponse,
    DecryptPayloadB64, DecryptKdfPayloadB64,
    DecryptLayeredQNERequest, DecryptParallelKdfQNERequest, # Specific QNE decrypt models
    PlaintextResponse
)
from ..core.security import verify_api_key 

# --- Import your actual encryption logic functions ---
# Ensure these are correctly imported from where they are defined.
# For this example, assuming main_unified_poc.py or a similar module is accessible.
WRAPPERS_LOADED = False
try:
    from main_unified_poc import ( 
        encrypt_layered_with_qne, decrypt_layered_with_qne,
        encrypt_parallel_kdf_with_qne, decrypt_parallel_kdf_with_qne
    )
    from epic1_modules.layered_encryption_vault import layered_encrypt_vault, layered_decrypt_vault
    from epic1_modules.parallel_encryption_vault import parallel_encrypt_vault, parallel_decrypt_vault
    WRAPPERS_LOADED = True
except ImportError as e:
    print(f"WARNING: [api_server/routers/encryption.py] Could not load all encryption functions: {e}")


router = APIRouter(
    tags=["Encryption & Decryption"],
    dependencies=[Depends(verify_api_key)] 
)

# Helper for error handling
def handle_crypto_errors(e: Exception, operation_name: str):
    if isinstance(e, base64.binascii.Error):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid base64 encoding in request for {operation_name}.")
    elif isinstance(e, ValueError): 
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{operation_name} input error: {str(e)}")
    elif isinstance(e, RuntimeError): 
        if "Vault" in str(e) or "KEM" in str(e) or "AES" in str(e) or "Unpadding" in str(e) or "QNE Layer" in str(e):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"{operation_name} processing error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Internal server error during {operation_name}: {str(e)}")
    else: 
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Unexpected error during {operation_name}: {str(e)}")


# --- Layered Encryption Endpoints ---
@router.post("/encrypt/layered", response_model=CiphertextResponse, summary="Layered Encryption (Epic 1)")
async def api_encrypt_layered(request_data: EncryptPayloadB64): # Changed model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="Core encryption logic (layered_encrypt_vault) not loaded.")
    try:
        plaintext_bytes = base64.b64decode(request_data.plaintext_b64)
        ciphertext_bytes = layered_encrypt_vault(plaintext_bytes)
        return CiphertextResponse(ciphertext_b64=base64.b64encode(ciphertext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Layered Encryption")

@router.post("/decrypt/layered", response_model=PlaintextResponse, summary="Layered Decryption (Epic 1)")
async def api_decrypt_layered(request_data: DecryptPayloadB64): # Changed model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="Core encryption logic (layered_decrypt_vault) not loaded.")
    try:
        ciphertext_bytes = base64.b64decode(request_data.ciphertext_b64)
        plaintext_bytes = layered_decrypt_vault(ciphertext_bytes)
        return PlaintextResponse(plaintext_b64=base64.b64encode(plaintext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Layered Decryption")

# --- Parallel Encryption (Random K1) Endpoints ---
@router.post("/encrypt/parallel/random", response_model=CiphertextResponse, summary="Parallel Encryption with Random K1 (Epic 1)")
async def api_encrypt_parallel_random(request_data: EncryptPayloadB64): # Changed model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="Core encryption logic (parallel_encrypt_vault) not loaded.")
    try:
        plaintext_bytes = base64.b64decode(request_data.plaintext_b64)
        ciphertext_bytes = parallel_encrypt_vault(plaintext_bytes) # Call without password/factors
        return CiphertextResponse(ciphertext_b64=base64.b64encode(ciphertext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Parallel Encryption (Random K1)")

@router.post("/decrypt/parallel/random", response_model=PlaintextResponse, summary="Parallel Decryption with Random K1 (Epic 1)")
async def api_decrypt_parallel_random(request_data: DecryptPayloadB64): # Changed model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="Core encryption logic (parallel_decrypt_vault) not loaded.")
    try:
        ciphertext_bytes = base64.b64decode(request_data.ciphertext_b64)
        plaintext_bytes = parallel_decrypt_vault(ciphertext_bytes) # Call without password/factors
        return PlaintextResponse(plaintext_b64=base64.b64encode(plaintext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Parallel Decryption (Random K1)")

# --- Parallel Encryption (KDF K1) Endpoints ---
@router.post("/encrypt/parallel/kdf", response_model=CiphertextResponse, summary="Parallel Encryption with KDF-derived K1")
async def api_encrypt_parallel_kdf(request_data: EncryptKdfPayloadB64): # Changed model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="Core encryption logic (parallel_encrypt_vault) not loaded.")
    try:
        plaintext_bytes = base64.b64decode(request_data.plaintext_b64)
        password_bytes = base64.b64decode(request_data.password_b64)
        additional_inputs_bytes = [base64.b64decode(s) for s in request_data.additional_kdf_inputs_b64]
        
        ciphertext_bytes = parallel_encrypt_vault(
            plaintext_bytes, 
            password=password_bytes, 
            additional_kdf_inputs=additional_inputs_bytes
        )
        return CiphertextResponse(ciphertext_b64=base64.b64encode(ciphertext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Parallel Encryption (KDF K1)")

@router.post("/decrypt/parallel/kdf", response_model=PlaintextResponse, summary="Parallel Decryption with KDF-derived K1")
async def api_decrypt_parallel_kdf(request_data: DecryptKdfPayloadB64): # Changed model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="Core encryption logic (parallel_decrypt_vault) not loaded.")
    try:
        ciphertext_bytes = base64.b64decode(request_data.ciphertext_b64)
        password_bytes = base64.b64decode(request_data.password_b64)
        additional_inputs_bytes = [base64.b64decode(s) for s in request_data.additional_kdf_inputs_b64]

        plaintext_bytes = parallel_decrypt_vault(
            ciphertext_bytes,
            password=password_bytes,
            additional_kdf_inputs=additional_inputs_bytes
        )
        return PlaintextResponse(plaintext_b64=base64.b64encode(plaintext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Parallel Decryption (KDF K1)")

# --- QNE-Infused Endpoints ---
@router.post("/encrypt/layered_qne", response_model=QNEEncryptResponse, summary="Layered Encryption + QNE Infusion")
async def api_encrypt_layered_qne(request_data: EncryptPayloadB64, fastapi_request: Request): # Model for simple plaintext
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="QNE wrapper logic (encrypt_layered_with_qne) not loaded.")
    qne_pool = fastapi_request.app.state.qne_pool 
    if not qne_pool:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="QNE Pool not available for API.")
    try:
        plaintext_bytes = base64.b64decode(request_data.plaintext_b64)
        final_ciphertext, qne_key_poc = encrypt_layered_with_qne(plaintext_bytes, qne_pool)
        return QNEEncryptResponse(
            final_ciphertext_b64=base64.b64encode(final_ciphertext).decode(),
            qne_layer_key_b64=base64.b64encode(qne_key_poc).decode()
        )
    except Exception as e:
        handle_crypto_errors(e, "Layered Encryption with QNE")

@router.post("/decrypt/layered_qne", response_model=PlaintextResponse, summary="Decrypt QNE-Infused Layered Ciphertext")
async def api_decrypt_layered_qne(request_data: DecryptLayeredQNERequest): # Specific model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="QNE wrapper logic (decrypt_layered_with_qne) not loaded.")
    try:
        final_ciphertext_bytes = base64.b64decode(request_data.final_ciphertext_b64)
        qne_key_bytes = base64.b64decode(request_data.qne_layer_key_b64)
        plaintext_bytes = decrypt_layered_with_qne(final_ciphertext_bytes, qne_key_bytes)
        return PlaintextResponse(plaintext_b64=base64.b64encode(plaintext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Layered QNE Decryption")

@router.post("/encrypt/parallel_kdf_qne", response_model=QNEEncryptResponse, summary="Parallel KDF Encryption + QNE Infusion")
async def api_encrypt_parallel_kdf_qne(request_data: EncryptKdfPayloadB64, fastapi_request: Request): # Model for PT, Pass, Factors
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="QNE wrapper logic (encrypt_parallel_kdf_with_qne) not loaded.")
    qne_pool = fastapi_request.app.state.qne_pool
    if not qne_pool:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="QNE Pool not available for API.")
    try:
        plaintext_bytes = base64.b64decode(request_data.plaintext_b64)
        password_bytes = base64.b64decode(request_data.password_b64)
        additional_inputs_bytes = [base64.b64decode(s) for s in request_data.additional_kdf_inputs_b64]

        final_ciphertext, qne_key_poc = encrypt_parallel_kdf_with_qne(
            plaintext_bytes, password_bytes, additional_inputs_bytes, qne_pool
        )
        return QNEEncryptResponse(
            final_ciphertext_b64=base64.b64encode(final_ciphertext).decode(),
            qne_layer_key_b64=base64.b64encode(qne_key_poc).decode()
        )
    except Exception as e:
        handle_crypto_errors(e, "Parallel KDF Encryption with QNE")

@router.post("/decrypt/parallel_kdf_qne", response_model=PlaintextResponse, summary="Decrypt QNE-Infused Parallel KDF Ciphertext")
async def api_decrypt_parallel_kdf_qne(request_data: DecryptParallelKdfQNERequest): # Specific model
    if not WRAPPERS_LOADED: raise HTTPException(status_code=503, detail="QNE wrapper logic (decrypt_parallel_kdf_with_qne) not loaded.")
    try:
        final_ciphertext_bytes = base64.b64decode(request_data.final_ciphertext_b64)
        password_bytes = base64.b64decode(request_data.password_b64)
        additional_inputs_bytes = [base64.b64decode(s) for s in request_data.additional_kdf_inputs_b64]
        qne_key_bytes = base64.b64decode(request_data.qne_layer_key_b64)

        plaintext_bytes = decrypt_parallel_kdf_with_qne(
            final_ciphertext_bytes, password_bytes, additional_inputs_bytes, qne_key_bytes
        )
        return PlaintextResponse(plaintext_b64=base64.b64encode(plaintext_bytes).decode())
    except Exception as e:
        handle_crypto_errors(e, "Parallel KDF QNE Decryption")