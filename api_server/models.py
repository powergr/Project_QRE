# api_server/models.py
from pydantic import BaseModel, Field
from typing import List, Optional

# --- Common Base Models ---
class BaseRequest(BaseModel):
    pass

class BaseResponse(BaseModel):
    pass

# --- Encryption Models ---
class EncryptPayloadB64(BaseRequest): # Generic for plaintext input
    plaintext_b64: str = Field(..., description="Base64 encoded plaintext bytes.")

class EncryptKdfPayloadB64(EncryptPayloadB64): # Inherits plaintext_b64
    password_b64: str = Field(..., description="Base64 encoded password for KDF.")
    additional_kdf_inputs_b64: List[str] = Field(default_factory=list, 
                                                 description="List of Base64 encoded additional inputs for KDF.")

# Generic Encryption Response (Ciphertext for non-QNE routes)
class CiphertextResponse(BaseResponse):
    ciphertext_b64: str = Field(..., description="Base64 encoded final ciphertext bytes.")

# Specific for QNE Encryption (QNE key is returned for PoC)
class QNEEncryptResponse(BaseResponse):
    final_ciphertext_b64: str = Field(..., description="Base64 encoded final (QNE-wrapped) ciphertext.")
    qne_layer_key_b64: str = Field(..., description="Base64 encoded AES-GCM key for the QNE layer (PoC only).")


# --- Decryption Models ---
class DecryptPayloadB64(BaseRequest): # Generic for ciphertext input
    ciphertext_b64: str = Field(..., description="Base64 encoded ciphertext to decrypt.")

class DecryptKdfPayloadB64(DecryptPayloadB64): # Inherits ciphertext_b64
    password_b64: str = Field(..., description="Base64 encoded password for KDF.")
    additional_kdf_inputs_b64: List[str] = Field(default_factory=list,
                                                 description="List of Base64 encoded additional inputs for KDF.")

class DecryptLayeredQNERequest(BaseRequest):
    final_ciphertext_b64: str = Field(..., description="The QNE-wrapped ciphertext from the corresponding encrypt operation.")
    qne_layer_key_b64: str = Field(..., description="Base64 encoded AES-GCM key for the QNE layer (from encrypt PoC response).")

class DecryptParallelKdfQNERequest(BaseRequest):
    final_ciphertext_b64: str = Field(..., description="The QNE-wrapped ciphertext from the corresponding encrypt operation.")
    password_b64: str # For the inner KDF
    additional_kdf_inputs_b64: List[str] = Field(default_factory=list) # For inner KDF
    qne_layer_key_b64: str # Key for the outer QNE layer

# Generic Decryption Response (Plaintext)
class PlaintextResponse(BaseResponse):
    plaintext_b64: str = Field(..., description="Base64 encoded decrypted plaintext bytes.")


# --- Key Management Models ---
class DeleteKeyResponse(BaseResponse):
    status: str = Field(..., example="deleted")
    key_id_hex: str = Field(..., description="Hex representation of the key_id that was processed.")

class GeneralErrorResponse(BaseModel): # For documenting error responses in OpenAPI
    detail: str