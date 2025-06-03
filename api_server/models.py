# api_server/models.py
from pydantic import BaseModel, Field
from typing import List, Optional

# --- Common Base Models ---
class BaseRequest(BaseModel):
    """Base model for API requests, can be extended."""
    pass

class BaseResponse(BaseModel):
    """Base model for API responses, can be extended."""
    pass

# --- Encryption Models ---
class EncryptPayloadB64(BaseRequest):
    """Request model for endpoints requiring only plaintext for encryption."""
    plaintext_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the plaintext to be encrypted.",
        example="SGVsbG8gV29ybGQh" # "Hello World!"
    )

class EncryptKdfPayloadB64(EncryptPayloadB64):
    """
    Request model for encryption endpoints that use a Key Derivation Function (KDF)
    requiring a password and additional factors. Inherits plaintext_b64.
    """
    password_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the user's password for KDF.",
        example="U3VwZXJTZWN1cmVQYXNzd29yZCE=" # "SuperSecurePassword!"
    )
    additional_kdf_inputs_b64: List[str] = Field(
        default_factory=list, 
        description="List of Base64 encoded byte strings representing additional factors for KDF (e.g., device ID, session data).",
        example=["ZmFjdG9yMQ==", "ZmFjdG9yMg=="] # "factor1", "factor2"
    )

# Generic Encryption Response (Ciphertext for non-QNE routes)
class CiphertextResponse(BaseResponse):
    """Response model containing the resulting ciphertext."""
    ciphertext_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the final ciphertext. This typically includes a key_id prepended, which is used by the decryption endpoints to retrieve necessary keys from Vault."
    )

# Specific for QNE Encryption (QNE key is returned for PoC)
class QNEEncryptResponse(BaseResponse):
    """
    Response model for QNE-infused encryption operations.
    Includes the final ciphertext and, for PoC purposes, the transient key used for the QNE layer.
    """
    final_ciphertext_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the final, QNE-wrapped ciphertext."
    )
    qne_layer_key_b64: str = Field(
        ..., 
        description="Base64 encoded AES-GCM key used for the outer QNE layer. This is returned for PoC testing and would be managed differently in production."
    )

# --- Decryption Models ---
class DecryptPayloadB64(BaseRequest):
    """Request model for endpoints requiring only ciphertext for decryption."""
    ciphertext_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the ciphertext to be decrypted. It's expected to contain a prepended key_id for Vault key retrieval."
    )

class DecryptKdfPayloadB64(DecryptPayloadB64):
    """
    Request model for decryption endpoints where a KDF was used for key generation.
    Inherits ciphertext_b64 and adds password/additional factors for key re-derivation.
    """
    password_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the user's password, used to re-derive the encryption key via KDF."
    )
    additional_kdf_inputs_b64: List[str] = Field(
        default_factory=list,
        description="List of Base64 encoded byte strings for additional factors, matching those used during encryption for KDF."
    )

class DecryptLayeredQNERequest(BaseRequest):
    """Request model for decrypting QNE-infused layered ciphertexts."""
    final_ciphertext_b64: str = Field(
        ..., 
        description="The QNE-wrapped ciphertext (Base64 encoded) from the corresponding layered QNE encryption operation."
    )
    qne_layer_key_b64: str = Field(
        ..., 
        description="Base64 encoded AES-GCM key for the outer QNE layer (obtained from the PoC encryption response)."
    )

class DecryptParallelKdfQNERequest(BaseRequest):
    """Request model for decrypting QNE-infused parallel KDF ciphertexts."""
    final_ciphertext_b64: str = Field(
        ..., 
        description="The QNE-wrapped ciphertext (Base64 encoded) from the corresponding parallel KDF QNE encryption."
    )
    password_b64: str = Field(..., description="Base64 encoded password for re-deriving the inner K1 key.")
    additional_kdf_inputs_b64: List[str] = Field(
        default_factory=list, 
        description="List of Base64 encoded additional factors for re-deriving K1."
    )
    qne_layer_key_b64: str = Field(..., description="Base64 encoded AES-GCM key for the outer QNE layer.")

# Generic Decryption Response (Plaintext)
class PlaintextResponse(BaseResponse):
    """Response model containing the decrypted plaintext."""
    plaintext_b64: str = Field(
        ..., 
        description="Base64 encoded byte string of the original decrypted plaintext."
    )

# --- Key Management Models ---
class DeleteKeyResponse(BaseResponse):
    """Response model for successful key deletion."""
    status: str = Field(..., example="deleted", description="Status of the deletion operation.")
    key_id_hex: str = Field(
        ..., 
        description="Hex representation of the key_id that was processed (e.g., deleted)."
    )

class GeneralErrorResponse(BaseModel): # For documenting error responses in OpenAPI
    """A generic error response model."""
    detail: str = Field(..., description="A human-readable description of the error.")