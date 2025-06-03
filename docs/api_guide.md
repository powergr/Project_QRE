# docs/api_guide.md

# API Guide: Quantum-Resistant Encryption System v0.1 (PoC)

## 1. Introduction

This document provides a guide to using the API for the Quantum-Resistant Encryption System.
The API allows for encryption and decryption using various hybrid and advanced schemes,
with keys and sensitive components managed via HashiCorp Vault.

**Base URL:** `http://127.0.0.1:8000/api/v1` (for local development)

**Authentication:**
All endpoints require an API key to be passed in the `X-API-Key` request header.
For the PoC, the default key is `poc_super_secret_api_key_123!`. This can be overridden by setting the `SERVER_API_KEY` environment variable when starting the API server.

**Data Format:**
All request and response bodies are in JSON. Binary data (plaintext, ciphertext, passwords, factors, QNE keys) must be Base64 encoded strings.

## 2. Common Error Responses

*   **400 Bad Request:** Invalid input format, missing required fields, or invalid Base64 encoding.

    { "detail": "Descriptive error message." }
    ```
*   **401 Unauthorized:** Missing or invalid `X-API-Key` header.
  
    { "detail": "Invalid API Key." } 
    ``` 
    or 
   
    { "detail": "Not authenticated: X-API-Key header missing." }
    ```
*   **404 Not Found:** Typically for `DELETE /vault/keys/{key_id_hex}` if the `key_id_hex` does not exist.

    { "detail": "Key ID '<key_id_hex>' not found in Vault. Nothing to delete." }
    ```
*   **422 Unprocessable Content:** The request was well-formed, but contained semantic errors (e.g., cryptographic processing failure due to bad data, decapsulation failure).

    { "detail": "<Operation> processing error: <specific_error_from_crypto_logic>" }
    ```
*   **500 Internal Server Error:** An unexpected error occurred on the server.

    { "detail": "Internal server error during <Operation>: <specific_error>" }
    ```
*   **503 Service Unavailable:** A required backend service (like the QNE Pool) is not available.

    { "detail": "QNE Pool not available for API." }
    ```

## 3. API Endpoints

---
### 3.1 Layered Encryption (Epic 1)

#### `POST /encrypt/layered`
Encrypts plaintext using the layered scheme (AES-CBC with KEM-encapsulated key). The KEM private key is stored in Vault.

**Request Body:**

{
    "plaintext_b64": "string (Base64 encoded plaintext)"
}

Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/encrypt/layered" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{"plaintext_b64": "SGVsbG8gV29ybGQh"}' # "Hello World!"


Success Response (200 OK):
{
    "ciphertext_b64": "string (Base64 encoded ciphertext, includes Vault key_id)"
}


POST /decrypt/layered
Decrypts ciphertext from the layered scheme. Retrieves KEM private key from Vault using key_id embedded in the ciphertext.
Request Body:
{
    "ciphertext_b64": "string (Base64 encoded ciphertext from /encrypt/layered)"
}


Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/decrypt/layered" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{"ciphertext_b64": "<output_from_encrypt_layered>"}'


Success Response (200 OK):
{
    "plaintext_b64": "string (Base64 encoded original plaintext)"
}


3.2 Parallel Encryption - Random K1 (Epic 1)
POST /encrypt/parallel/random
Encrypts using parallel scheme with a randomly generated K1. K1 and KEM SK stored in Vault.
Request Body:
{
    "plaintext_b64": "string (Base64)"
}


Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/encrypt/parallel/random" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{"plaintext_b64": "SGVsbG8gV29ybGQh"}'


Success Response (200 OK):
{
    "ciphertext_b64": "string (Base64)"
}


POST /decrypt/parallel/random
Decrypts parallel scheme (random K1 path). Retrieves K1 from Vault. (PoC decrypts C1 path).
Request Body:
{
    "ciphertext_b64": "string (Base64)"
}


Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/decrypt/parallel/random" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{"ciphertext_b64": "<output_from_encrypt_parallel_random>"}'

Success Response (200 OK):
{
    "plaintext_b64": "string (Base64)"
}


3.3 Parallel Encryption - KDF K1 (Epic 1 + Epic 3 Anchoring)
POST /encrypt/parallel/kdf
Encrypts using parallel scheme. K1 is derived via anchored KDF from password/factors. KDF salts and KEM SK stored in Vault.
Request Body:
{
    "plaintext_b64": "string (Base64)",
    "password_b64": "string (Base64 encoded password)",
    "additional_kdf_inputs_b64": ["string (Base64 factor1)", "string (Base64 factor2)"] 
}

Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/encrypt/parallel/kdf" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{
    "plaintext_b64": "SGVsbG8gV29ybGQh",
    "password_b64": "U2VjcmV0UEBzc3dvcmQ=", 
    "additional_kdf_inputs_b64": ["ZmFjdG9yMQ==", "ZmFjdG9yMg=="]
}'

Success Response (200 OK):
{
    "ciphertext_b64": "string (Base64)"
}

POST /decrypt/parallel/kdf
Decrypts parallel scheme (KDF K1 path). Re-derives K1 using provided password/factors and KDF salts from Vault. (PoC decrypts C1 path).
Request Body:
{
    "ciphertext_b64": "string (Base64)",
    "password_b64": "string (Base64 encoded password)",
    "additional_kdf_inputs_b64": ["string (Base64 factor1)", "string (Base64 factor2)"]
}

Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/decrypt/parallel/kdf" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{
    "ciphertext_b64": "<output_from_encrypt_parallel_kdf>",
    "password_b64": "U2VjcmV0UEBzc3dvcmQ=",
    "additional_kdf_inputs_b64": ["ZmFjdG9yMQ==", "ZmFjdG9yMg=="]
}'

Success Response (200 OK):
{
    "plaintext_b64": "string (Base64)"
}

3.4 Layered Encryption with QNE Infusion (Epic 1 + Epic 2)
POST /encrypt/layered_qne
Layered encryption (Epic 1) whose output is then wrapped by QNE infusion (Epic 2).
Request Body:
{
    "plaintext_b64": "string (Base64)"
}

Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/encrypt/layered_qne" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{"plaintext_b64": "SGVsbG8gV29ybGQh"}'

Success Response (200 OK):
{
    "final_ciphertext_b64": "string (Base64 encoded final, QNE-wrapped ciphertext)",
    "qne_layer_key_b64": "string (Base64 encoded AES-GCM key for QNE layer - PoC only)"
}

POST /decrypt/layered_qne
Decrypts QNE-infused layered ciphertext. Requires the QNE layer key.
Request Body:
{
    "final_ciphertext_b64": "string (Base64)",
    "qne_layer_key_b64": "string (Base64, from corresponding encrypt call)"
}

Example curl:
curl -X POST "http://127.0.0.1:8000/api/v1/decrypt/layered_qne" \
-H "X-API-Key: poc_super_secret_api_key_123!" \
-H "Content-Type: application/json" \
-d '{
    "final_ciphertext_b64": "<output_final_ciphertext_from_encrypt_layered_qne>",
    "qne_layer_key_b64": "<output_qne_layer_key_from_encrypt_layered_qne>"
}'

Success Response (200 OK):
{
    "plaintext_b64": "string (Base64)"
}

3.5 Parallel KDF Encryption with QNE Infusion (Epic 1 + Epic 3 + Epic 2)
POST /encrypt/parallel_kdf_qne
Parallel KDF encryption (Epic 1 + Epic 3) whose output is then wrapped by QNE infusion (Epic 2).
Request Body:
{
    "plaintext_b64": "string (Base64)",
    "password_b64": "string (Base64 encoded password)",
    "additional_kdf_inputs_b64": ["string (Base64 factor1)", "..."] 
}

Example curl: (Similar to /encrypt/parallel/kdf, just different endpoint)
Success Response (200 OK):
{
    "final_ciphertext_b64": "string (Base64)",
    "qne_layer_key_b64": "string (Base64 - PoC only)"
}

POST /decrypt/parallel_kdf_qne
Decrypts QNE-infused parallel KDF ciphertext. Requires password, factors, and QNE layer key.
Request Body:
{
    "final_ciphertext_b64": "string (Base64)",
    "password_b64": "string (Base64)",
    "additional_kdf_inputs_b64": ["string (Base64)", "..."],
    "qne_layer_key_b64": "string (Base64)"
}

Example curl: (Similar to /decrypt/parallel/kdf, but with final_ciphertext_b64 and qne_layer_key_b64)
Success Response (200 OK):
{
    "plaintext_b64": "string (Base64)"
}

3.6 Key Management (Vault)
DELETE /vault/keys/{key_id_hex}
Deletes a key set (KEM SK, AES K1, or KDF salts associated with an encryption operation) from Vault.
Path Parameter:
key_id_hex (string, required): The 32-character hexadecimal representation of the 16-byte key UUID.
Example curl:
curl -X DELETE "http://127.0.0.1:8000/api/v1/vault/keys/your_32_char_hex_key_id" \
-H "X-API-Key: poc_super_secret_api_key_123!"

Success Response (200 OK):
{
    "status": "deleted",
    "key_id_hex": "<key_id_hex_that_was_deleted>"
}

Error Response (404 Not Found):
{
    "detail": "Key ID '<key_id_hex>' not found in Vault. Nothing to delete."
}