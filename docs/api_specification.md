# Quantum-Resistant Encryption System - API Specification v0.1 (PoC)

## 1. Overview
This API provides endpoints for performing hybrid quantum-resistant encryption and decryption,
and basic key management operations interacting with a HashiCorp Vault backend.

**Base URL:** `http://localhost:8000/api/v1` (Example for local development)
**Authentication:** All endpoints require an API key passed in the `X-API-Key` header.
**Data Format:** All request and response bodies are in JSON format. Binary data fields (plaintext, ciphertext, keys, passwords, factors) are Base64 encoded.

## 2. Common Error Responses
*   **400 Bad Request:** `{ "detail": "Error message related to invalid input or format." }`
*   **401 Unauthorized:** `{ "detail": "Invalid or missing API Key" }`
*   **404 Not Found:** `{ "detail": "Resource not found (e.g., key_id)." }`
*   **500 Internal Server Error:** `{ "detail": "A server-side error occurred during the operation." }`
*   **503 Service Unavailable:** `{ "detail": "A dependent service (e.g., QNE Pool) is not available." }`

## 3. Endpoints

### 3.1 Layered Encryption

#### 3.1.1 Encrypt Layered
*   **Endpoint:** `POST /encrypt/layered`
*   **Description:** Encrypts plaintext using the layered scheme (AES-CBC with KEM-encapsulated key; KEM private key stored in Vault).
*   **Request Header:**
    *   `X-API-Key: <your_api_key>`
*   **Request Body:**
    ```json
    {
        "plaintext_b64": "string (base64 encoded bytes)"
    }
    ```
*   **Response Body (200 OK):**
    ```json
    {
        "ciphertext_b64": "string (base64 encoded bytes)" 
    }
    ```

#### 3.1.2 Decrypt Layered
*   **Endpoint:** `POST /decrypt/layered`
    *   ... (continue for all defined endpoints: Description, Request Header, Request Body, Success Response, Error Responses) ...

### 3.2 Parallel Encryption (Random K1)
    ...

### 3.3 Parallel Encryption (KDF K1)
    ...

### 3.4 Layered Encryption with QNE Infusion
    ...

### 3.5 Parallel Encryption (KDF K1) with QNE Infusion
    ...

### 3.6 Key Management (Vault)

#### 3.6.1 Delete Key Set
*   **Endpoint:** `DELETE /vault/keys/{key_id_hex}`
*   **Description:** Deletes all key material associated with the given `key_id` from Vault.
*   **Path Parameter:**
    *   `key_id_hex` (string): The hexadecimal representation of the 16-byte key UUID.
*   **Request Header:**
    *   `X-API-Key: <your_api_key>`
*   **Response Body (200 OK):**
    ```json
    {
        "status": "deleted",
        "key_id_hex": "<key_id_hex>"
    }
    ```
*   **Response (204 No Content):** Also acceptable for successful deletion.

## 4. Data Models / Schemas (for OpenAPI later)

### PlaintextRequest
*   `plaintext_b64`: string (base64) - The data to be encrypted.

### CiphertextResponse
*   `ciphertext_b64`: string (base64) - The resulting encrypted data.

### KdfEncryptRequest
*   `plaintext_b64`: string (base64)
*   `password_b64`: string (base64)
*   `additional_kdf_inputs_b64`: array of strings (base64)

### CiphertextForDecryptRequest
*   `ciphertext_b64`: string (base64) - The data to be decrypted.

### KdfDecryptRequest
*   `ciphertext_b64`: string (base64)
*   `password_b64`: string (base64)
*   `additional_kdf_inputs_b64`: array of strings (base64)

### PlaintextResponse
*   `plaintext_b64`: string (base64) - The decrypted data.

### LayeredQNEEncryptResponse
*   `final_ciphertext_b64`: string (base64)
*   `qne_layer_key_b64`: string (base64) - *PoC only: key for outer QNE layer.*

### LayeredQNEDecryptRequest
*   `final_ciphertext_b64`: string (base64)
*   `qne_layer_key_b64`: string (base64) - *PoC only: key for outer QNE layer.*

### ParallelKdfQNEEncryptResponse
*   `final_ciphertext_b64`: string (base64)
*   `qne_layer_key_b64`: string (base64) - *PoC only: key for outer QNE layer.*

### ParallelKdfQNEDecryptRequest
*   `final_ciphertext_b64`: string (base64)
*   `password_b64`: string (base64)
*   `additional_kdf_inputs_b64`: array of strings (base64)
*   `qne_layer_key_b64`: string (base64) - *PoC only: key for outer QNE layer.*

### DeleteKeyResponse
*   `status`: string (e.g., "deleted")
*   `key_id_hex`: string