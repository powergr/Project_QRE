# docs/api_tutorial.md

# API Tutorial: Encrypting and Decrypting Data

This tutorial walks through using the Quantum-Resistant Encryption System API to encrypt and decrypt data using the "Layered Encryption with QNE Infusion" scheme as an example.

## Prerequisites

1.  The API server is running (see `README.md` for setup).
2.  You have a valid API Key (default PoC key: `poc_super_secret_api_key_123!`).
3.  You have `curl` installed or a tool like Postman, or you will use Python with the `requests` library.

## Scenario: Encrypting and Decrypting a Message

We will encrypt the message "My secret conference plan" using the Layered + QNE scheme.

### Step 1: Prepare Your Data

*   **Plaintext:** "My secret conference plan"
*   **Base64 Encode Plaintext:**
    You need to send the plaintext Base64 encoded.
    Using Python:
    ```python
    import base64
    plaintext = b"My secret conference plan"
    plaintext_b64 = base64.b64encode(plaintext).decode('utf-8')
    print(plaintext_b64) 
    # Output: TXkgc2VjcmV0IGNvbmZlcmVuY2UgcGxhbg==
    ```

### Step 2: Encrypt the Data via API

We will make a POST request to the `/api/v1/encrypt/layered_qne` endpoint.

**Using `curl`:**
```bash
API_KEY="poc_super_secret_api_key_123!"
PLAINTEXT_B64="TXkgc2VjcmV0IGNvbmZlcmVuY2UgcGxhbg=="

curl -X POST "http://127.0.0.1:8000/api/v1/encrypt/layered_qne" \
-H "X-API-Key: ${API_KEY}" \
-H "Content-Type: application/json" \
-d "{
\"plaintext_b64\": \"${PLAINTEXT_B64}\"
}"

Expected Encryption Response (Example):
{
    "final_ciphertext_b64": "eyJ...", // This will be a long Base64 string
    "qne_layer_key_b64": "abc..."    // Another Base64 string (PoC key)
}

Store both final_ciphertext_b64 and qne_layer_key_b64 securely. You will need them for decryption. The final_ciphertext_b64 internally contains the key_id that points to the KEM private key in Vault.
Step 3: Decrypt the Data via API
Now, use the final_ciphertext_b64 and qne_layer_key_b64 obtained from the encryption step to decrypt the message.
Using curl:
API_KEY="poc_super_secret_api_key_123!"
# Replace with the actual values you received from the encryption step
FINAL_CIPHERTEXT_B64="eyJ..." 
QNE_LAYER_KEY_B64="abc..."    

curl -X POST "http://127.0.0.1:8000/api/v1/decrypt/layered_qne" \
-H "X-API-Key: ${API_KEY}" \
-H "Content-Type: application/json" \
-d "{
\"final_ciphertext_b64\": \"${FINAL_CIPHERTEXT_B64}\",
\"qne_layer_key_b64\": \"${QNE_LAYER_KEY_B64}\"
}"


Expected Decryption Response (200 OK):
{
    "plaintext_b64": "TXkgc2VjcmV0IGNvbmZlcmVuY2UgcGxhbg=="
}

Step 4: Verify Decrypted Plaintext
Base64 decode the plaintext_b64 from the decryption response:
import base64
decrypted_b64 = "TXkgc2VjcmV0IGNvbmZlcmVuY2UgcGxhbg=="
original_message_bytes = base64.b64decode(decrypted_b64)
original_message = original_message_bytes.decode('utf-8')
print(original_message)
# Output: My secret conference plan

If the output matches your original message, the encryption and decryption cycle was successful!
Python Example for API Interaction
Here's a Python script using the requests library:
import requests
import base64
import json

API_BASE_URL = "http://127.0.0.1:8000/api/v1"
API_KEY = "poc_super_secret_api_key_123!" # Replace if you use a different one

HEADERS = {
    "X-API-Key": API_KEY,
    "Content-Type": "application/json",
    "accept": "application/json"
}

def encrypt_message_layered_qne(plaintext_str: str) -> tuple[str | None, str | None]:
    plaintext_b64 = base64.b64encode(plaintext_str.encode('utf-8')).decode('utf-8')
    payload = {"plaintext_b64": plaintext_b64}
    
    try:
        response = requests.post(f"{API_BASE_URL}/encrypt/layered_qne", headers=HEADERS, json=payload, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        data = response.json()
        return data.get("final_ciphertext_b64"), data.get("qne_layer_key_b64")
    except requests.exceptions.RequestException as e:
        print(f"Encryption API request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                print(f"Error details: {e.response.json()}")
            except json.JSONDecodeError:
                print(f"Error details (raw): {e.response.text}")
    return None, None

def decrypt_message_layered_qne(final_ciphertext_b64: str, qne_key_b64: str) -> str | None:
    payload = {
        "final_ciphertext_b64": final_ciphertext_b64,
        "qne_layer_key_b64": qne_key_b64
    }
    try:
        response = requests.post(f"{API_BASE_URL}/decrypt/layered_qne", headers=HEADERS, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        decrypted_b64 = data.get("plaintext_b64")
        if decrypted_b64:
            return base64.b64decode(decrypted_b64).decode('utf-8')
    except requests.exceptions.RequestException as e:
        print(f"Decryption API request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            try:
                print(f"Error details: {e.response.json()}")
            except json.JSONDecodeError:
                print(f"Error details (raw): {e.response.text}")
    return None

if __name__ == '__main__':
    message_to_encrypt = "My Python API Test Message!"
    print(f"Original message: {message_to_encrypt}")

    ct_b64, qne_k_b64 = encrypt_message_layered_qne(message_to_encrypt)

    if ct_b64 and qne_k_b64:
        print(f"Encrypted (Ciphertext B64): {ct_b64[:50]}...")
        print(f"Encrypted (QNE Key B64): {qne_k_b64}")

        print("\nAttempting decryption...")
        decrypted_message = decrypt_message_layered_qne(ct_b64, qne_k_b64)
        if decrypted_message:
            print(f"Decrypted message: {decrypted_message}")
            assert decrypted_message == message_to_encrypt
            print("SUCCESS: Tutorial cycle complete!")
        else:
            print("Decryption failed or returned no data.")
    else:
        print("Encryption failed, cannot proceed to decryption.")

This script demonstrates a full cycle for one of the more complex endpoints. You can create similar examples for other endpoints (like parallel KDF).