# tests/api_tests/test_encryption_endpoints.py
import httpx 
import base64
import pytest 
import os 

try:
    from main_unified_poc import (
        encrypt_layered_with_qne, decrypt_layered_with_qne,
        encrypt_parallel_kdf_with_qne, decrypt_parallel_kdf_with_qne
    )
    QNE_WRAPPERS_LOADED = True
except ImportError:
    QNE_WRAPPERS_LOADED = False
    def encrypt_layered_with_qne(*args, **kwargs): raise NotImplementedError("QNE Wrapper not loaded")
    def decrypt_layered_with_qne(*args, **kwargs): raise NotImplementedError("QNE Wrapper not loaded")
    def encrypt_parallel_kdf_with_qne(*args, **kwargs): raise NotImplementedError("QNE Wrapper not loaded")
    def decrypt_parallel_kdf_with_qne(*args, **kwargs): raise NotImplementedError("QNE Wrapper not loaded")


def test_api_root_is_accessible(api_client: httpx.Client):
    root_url_obj = api_client.base_url.copy_with(path="/")
    with httpx.Client(base_url=str(root_url_obj.copy_with(path=""))) as client:
        response = client.get("/")
    assert response.status_code == 200, f"Root / endpoint failed: {response.text}"
    assert response.json()["message"] == "Welcome to the Quantum-Resistant Encryption API PoC!"

def test_encrypt_decrypt_layered_api(api_client: httpx.Client, sample_plaintext_b64: str, sample_plaintext_bytes: bytes):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64}
    encrypt_response = api_client.post("/encrypt/layered", json=encrypt_payload)
    assert encrypt_response.status_code == 200, f"Encrypt failed: {encrypt_response.text}" # Corrected typo here
    encrypt_data = encrypt_response.json()
    assert "ciphertext_b64" in encrypt_data
    ciphertext_b64 = encrypt_data["ciphertext_b64"]
    assert isinstance(ciphertext_b64, str) and len(ciphertext_b64) > 0

    decrypt_payload = {"ciphertext_b64": ciphertext_b64}
    decrypt_response = api_client.post("/decrypt/layered", json=decrypt_payload)
    assert decrypt_response.status_code == 200, f"Decrypt failed: {decrypt_response.text}"
    decrypt_data = decrypt_response.json()
    assert "plaintext_b64" in decrypt_data
    decrypted_pt_b64 = decrypt_data["plaintext_b64"]
    assert base64.b64decode(decrypted_pt_b64) == sample_plaintext_bytes

def test_decrypt_layered_invalid_base64_ciphertext(api_client: httpx.Client):
    """Test /decrypt/layered with different types of invalid base64 ciphertext."""
    # Test 1: String that is fundamentally not Base64 (e.g. contains invalid characters)
    # FastAPI/Pydantic might catch this with a 422 if it has base64 format validation,
    # or your b64decode will raise binascii.Error leading to 400.
    # The previous traceback showed a 422 for a similar string for this test.
    # The string "ThisIsNotValidBase64AndAlsoNotValidCiphertext!@#" might be valid as a generic string
    # for Pydantic, and then base64.b64decode raises the error.
    # Let's test what your SUT returns for THIS string.
    # If api_server/routers/encryption.py's api_decrypt_layered has:
    #   except base64.binascii.Error:
    #       raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid base64 for ciphertext.")
    # Then this should result in 400. The traceback showed your handle_crypto_errors doing this:
    # `raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid base64 encoding in request for {operation_name}.")`

    invalid_b64_string = "ThisIsNotValidBase64AndAlsoNotValidCiphertext!@#" 
    decrypt_payload1 = {"ciphertext_b64": invalid_b64_string}
    response1 = api_client.post("/decrypt/layered", json=decrypt_payload1)
    assert response1.status_code == 400 # Expecting 400 from your explicit catch
    assert "Invalid base64 encoding in request for Layered Decryption." in response1.json()["detail"] # CORRECTED

    # Test 2: Valid Base64 string but cryptographically malformed (too short, wrong structure)
    valid_b64_but_bad_crypto = base64.b64encode(b"short").decode() # Valid b64, but too short for crypto
    decrypt_payload_2 = {"ciphertext_b64": valid_b64_but_bad_crypto}
    response_2 = api_client.post("/decrypt/layered", json=decrypt_payload_2)
    assert response_2.status_code in [400, 422] 
    response_detail = response_2.json()["detail"]
    assert "Malformed ciphertext" in response_detail or "Layered Decryption input error" in response_detail or "Layered Decryption processing error" in response_detail


def test_encrypt_decrypt_parallel_random_api(api_client: httpx.Client, sample_plaintext_b64: str, sample_plaintext_bytes: bytes):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64}
    encrypt_response = api_client.post("/encrypt/parallel/random", json=encrypt_payload)
    assert encrypt_response.status_code == 200, f"Encrypt failed: {encrypt_response.text}"
    ciphertext_b64 = encrypt_response.json()["ciphertext_b64"]
    decrypt_payload = {"ciphertext_b64": ciphertext_b64}
    decrypt_response = api_client.post("/decrypt/parallel/random", json=decrypt_payload)
    assert decrypt_response.status_code == 200, f"Decrypt failed: {decrypt_response.text}"
    assert base64.b64decode(decrypt_response.json()["plaintext_b64"]) == sample_plaintext_bytes

def test_encrypt_decrypt_parallel_kdf_api(
    api_client: httpx.Client, sample_plaintext_b64: str, sample_plaintext_bytes: bytes,
    kdf_password_b64: str, kdf_additional_inputs_b64: list[str]):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64, "password_b64": kdf_password_b64, "additional_kdf_inputs_b64": kdf_additional_inputs_b64}
    encrypt_response = api_client.post("/encrypt/parallel/kdf", json=encrypt_payload)
    assert encrypt_response.status_code == 200, f"Encrypt failed: {encrypt_response.text}"
    ciphertext_b64 = encrypt_response.json()["ciphertext_b64"]
    decrypt_payload = {"ciphertext_b64": ciphertext_b64, "password_b64": kdf_password_b64, "additional_kdf_inputs_b64": kdf_additional_inputs_b64}
    decrypt_response = api_client.post("/decrypt/parallel/kdf", json=decrypt_payload)
    assert decrypt_response.status_code == 200, f"Decrypt failed: {decrypt_response.text}"
    assert base64.b64decode(decrypt_response.json()["plaintext_b64"]) == sample_plaintext_bytes

def test_decrypt_parallel_kdf_wrong_password(
    api_client: httpx.Client, sample_plaintext_b64: str, kdf_password_b64: str, kdf_additional_inputs_b64: list[str]):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64, "password_b64": kdf_password_b64, "additional_kdf_inputs_b64": kdf_additional_inputs_b64}
    encrypt_response = api_client.post("/encrypt/parallel/kdf", json=encrypt_payload)
    assert encrypt_response.status_code == 200
    ciphertext_b64 = encrypt_response.json()["ciphertext_b64"]
    wrong_password_b64 = base64.b64encode(b"ThisIsTheWrongPassword").decode('utf-8')
    decrypt_payload = {"ciphertext_b64": ciphertext_b64, "password_b64": wrong_password_b64, "additional_kdf_inputs_b64": kdf_additional_inputs_b64}
    decrypt_response = api_client.post("/decrypt/parallel/kdf", json=decrypt_payload)
    assert decrypt_response.status_code in [422, 500]
    assert "Unpadding C1 failed (corrupted data or incorrect key K1?): Invalid padding bytes." in decrypt_response.json()["detail"]

@pytest.mark.skipif(not QNE_WRAPPERS_LOADED, reason="Skipping QNE API tests as unified wrapper functions were not loaded/imported.")
def test_encrypt_decrypt_layered_qne_api(api_client: httpx.Client, sample_plaintext_b64: str, sample_plaintext_bytes: bytes):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64}
    encrypt_response = api_client.post("/encrypt/layered_qne", json=encrypt_payload)
    assert encrypt_response.status_code == 200, f"Encrypt layered_qne failed: {encrypt_response.text}"
    encrypt_data = encrypt_response.json()
    final_ciphertext_b64 = encrypt_data["final_ciphertext_b64"]
    qne_layer_key_b64 = encrypt_data["qne_layer_key_b64"]
    decrypt_payload = {"final_ciphertext_b64": final_ciphertext_b64, "qne_layer_key_b64": qne_layer_key_b64}
    decrypt_response = api_client.post("/decrypt/layered_qne", json=decrypt_payload)
    assert decrypt_response.status_code == 200, f"Decrypt layered_qne failed: {decrypt_response.text}"
    assert base64.b64decode(decrypt_response.json()["plaintext_b64"]) == sample_plaintext_bytes

@pytest.mark.skipif(not QNE_WRAPPERS_LOADED, reason="Skipping QNE API tests as unified wrapper functions were not loaded/imported.")
def test_encrypt_decrypt_parallel_kdf_qne_api(
    api_client: httpx.Client, sample_plaintext_b64: str, sample_plaintext_bytes: bytes,
    kdf_password_b64: str, kdf_additional_inputs_b64: list[str]):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64, "password_b64": kdf_password_b64, "additional_kdf_inputs_b64": kdf_additional_inputs_b64}
    encrypt_response = api_client.post("/encrypt/parallel_kdf_qne", json=encrypt_payload)
    assert encrypt_response.status_code == 200, f"Encrypt parallel_kdf_qne failed: {encrypt_response.text}"
    encrypt_data = encrypt_response.json()
    final_ciphertext_b64_from_encrypt = encrypt_data["final_ciphertext_b64"]
    qne_layer_key_b64_from_encrypt = encrypt_data["qne_layer_key_b64"]
    decrypt_payload = {
        "final_ciphertext_b64": final_ciphertext_b64_from_encrypt, 
        "password_b64": kdf_password_b64,
        "additional_kdf_inputs_b64": kdf_additional_inputs_b64,
        "qne_layer_key_b64": qne_layer_key_b64_from_encrypt
    }
    decrypt_response = api_client.post("/decrypt/parallel_kdf_qne", json=decrypt_payload)
    assert decrypt_response.status_code == 200, f"Decrypt parallel_kdf_qne failed: {decrypt_response.text}"
    assert base64.b64decode(decrypt_response.json()["plaintext_b64"]) == sample_plaintext_bytes

def test_missing_api_key(api_client: httpx.Client, sample_plaintext_b64: str):
    with httpx.Client(base_url=str(api_client.base_url), timeout=10.0) as no_auth_client:
        encrypt_payload = {"plaintext_b64": sample_plaintext_b64}
        response = no_auth_client.post("/encrypt/layered", json=encrypt_payload) 
        assert response.status_code == 401 
        assert "X-API-Key header missing" in response.json()["detail"]

def test_invalid_api_key(api_client: httpx.Client, sample_plaintext_b64: str):
    encrypt_payload = {"plaintext_b64": sample_plaintext_b64}
    response = api_client.post("/encrypt/layered", json=encrypt_payload, headers={"X-API-Key": "this_is_a_very_wrong_key"})
    assert response.status_code == 401 
    assert "Invalid API Key." in response.json()["detail"] # Corrected to match SUT