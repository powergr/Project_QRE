# tests/api_tests/test_key_management_endpoints.py
import pytest
import httpx # For type hinting client if needed, though pytest injects fixtures
import uuid
import base64
import os

# Fixtures like api_client are automatically available from tests/api_tests/conftest.py
# We'll also need some way to ensure a key exists in Vault to test deletion.
# We can use one of the encryption endpoints for this setup.

# Assuming these are correctly imported by your API server's routers for actual operation
# For testing, we might need to make calls that set up keys via other API endpoints first.
# Adjust import if your encryption functions are in a different utility module for tests
try:
    from main_unified_poc import layered_encrypt_vault # Or from system_core_logic
    SETUP_CRYPTO_FUNCTIONS_LOADED = True
except ImportError:
    # This is only needed if tests *directly* call these to set up state for deletion.
    # It's better if tests use API calls for setup if possible.
    # For now, we'll assume we can use an encryption endpoint to create a key_id.
    print("Warning [test_key_management_endpoints]: Could not import layered_encrypt_vault "
          "for direct test setup. Tests will rely on API for setup.")
    SETUP_CRYPTO_FUNCTIONS_LOADED = False # Or make it a hard fail if needed for setup

# We also need to interact with key_vault_manager directly for verification after API delete
try:
    from epic1_modules.key_vault_manager import get_keys, VAULT_ADDR_ENV, VAULT_TOKEN_ENV
    VAULT_MANAGER_LOADED = True
except ImportError:
    VAULT_MANAGER_LOADED = False
    def get_keys(*args, **kwargs): raise NotImplementedError("key_vault_manager.get_keys not loaded")

def is_vault_configured_for_api_tests(): # Helper for skipping if Vault not set for API run
    return os.environ.get(VAULT_ADDR_ENV) and os.environ.get(VAULT_TOKEN_ENV)


@pytest.mark.skipif(not is_vault_configured_for_api_tests(), 
                    reason="VAULT_ADDR and VAULT_TOKEN env vars must be set for these API tests.")
@pytest.mark.skipif(not VAULT_MANAGER_LOADED, 
                    reason="epic1_modules.key_vault_manager.get_keys not available for verification.")
class TestKeyManagementEndpoints: # Pytest will collect classes starting with Test

    def _create_key_in_vault_via_api(self, api_client: httpx.Client) -> tuple[str, bytes]:
        """
        Helper to create a key set in Vault using an encrypt endpoint and return its hex key_id and bytes key_id.
        Returns (key_id_hex, key_id_bytes)
        """
        plaintext_b64 = base64.b64encode(b"dummy data for key creation").decode('utf-8')
        encrypt_payload = {"plaintext_b64": plaintext_b64}
        
        # Use a reliable encryption endpoint that generates a key_id and stores keys
        # /encrypt/layered is a good candidate as it stores one KEM SK.
        response = api_client.post("/encrypt/layered", json=encrypt_payload)
        assert response.status_code == 200, f"Setup failed: Could not create key via /encrypt/layered: {response.text}"
        
        ciphertext_b64 = response.json()["ciphertext_b64"]
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        key_id_bytes = ciphertext_bytes[:16] # First 16 bytes are key_id
        key_id_hex = key_id_bytes.hex()
        
        # Verify it exists initially
        keys_in_vault = get_keys(key_id_bytes) # Direct check
        assert "Kyber_SK" in keys_in_vault, "Setup failed: Kyber_SK not found in Vault after creation."
        return key_id_hex, key_id_bytes

    def test_delete_existing_key_successfully(self, api_client: httpx.Client):
        """Test successfully deleting an existing key set from Vault."""
        key_id_hex, key_id_bytes = self._create_key_in_vault_via_api(api_client)
        
        delete_response = api_client.delete(f"/vault/keys/{key_id_hex}")
        assert delete_response.status_code == 200, \
            f"DELETE /vault/keys/{key_id_hex} failed: {delete_response.text}"
        
        response_data = delete_response.json()
        assert response_data["status"] == "deleted"
        assert response_data["key_id_hex"] == key_id_hex

        # Verify the key set is actually gone from Vault by trying to get it
        with pytest.raises(ValueError) as exc_info: # get_keys raises ValueError if path not found
            get_keys(key_id_bytes)
        assert f"No keys found in Vault for key_id: {key_id_hex}" in str(exc_info.value)

    def test_delete_non_existent_key(self, api_client: httpx.Client):
        """Test attempting to delete a key_id that does not exist in Vault."""
        non_existent_key_id_hex = uuid.uuid4().hex # Generate a random UUID hex
        
        response = api_client.delete(f"/vault/keys/{non_existent_key_id_hex}")
        assert response.status_code == 404, \
            f"Expected 404 for non-existent key, got {response.status_code}: {response.text}"
        assert "Key ID not found" in response.json()["detail"]

    def test_delete_key_invalid_key_id_format(self, api_client: httpx.Client):
        """Test attempting to delete with an invalid key_id_hex format."""
        invalid_key_id_hex = "this-is-not-a-valid-hex-uuid"
        response = api_client.delete(f"/vault/keys/{invalid_key_id_hex}")
        assert response.status_code == 400, \
            f"Expected 400 for invalid key_id format, got {response.status_code}: {response.text}"
        assert "Invalid key_id_hex format" in response.json()["detail"]

        short_key_id_hex = "12345" # Too short
        response_short = api_client.delete(f"/vault/keys/{short_key_id_hex}")
        assert response_short.status_code == 400
        assert "Invalid key_id_hex format" in response_short.json()["detail"]


    def test_delete_key_missing_api_key(self, api_client: httpx.Client):
        """Test DELETE /keys/{key_id_hex} without API key."""
        key_id_hex_dummy = uuid.uuid4().hex
        # Use a new client without the default auth header
        with httpx.Client(base_url=str(api_client.base_url), timeout=10.0) as no_auth_client:
            response = no_auth_client.delete(f"/vault/keys/{key_id_hex_dummy}")
        
        assert response.status_code == 401
        assert "X-API-Key header missing" in response.json()["detail"]

    def test_delete_key_invalid_api_key(self, api_client: httpx.Client):
        """Test DELETE /keys/{key_id_hex} with an invalid API key."""
        key_id_hex_dummy = uuid.uuid4().hex
        response = api_client.delete(
            f"/vault/keys/{key_id_hex_dummy}", 
            headers={"X-API-Key": "this_is_the_wrong_key_for_sure"}
        )
        assert response.status_code == 401
        assert "Invalid API Key." in response.json()["detail"]