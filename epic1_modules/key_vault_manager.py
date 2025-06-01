# key_vault_manager.py
"""
Manages storage and retrieval of cryptographic keys using HashiCorp Vault.
"""
import hvac
import os
import base64
import uuid # Though uuid generation will be in the encryption functions
from typing import Dict, Union

# Environment variable names
VAULT_ADDR_ENV = 'VAULT_ADDR'
VAULT_TOKEN_ENV = 'VAULT_TOKEN'

# Vault KV v2 mount point and path prefix for keys
VAULT_KV_MOUNT_POINT = 'secret' # Default for dev mode
KEY_PATH_PREFIX = 'keys'

def _get_vault_client() -> hvac.Client:
    """Initializes and returns an HVAC Vault client instance."""
    vault_addr = os.environ.get(VAULT_ADDR_ENV)
    vault_token = os.environ.get(VAULT_TOKEN_ENV)

    if not vault_addr or not vault_token:
        raise EnvironmentError(
            f"Vault address ('{VAULT_ADDR_ENV}') and token ('{VAULT_TOKEN_ENV}') "
            "must be set as environment variables."
        )
    
    client = hvac.Client(url=vault_addr, token=vault_token)
    if not client.is_authenticated():
        raise ConnectionError("Failed to authenticate with Vault. Check token and address.")
    return client

def store_keys(key_id: bytes, keys_to_store: Dict[str, bytes]) -> None:
    """
    Stores cryptographic keys in Vault, base64 encoding them.

    Args:
        key_id: A 16-byte UUID (bytes form) used as the primary identifier.
        keys_to_store: A dictionary where keys are string names (e.g., 'K1', 'Kyber_SK')
                       and values are the raw key bytes.
    
    Raises:
        RuntimeError: If storing keys in Vault fails.
    """
    if not isinstance(key_id, bytes) or len(key_id) != 16:
        raise ValueError("key_id must be 16 bytes.")
    if not isinstance(keys_to_store, dict) or \
       not all(isinstance(k, str) and isinstance(v, bytes) for k, v in keys_to_store.items()):
        raise ValueError("keys_to_store must be a Dict[str, bytes].")

    client = _get_vault_client()
    
    # Base64 encode all byte values before storing
    secret_payload = {key_name: base64.b64encode(key_bytes).decode('utf-8') 
                      for key_name, key_bytes in keys_to_store.items()}
    
    vault_path = f'{KEY_PATH_PREFIX}/{key_id.hex()}' # Use hex representation of key_id for Vault path

    try:
        client.secrets.kv.v2.create_or_update_secret(
            mount_point=VAULT_KV_MOUNT_POINT,
            path=vault_path,
            secret=secret_payload  # Note: hvac expects 'secret' kwarg for the payload
        )
        # print(f"Keys stored successfully in Vault at path: {VAULT_KV_MOUNT_POINT}/{vault_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to store keys in Vault at {vault_path}: {e}")

def get_keys(key_id: bytes) -> Dict[str, bytes]:
    """
    Retrieves and base64-decodes cryptographic keys from Vault.

    Args:
        key_id: The 16-byte UUID (bytes form) used to identify the keys.

    Returns:
        A dictionary where keys are string names and values are the raw key bytes.

    Raises:
        ValueError: If no keys are found for the key_id or if key_id is invalid.
        RuntimeError: If retrieving keys from Vault fails.
    """
    if not isinstance(key_id, bytes) or len(key_id) != 16:
        raise ValueError("key_id must be 16 bytes.")

    client = _get_vault_client()
    vault_path = f'{KEY_PATH_PREFIX}/{key_id.hex()}'

    try:
        response = client.secrets.kv.v2.read_secret_version(
            mount_point=VAULT_KV_MOUNT_POINT,
            path=vault_path,
            raise_on_deleted_version=True
        )
        if response is None or 'data' not in response or 'data' not in response['data']:
             raise ValueError(f"No keys found in Vault for key_id: {key_id.hex()} at path {vault_path} (empty response or no data field).")

        # Base64 decode all byte values after retrieving
        retrieved_keys_b64 = response['data']['data']
        decoded_keys = {key_name: base64.b64decode(key_data_b64)
                        for key_name, key_data_b64 in retrieved_keys_b64.items()}
        return decoded_keys
        
    except hvac.exceptions.InvalidPath:
        raise ValueError(f"No keys found in Vault for key_id: {key_id.hex()} (path not found at {vault_path}).")
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve keys from Vault from {vault_path}: {e}")

if __name__ == '__main__':
    # Basic test for key_vault_manager (requires Vault dev server running and env vars set)
    print("Running basic Vault interaction test...")
    try:
        test_key_id = uuid.uuid4().bytes
        sample_aes_key = os.urandom(32)
        sample_kyber_sk = os.urandom(1632) # ML-KEM-512 SK size

        keys_to_store_map = {
            "AES_K1": sample_aes_key,
            "Kyber_SK": sample_kyber_sk
        }
        print(f"Attempting to store keys with key_id: {test_key_id.hex()}")
        store_keys(test_key_id, keys_to_store_map)
        print("Keys stored.")

        print(f"Attempting to retrieve keys with key_id: {test_key_id.hex()}")
        retrieved_map = get_keys(test_key_id)
        print("Keys retrieved.")

        assert retrieved_map["AES_K1"] == sample_aes_key, "AES key mismatch!"
        assert retrieved_map["Kyber_SK"] == sample_kyber_sk, "Kyber SK mismatch!"
        
        print("Vault store and get test PASSED!")

        # Test getting non-existent key
        print("\nAttempting to retrieve non-existent key_id...")
        non_existent_key_id = uuid.uuid4().bytes
        try:
            get_keys(non_existent_key_id)
            print("ERROR: Should have raised ValueError for non-existent key_id.")
        except ValueError as ve:
            print(f"Correctly caught expected error for non-existent key: {ve}")
            assert f"No keys found in Vault for key_id: {non_existent_key_id.hex()}" in str(ve)
            print("Non-existent key test PASSED!")

    except EnvironmentError as ee:
        print(f"ENVIRONMENT ERROR: {ee}")
        print("Please ensure VAULT_ADDR and VAULT_TOKEN environment variables are set.")
    except ConnectionError as ce:
        print(f"VAULT CONNECTION ERROR: {ce}")
        print("Please ensure Vault dev server is running and accessible.")
    except Exception as e:
        print(f"An unexpected error occurred in Vault interaction test: {e}")
        import traceback
        traceback.print_exc()