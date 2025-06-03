# api_server/routers/key_management.py
from fastapi import APIRouter, Depends, HTTPException, status
import uuid
import hvac # Import hvac for its exceptions, and for _get_vault_client if used directly

from ..core.security import verify_api_key # Use the verification dependency
from ..models import DeleteKeyResponse, GeneralErrorResponse

# Import a function to interact with Vault for deletion.
# Ideally, this comes from key_vault_manager.py
# Let's assume key_vault_manager.py has a delete_key_set function.
# If not, we use _get_vault_client and do it here.
try:
    from epic1_modules.key_vault_manager import _get_vault_client, VAULT_KV_MOUNT_POINT, KEY_PATH_PREFIX 
    # If you add a delete_key_set(key_id_bytes) to key_vault_manager.py, import that instead.
    VAULT_ACCESS_POSSIBLE = True
except ImportError:
    print("Warning: Could not import Vault access functions in key_management_router.")
    VAULT_ACCESS_POSSIBLE = False


router = APIRouter(
    prefix="/vault/keys", # Path as per spec: /api/v1/vault/keys/...
    tags=["Key Management (Vault)"],
    dependencies=[Depends(verify_api_key)]
)

@router.delete(
    "/{key_id_hex}", 
    response_model=DeleteKeyResponse,
    summary="Delete a key set from Vault by its Key ID.",
    responses={
        200: {"description": "Key successfully deleted (or was already non-existent)"}, # Update description
        400: {"model": GeneralErrorResponse, "description": "Invalid key_id format"},
        404: {"model": GeneralErrorResponse, "description": "Key ID not found prior to delete attempt"},
        500: {"model": GeneralErrorResponse, "description": "Vault error or other internal error"}
    }
)
async def api_delete_key_set(key_id_hex: str):
    if not VAULT_ACCESS_POSSIBLE:
        raise HTTPException(status_code=503, detail="Vault key manager not loaded.")
    
    # Validate key_id_hex format first
    if not (len(key_id_hex) == 32 and all(c in '0123456789abcdefABCDEF' for c in key_id_hex)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid key_id_hex format. Must be 32 hex characters.")

    client = _get_vault_client()
    vault_path = f'{KEY_PATH_PREFIX}/{key_id_hex}'

    try:
        # STEP 1: Attempt to read the secret's metadata to see if it exists.
        # Reading a secret that doesn't exist will raise InvalidPath.
        # We don't need the actual data, just to check existence.
        # client.secrets.kv.v2.read_secret_metadata(path=vault_path, mount_point=VAULT_KV_MOUNT_POINT)
        # A more direct way for KVv2 is to try reading the secret itself. If it's not there, InvalidPath.
        client.secrets.kv.v2.read_secret_version(
            path=vault_path, 
            mount_point=VAULT_KV_MOUNT_POINT,
            raise_on_deleted_version=False # Don't error if it's just a deleted version, we care about path existence
        )
        # If the above didn't raise InvalidPath, the path exists (or existed). Now delete.
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            mount_point=VAULT_KV_MOUNT_POINT,
            path=vault_path
        )
        return DeleteKeyResponse(status="deleted", key_id_hex=key_id_hex)

    except hvac.exceptions.InvalidPath:
        # This means the path didn't exist when we tried to read/check it.
        # So, the key we were asked to delete was not found.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Key ID '{key_id_hex}' not found in Vault. Nothing to delete.")
    except hvac.exceptions.VaultError as ve:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Vault operation error: {ve}")
    except Exception as e:
        print(f"Unexpected error during key deletion for {key_id_hex}: {e}") # Log for server
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred while deleting key: {e}")