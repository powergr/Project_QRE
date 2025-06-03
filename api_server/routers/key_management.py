# api_server/routers/key_management.py
from fastapi import APIRouter, Depends, HTTPException, status
import uuid
import hvac 

from ..core.security import verify_api_key 
from ..models import DeleteKeyResponse, GeneralErrorResponse

VAULT_ACCESS_POSSIBLE = False
try:
    from epic1_modules.key_vault_manager import _get_vault_client, VAULT_KV_MOUNT_POINT, KEY_PATH_PREFIX 
    VAULT_ACCESS_POSSIBLE = True
except ImportError:
    print("Warning: Could not import Vault access functions in key_management_router.")


router = APIRouter(
    prefix="/vault/keys", 
    tags=["Key Management (Vault)"],
    dependencies=[Depends(verify_api_key)]
)

@router.delete(
    "/{key_id_hex}", 
    response_model=DeleteKeyResponse,
    summary="Delete Key Set from Vault",
    description="Permanently deletes all versions and metadata for a key set associated with the given `key_id` from Vault's KVv2 secrets engine. Use with caution.",
    responses={
        200: {"description": "Key set successfully deleted."},
        400: {"model": GeneralErrorResponse, "description": "Invalid `key_id_hex` format provided in the path."},
        404: {"model": GeneralErrorResponse, "description": "The specified `key_id_hex` was not found in Vault."},
        500: {"model": GeneralErrorResponse, "description": "An internal Vault error or unexpected issue occurred."},
        503: {"model": GeneralErrorResponse, "description": "Vault key manager module not loaded."}
    }
)
async def api_delete_key_set(key_id_hex: str):
    """
    Deletes all versions and metadata for a secret (key set) stored in Vault
    under `secret/keys/{key_id_hex}`.
    """
    if not VAULT_ACCESS_POSSIBLE:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Vault key manager functions not loaded.")
    
    if not (len(key_id_hex) == 32 and all(c in '0123456789abcdefABCDEF' for c in key_id_hex)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid key_id_hex format. Must be 32 hexadecimal characters.")

    try:
        client = _get_vault_client()
        vault_path = f'{KEY_PATH_PREFIX}/{key_id_hex}'

        # Check if path exists before attempting delete to provide a more specific 404
        try:
            client.secrets.kv.v2.read_secret_version(
                path=vault_path, 
                mount_point=VAULT_KV_MOUNT_POINT,
                raise_on_deleted_version=False 
            )
        except hvac.exceptions.InvalidPath:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Key ID '{key_id_hex}' not found in Vault. Nothing to delete.")
        
        # If read didn't raise InvalidPath, proceed with deletion
        client.secrets.kv.v2.delete_metadata_and_all_versions(
            mount_point=VAULT_KV_MOUNT_POINT,
            path=vault_path
        )
        return DeleteKeyResponse(status="deleted", key_id_hex=key_id_hex)

    except hvac.exceptions.VaultError as ve: 
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Vault operation error during deletion: {ve}")
    except Exception as e: 
        print(f"Unexpected error during key deletion for {key_id_hex}: {e}") 
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An unexpected error occurred while deleting key: {e}")