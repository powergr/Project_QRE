# api_server/core/security.py
from fastapi import Security, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
import os
from typing import Optional

# For PoC, API key can be set via environment variable or hardcoded as a default
SERVER_API_KEY_ENV_VAR = "SERVER_API_KEY"
DEFAULT_POC_API_KEY = "poc_super_secret_api_key_123!" # Change this in a real setting

API_KEY = os.environ.get(SERVER_API_KEY_ENV_VAR, DEFAULT_POC_API_KEY)
API_KEY_NAME = "X-API-Key" # Custom header name

api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=False) # auto_error=False to handle error manually

async def get_api_key(api_key_header: Optional[str] = Security(api_key_header_auth)):
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated: X-API-Key header missing.",
        )
    if api_key_header == API_KEY:
        return api_key_header
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key.",
        )

# You can also create a dependency that returns a boolean or user object
async def verify_api_key(api_key: str = Depends(get_api_key)):
    # This dependency can be used if you just need to protect the route
    # and don't need the api_key value itself in the route function.
    if not api_key: # Should not happen if get_api_key worked as expected
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    return True # Indicates successful authentication