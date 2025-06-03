# api_server/core/security.py
from fastapi import Security, HTTPException, status, Depends
from fastapi.security.api_key import APIKeyHeader
import os
from typing import Optional

# --- Define the expected API Key ---
# For PoC, API key can be set via environment variable or hardcoded as a default
SERVER_API_KEY_ENV_VAR = "SERVER_API_KEY"
DEFAULT_POC_API_KEY = "poc_super_secret_api_key_123!" # Ensure this matches your .env and conftest.py

# This is the key the server will expect.
# It tries to get it from the environment variable SERVER_API_KEY.
# If that's not set, it uses the DEFAULT_POC_API_KEY.
API_KEY = os.environ.get(SERVER_API_KEY_ENV_VAR, DEFAULT_POC_API_KEY)
# --- End Define the expected API Key ---

API_KEY_NAME = "X-API-Key" # Custom header name for clients to send the key

# auto_error=False allows us to give custom messages for missing vs. invalid
api_key_header_auth = APIKeyHeader(name=API_KEY_NAME, auto_error=False) 

async def get_api_key(api_key_header: Optional[str] = Security(api_key_header_auth)):
    """
    Dependency to validate the API key from the X-API-Key header.
    Compares the provided header against the server's expected API_KEY.
    """
    # Add a debug print here to see what the server thinks the API_KEY is
    # print(f"DEBUG [security.py]: Server expecting API Key: '{API_KEY}'")
    # print(f"DEBUG [security.py]: Received X-API-Key header: '{api_key_header}'")

    if api_key_header is None: # Header was missing
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated: X-API-Key header missing.",
        )
    if api_key_header == API_KEY: # The crucial comparison
        return api_key_header # Return the key if it's valid
    else: # Header was present but the key value was wrong
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, # 401 is appropriate for bad credentials
            detail="Invalid API Key.", # This message now matches your failing test's expectation
        )

async def verify_api_key(api_key: str = Depends(get_api_key)):
    """
    A simple dependency that uses get_api_key to protect a route.
    If get_api_key successfully returns (i.e., doesn't raise HTTPException),
    it means authentication passed.
    """
    # No need for 'if not api_key:' here, as get_api_key would have raised
    # an exception if the key was missing or invalid.
    return True # If we get here, auth was successful.