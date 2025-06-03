# tests/api_tests/conftest.py
import pytest
import httpx
import os
import base64 # For encoding test data
from typing import Generator

# --- Configuration for API tests ---
# Use environment variables for flexibility or fall back to defaults
API_BASE_URL = os.environ.get("TEST_API_BASE_URL", "http://127.0.0.1:8000/api/v1")
SERVER_POC_API_KEY = os.environ.get("TEST_SERVER_API_KEY", "poc_super_secret_api_key_123!") 
# ^ This should match the key your FastAPI server is expecting

@pytest.fixture(scope="session") # "session" scope means this runs once per test session
def api_client() -> Generator[httpx.Client, None, None]: # <--- CORRECTED TYPE HINT
    """
    Provides an authenticated httpx client for making API requests.
    The client includes the necessary X-API-Key header.
    The client is managed by a context manager and closed after the session.
    """
    headers = {
        "X-API-Key": SERVER_POC_API_KEY,
        "accept": "application/json",
        "Content-Type": "application/json"
    }
    # The 'with' statement ensures the client is properly closed after all tests
    # in the session that use this fixture have completed.
    with httpx.Client(base_url=API_BASE_URL, headers=headers, timeout=10.0) as client:
        yield client # This client instance is what tests will receive

@pytest.fixture(scope="module")
def sample_plaintext_bytes() -> bytes:
    return b"This is some sample plaintext for API testing!"

@pytest.fixture(scope="module")
def sample_plaintext_b64(sample_plaintext_bytes: bytes) -> str:
    return base64.b64encode(sample_plaintext_bytes).decode('utf-8')

@pytest.fixture(scope="module")
def kdf_password_bytes() -> bytes:
    return b"StrongApiTestP@ssw0rd"

@pytest.fixture(scope="module")
def kdf_password_b64(kdf_password_bytes: bytes) -> str:
    return base64.b64encode(kdf_password_bytes).decode('utf-8')

@pytest.fixture(scope="module")
def kdf_additional_inputs_bytes() -> list[bytes]:
    return [b"api_factor_1", b"device_api_xyz"]

@pytest.fixture(scope="module")
def kdf_additional_inputs_b64(kdf_additional_inputs_bytes: list[bytes]) -> list[str]:
    return [base64.b64encode(factor).decode('utf-8') for factor in kdf_additional_inputs_bytes]