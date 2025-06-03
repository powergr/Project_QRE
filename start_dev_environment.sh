#!/bin/bash

# Script to start the development environment for Hybrid Cipher Project

echo "Starting Hybrid Cipher Project Development Environment..."

# --- Configuration ---
MY_FIXED_VAULT_TOKEN="mydevroot" # Your chosen fixed token
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN="${MY_FIXED_VAULT_TOKEN}" # EXPORT it here
export SERVER_API_KEY="poc_super_secret_api_key_123!"


# Check if Vault is running (simple check, not foolproof)
if ! curl -s "${VAULT_ADDR}/v1/sys/health" > /dev/null; then
    echo "Vault dev server not detected at ${VAULT_ADDR}."
    echo "Please start it in another terminal: vault server -dev"
    echo "Then, note the Root Token and set VAULT_TOKEN environment variable."
    # exit 1 # Or continue and let Python scripts fail if Vault is critical
else
    echo "Vault server seems to be running at ${VAULT_ADDR}."
fi

if [ -z "$VAULT_TOKEN" ]; then
    echo "--------------------------------------------------------------------"
    echo "IMPORTANT: VAULT_TOKEN environment variable is not set!"
    echo "Please get the Root Token from your 'vault server -dev' output"
    echo "and set it in this terminal session before running dependent scripts:"
    echo "  export VAULT_TOKEN='<your_vault_root_token>'"
    echo "--------------------------------------------------------------------"
    # exit 1 # Or allow scripts to run and potentially fail more gracefully
fi


# --- Activate Virtual Environment ---
if [ -d "venv" ]; then
    echo "Activating Python virtual environment..."
    source venv/Scripts/activate # For Git Bash on Windows
    # On Linux/macOS, it would be: source venv/bin/activate
else
    echo "Virtual environment 'venv' not found. Please create it first."
    exit 1
fi

# --- Optional: Fetch latest chaotic data ---
echo "Fetching latest solar flare data..."
python epic3_entropy_anchoring/data_fetcher.py

# --- Start FastAPI/Uvicorn Server ---
echo "Starting FastAPI server with Uvicorn..."
echo "API will be available at http://127.0.0.1:8000"
echo "Swagger UI docs at http://127.0.0.1:8000/docs"
echo "Press Ctrl+C to stop the server."

# Run Uvicorn. It will take over this terminal.
# You'll need another terminal to run tests or interact with the API via curl.
uvicorn api_server.main:app --reload --host 0.0.0.0 --port 8000

# --- Cleanup (optional, runs after Uvicorn is stopped with Ctrl+C) ---
echo "Deactivating virtual environment..."
deactivate # If applicable, though Ctrl+C might bypass this.

echo "Development environment script finished."