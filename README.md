# Project QRE: Hybrid Quantum-Resistant Encryption System (Proof of Concept)

This project implements a comprehensive Proof of Concept (PoC) for an advanced, multi-layered quantum-resistant encryption system. It demonstrates the synergy of several cutting-edge cryptographic concepts to provide robust data protection against both classical and emerging quantum threats.

The system integrates three core pillars:
1.  **Hybrid Cryptography:** Combines traditional AES-256 with post-quantum Key Encapsulation Mechanisms (ML-KEM/Kyber) in both parallel and layered configurations.
2.  **Advanced Key Derivation with Entropy Anchoring:** Derives strong encryption keys from user-provided passwords and multiple additional factors (e.g., device IDs, session data) using Argon2id or PBKDF2. This process is further enhanced by **Entropy Anchoring**, incorporating randomness extracted from real-world chaotic systems (simulated with solar flare data).
3.  **Dynamic Ciphertext Authentication with External Entropy (QNE Infusion):** Adds an optional outer layer of security by using dynamic entropy (from a simulated Quantum Random Number Generator) as Authenticated Data (AAD) in an AES-GCM encryption scheme. This binds the ciphertext to a unique, time-sensitive entropy source and provides integrity for the AAD.
4.  **Secure Key Management:** Utilizes HashiCorp Vault (in development mode for this PoC) for the basic storage and retrieval of KEM private keys, AES keys, and KDF salt components, identified by unique IDs.
5.  **API Access:** A FastAPI-based RESTful API is provided to expose the core encryption, decryption, and basic key management functionalities.

## Core System Functionality Demonstrated

The primary capabilities are showcased through high-level wrapper functions (found in `main_unified_poc.py`) and exposed via the API:

*   **Layered Encryption (with optional QNE Infusion):**
    1.  Data is encrypted using AES-256. The AES key is the shared secret from an ML-KEM (Kyber) operation. The ML-KEM private key is stored in Vault.
    2.  Optionally, the resulting ciphertext can be further wrapped using AES-256-GCM, with dynamic entropy from the QNE pool used as Authenticated Data (AAD).
*   **Parallel Encryption (with optional QNE Infusion):**
    1.  Data is encrypted twice in parallel using AES-256:
        *   Path A: AES key (`K1`) is derived from a password and additional factors using an anchored KDF (Argon2id/PBKDF2 + chaotic entropy). KDF salts are stored in Vault. (This path is also available with a randomly generated `K1`).
        *   Path B: AES key (`K2`) is derived from an ML-KEM (Kyber) shared secret. The KEM private key is stored in Vault.
    2.  Optionally, the combined ciphertext from these parallel paths can be further wrapped using AES-256-GCM with QNE as AAD.

## Project Structure

```
hybrid_cipher_project/
├── api_server/                 # FastAPI application
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   └── security.py       # API key authentication
│   ├── models.py           # Pydantic request/response models
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── encryption.py     # Encryption/decryption API endpoints
│   │   └── key_management.py # Vault key deletion API endpoint
│   └── main.py             # FastAPI app initialization, lifespan manager
├── epic1_modules/              # Hybrid Ciphers, KDF, Vault Key Management
│   ├── __init__.py
│   ├── key_derivation.py
│   ├── key_vault_manager.py
│   ├── layered_encryption_vault.py
│   └── parallel_encryption_vault.py
├── epic2_qne/                  # Quantum Noise Entropy Infusion
│   ├── __init__.py
│   ├── cipher_engine.py
│   ├── entropy_pool.py
│   └── qrng.py
├── epic3_entropy_anchoring/      # Entropy Anchoring
│   ├── __init__.py
│   ├── data_fetcher.py
│   ├── entropy_extractor.py
│   └── secure_prng.py
├── tests/                      # All Pytest unit and integration tests
│   ├── __init__.py
│   ├── api_tests/
│   │   ├── __init__.py
│   │   ├── conftest.py
│   │   ├── test_encryption_endpoints.py
│   │   └── test_key_management_endpoints.py
│   ├── epic1_tests/
│   ├── epic2_tests/
│   └── epic3_tests/
├── docs/                       # Documentation files
│   ├── README.md (usually points to this main one or is a higher-level overview)
│   ├── api_guide.md
│   ├── api_tutorial.md
│   ├── benchmark_report.md
│   ├── docker.md
│   ├── project_overview_for_everyone.md
│   ├── security_considerations.md
│   └── solar_flares_explanation.md
├── .env                        # For local development environment variables (GITIGNORED!)
├── .gitignore
├── Dockerfile                  # For containerizing the API server
├── docker-compose.yml          # For orchestrating API server and Vault
├── main_epic2_demo.py          # Standalone demo for QNE features
├── main_epic3_demo.py          # Standalone demo for Entropy Anchoring
├── main_unified_poc.py         # Demonstrates integrated Epic 1 & optional Epic 2 wrapping
├── benchmark_encryption.py     # Performance testing script
├── requirements.txt            # Python package dependencies
├── start_dev_environment.sh    # Bash script to set up dev environment & start API
└── venv/                       # Python virtual environment (GITIGNORED!)
```

## Setup and Running

### I. Prerequisites

*   Python 3.8+ (e.g., 3.13.1)
*   Pip (Python package installer)
*   Git
*   HashiCorp Vault (Community Edition, latest recommended)
*   Docker and Docker Compose (Optional, but recommended for an easier Vault+API setup)
*   A C compiler (e.g., GCC for MinGW on Windows, Clang/GCC on Linux/macOS) - potentially required for `oqs` (liboqs) and `argon2-cffi` if binary wheels are not available for your platform.
*   CMake - potentially required for building `liboqs`.

### II. Project Clone and Python Environment

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd hybrid_cipher_project
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    # On Windows (cmd.exe): venv\Scripts\activate.bat
    # On Windows (PowerShell): .\venv\Scripts\Activate.ps1
    # On macOS/Linux (bash/zsh): source venv/bin/activate
    ```

3.  **Install required Python packages:**
    ```bash
    pip install -r requirements.txt
    ```
    *   **Note on `oqs`:** The `requirements.txt` should specify the correct version of `oqs` from the Open Quantum Safe project (e.g., `oqs==0.12.0` or `oqs==0.10.0`). If you build `requirements.txt` with `pip freeze`, this will be handled. If installing manually, ensure you get the correct package.
    *   **Compilation Note:** `argon2-cffi` and `oqs` might require compilation. If issues arise, ensure build tools (C compiler, CMake for `liboqs`) are installed and accessible. For `liboqs`, if the Python wheel doesn't include it, manual compilation and ensuring the shared library (e.g., `liboqs.dll`) is in your system's PATH might be necessary.

### III. Setting Up HashiCorp Vault (Development Mode)

This PoC uses Vault in **development mode only (NOT for production)**.

**Option A: Manual Vault Setup (if not using Docker Compose)**

1.  **Install Vault:** Download from [vaultproject.io/downloads](https://www.vaultproject.io/downloads), extract, and add the `vault` executable to your system's PATH. Verify: `vault --version`.
2.  **Run Vault Dev Server:** Open a **separate, dedicated terminal** and run:
    ```bash
    vault server -dev -dev-root-token-id="mydevroot"
    ```
    *   Using `-dev-root-token-id="mydevroot"` sets a predictable root token. You can choose any string.
    *   Note the `API Address` (usually `http://127.0.0.1:8200`) and confirm the `Root Token` is `mydevroot`.
    *   **Keep this Vault terminal window open.**

**Option B: Using Docker Compose (Recommended for easy setup)**

1.  Ensure Docker Desktop is installed and running.
2.  From the project root (`hybrid_cipher_project/`), run:
    ```bash
    docker-compose up --build -d vault 
    ```
    *   This starts Vault in a detached container. The `VAULT_DEV_ROOT_TOKEN_ID` is set to `"mydevroot"` in `docker-compose.yml`.
    *   Vault will be accessible at `http://localhost:8200`. The token is `mydevroot`.

### IV. Setting Environment Variables (for API Server & Tests)

The application and tests require environment variables.

**Option A: Manual Export (if not using `.env` for the API server, or for `pytest` if `pytest-dotenv` is not used)**
In the terminal where you will run the API server or `pytest`:

*   `VAULT_ADDR`: `http://127.0.0.1:8200`
*   `VAULT_TOKEN`: `mydevroot` (or your chosen/auto-generated dev token)
*   `SERVER_API_KEY`: `poc_super_secret_api_key_123!` (for the API server)
*   `TEST_SERVER_API_KEY`: `poc_super_secret_api_key_123!` (for `pytest` via `conftest.py`)

    *   **Linux/macOS/Git Bash:**
        ```bash
        export VAULT_ADDR='http://127.0.0.1:8200'
        export VAULT_TOKEN='mydevroot'
        export SERVER_API_KEY='poc_super_secret_api_key_123!'
        export TEST_SERVER_API_KEY='poc_super_secret_api_key_123!'
        ```
    *   *(Equivalent `set` or `$env:` commands for Windows CMD/PowerShell)*

**Option B: Using `.env` file (Recommended for local development with `pytest` and can be adapted for API server)**
1.  Create a `.env` file in the project root (`hybrid_cipher_project/.env`):
    ```env
    VAULT_ADDR=http://127.0.0.1:8200
    VAULT_TOKEN=mydevroot
    SERVER_API_KEY=poc_super_secret_api_key_123!
    TEST_SERVER_API_KEY=poc_super_secret_api_key_123!
    ```
2.  **Add `.env` to your `.gitignore` file!**
3.  `pytest` (with `pytest-dotenv` installed) will automatically load this.
4.  For the API server (`uvicorn`), it won't automatically load `.env`. You can:
    *   Source the `.env` file before running `uvicorn` if your shell supports it (e.g., `set -a; source .env; set +a; uvicorn ...`).
    *   Or explicitly set them as in Option A in the terminal that runs `start_dev_environment.sh` or directly `uvicorn`.
    *   Or use the `python-dotenv` library within `api_server/main.py` to load it (e.g., `from dotenv import load_dotenv; load_dotenv()`).

### V. Running the Application & Demonstrations

**Always run Python commands from the project root directory (`hybrid_cipher_project/`) after activating your virtual environment and ensuring Vault and environment variables are set up.**

1.  **Start the API Server (using the helper script or Docker Compose):**
    *   **Using `start_dev_environment.sh` (for Git Bash on Windows, or adapt for Linux/macOS):**
        This script sets environment variables, activates venv, optionally fetches data, and starts Uvicorn.
        ```bash
        ./start_dev_environment.sh
        ```
        (Ensure Vault is already running in another terminal as per the script's instructions if not using Docker Compose for Vault).
    *   **Using Docker Compose (starts both Vault and API server):**
        ```bash
        docker-compose up --build api_server 
        # Or 'docker-compose up --build' to start all services defined (Vault and api_server)
        ```
    *   The API will be available at `http://127.0.0.1:8000`.
    *   Interactive API Docs: `http://127.0.0.1:8000/docs` (Swagger UI) and `/redoc`.

2.  **Fetch Initial Chaotic Data (for Entropy Anchoring functionality):**
    (If not included in your `start_dev_environment.sh` or if running API server differently)
    ```bash
    python epic3_entropy_anchoring/data_fetcher.py
    ```

3.  **Run the Unified PoC Demonstration (Recommended for overall check):**
    This script showcases integrated Epic 1 (with anchored KDF from Epic 3) and QNE layer from Epic 2.
    (Requires API server to be running if it makes API calls, or modify it to call Python functions directly if it's a backend demo).
    **The `main_unified_poc.py` we developed calls Python functions directly, so it doesn't strictly need the API server running for *its own execution*, but it *does* need Vault running and VAULT_ADDR/VAULT_TOKEN set in its execution environment.**
    ```bash
    python main_unified_poc.py
    ```

4.  **Run Individual Component Demos (Optional):**
    *   `python main_epic2_demo.py`
    *   `python main_epic3_demo.py`
    *   Inline tests within `epic1_modules` (run with `python -m epic1_modules.module_name`)
    *   Inline tests within `epic3_entropy_anchoring` modules.

### VI. Running Tests

Ensure Vault is running and all necessary environment variables (`VAULT_ADDR`, `VAULT_TOKEN`, `TEST_SERVER_API_KEY`) are set in the terminal where you run `pytest` (or use `.env` with `pytest-dotenv`). The API server also needs to be running for API tests.

1.  **Run All Unit and Integration Tests:**
    ```bash
    pytest
    ```
    (This will discover tests in the `tests/` directory based on `pytest.ini` configuration).

2.  **Run Specific Test Suites (Example):**
    ```bash
    pytest tests/api_tests/
    pytest tests/epic1_tests/test_vault_integration.py
    python -m unittest discover -s tests.epic3_tests -p "test_*.py" 
    ```

### VII. Running Performance Benchmarks
```bash
python benchmark_encryption.py
```
(Ensure Vault is running and env vars are set. Results and system info will be printed; also refer to `docs/benchmark_report.md`)

## Documentation

*   **Interactive API Docs (Swagger UI):** Served at `/docs` when the API server is running (e.g., `http://127.0.0.1:8000/docs`).
*   **Interactive API Docs (ReDoc):** Served at `/redoc` when the API server is running.
*   **Static API Guide:** [API Endpoint Guide](./docs/api_guide.md)
*   **API Tutorial:** [API Usage Tutorial](./docs/api_tutorial.md)
*   **Solar Flare Entropy:** [Explanation of Solar Flare Data Usage](./docs/solar_flares_explanation.md)
*   **Security Considerations:** [Important Security Notes](./docs/security_considerations.md)
*   **Benchmark Report:** [Performance Results](./docs/benchmark_report.md)
*   **Docker Usage:** [Containerizing with Docker](./docs/docker.md)
*   **Project Overview (Non-Technical):** [Project QRE Explained](./docs/project_overview_for_everyone.md)


## Future Work

*   **Production Hardening:** Address all points in `docs/security_considerations.md`.
*   **UI Development (Epic 4, Ticket 4.3):** Implement the basic web UI for key management.
*   **Algorithm Updates & PQC Standards:** Stay current with NIST PQC finalizations.
*   **Hardware QRNG/HSM:** Plan for and integrate hardware security components for production.

