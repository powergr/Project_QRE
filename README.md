
# Hybrid Quantum-Resistant Encryption Project

This project implements a proof-of-concept for hybrid encryption schemes,
combining classical symmetric algorithms with post-quantum key encapsulation
mechanisms. It includes modules for parallel encryption, layered (hybrid)
encryption, key derivation, and basic key management using HashiCorp Vault.

## Modules

*   **`parallel_encryption_vault.py`**: Implements parallel encryption (AES + KEM-derived AES) with keys stored in Vault.
*   **`layered_encryption_vault.py`**: Implements layered encryption (KEM encapsulates AES key) with KEM private key stored in Vault.
*   **`key_derivation.py`**: Provides functions to derive cryptographic keys using Argon2id or PBKDF2.
*   **`key_vault_manager.py`**: Handles interaction with HashiCorp Vault for storing and retrieving keys.

## Epic 3: Entropy Anchoring with Chaotic Systems

This component focuses on enhancing key generation by incorporating entropy derived
from real-world chaotic systems (simulated with solar flare data in the PoC).
The goal is to provide a novel and robust source of randomness for cryptographic keys.

**Key Modules for Epic 3 (found in `epic3_entropy_anchoring/` directory):**

*   **`data_fetcher.py`**: Responsible for fetching raw chaotic data (e.g., solar flare information from NOAA's API) and storing it locally.
*   **`entropy_extractor.py`**: Processes the raw chaotic data, extracts potentially unpredictable elements, and converts them into a fixed-size entropy string using cryptographic hashing (SHA3-256). Includes basic quality and freshness checks.
*   **`secure_prng.py`**:
    *   Implements `SecurePRNG`: An AES-CTR based pseudo-random number generator.
    *   Implements `EntropyManager`: A class that attempts to use freshly extracted chaotic entropy. If chaotic entropy is unavailable, stale, or fails quality checks, it falls back to using the `SecurePRNG` (which can be optionally seeded by chaotic entropy if available at initialization).
*   **`key_generator_anchored.py`**: Provides KDF functions (PBKDF2, HKDF) that enhance their inputs (like salts or initial keying material) with entropy obtained from the `EntropyManager`. This "anchors" the key derivation process to the chaotic entropy source.

**Demonstration:**

*   Run `python epic3_entropy_anchoring/data_fetcher.py` to download the latest solar flare data.
*   Run `python main_epic3_demo.py` to see a demonstration of the entropy manager and anchored key generation.

**Unit Tests for Epic 3:**
```bash
python -m unittest discover -s tests.epic3_tests -p "test_*.py"

## Setup and Running

### Prerequisites

*   Python 3.8+
*   Pip (Python package installer)
*   Git
*   HashiCorp Vault (see instructions below for dev mode)
*   A C compiler (e.g., GCC for MinGW on Windows, Clang/GCC on Linux/macOS) - required for `liboqs` (via the `oqs` Python package) and potentially `argon2-cffi`.
*   CMake - required for building `liboqs`.

### Python Environment and Dependencies

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <your-repository-url>
    cd <your-repository-name>
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    # On Windows (cmd.exe/powershell):
    # venv\Scripts\activate
    # On macOS/Linux (bash/zsh):
    source venv/bin/activate
    ```

3.  **Install required Python packages:**
    ```bash
    pip install cryptography oqs hvac uuid argon2-cffi requests psutil
    ```
    *Note: If `pip install oqs` installs an incorrect version (e.g., "Open Quick Script"), you may need to specify a version from the Open Quantum Safe project, like `pip install oqs==0.10.0` or `oqs==0.12.0`.*
    *Note: `argon2-cffi` and `oqs` (which depends on `liboqs`) might require compilation. If you encounter issues, ensure you have necessary build tools (C compiler, CMake for `liboqs`). For `liboqs`, you may need to build it manually and ensure the DLL/shared library is in your system's PATH if the Python wrapper doesn't handle it automatically.*

### Setting Up HashiCorp Vault (Development Mode)

For this Proof of Concept, we use HashiCorp Vault running in development mode. This mode is **not suitable for production** as it stores data in-memory and uses a known root token.

1.  **Install HashiCorp Vault:**
    *   Download the appropriate Vault binary for your operating system from the [official Vault website](https://www.vaultproject.io/downloads).
    *   Extract the downloaded archive.
    *   Place the `vault` executable in a directory that is part of your system's PATH environment variable (e.g., `/usr/local/bin` on Linux/macOS, or a custom directory you add to PATH on Windows).
    *   Verify installation by opening a new terminal and typing:
        ```bash
        vault --version
        ```

2.  **Run Vault Server in Development Mode:**
    *   Open a new terminal window.
    *   Execute the command:
        ```bash
        vault server -dev
        ```
    *   Vault will start and output several pieces of information. **Keep this terminal window open** as long as you are running the Python scripts that interact with Vault.

3.  **Note the Unseal Key and Root Token:**
    *   When `vault server -dev` starts, it will print lines similar to (example):
        ```
        ==> Vault server configuration:
        
                       Api Address: http://127.0.0.1:8200
                       Cgo: disabled
                       Listener 1: tcp (addr: "127.0.0.1:8200", cluster address: "127.0.0.1:8201", max_request_duration: "1m30s", proxy_protocol_behavior: "use_always", tls: "disabled")
                       Log Level: info
                       Mlock: supported: true, enabled: false
                       Recovery Mode: false
                       Storage: inmem (HA available)
                       Version: Vault vX.Y.Z
                       Version Sha: ...
        
        ==> Vault server started! Log data will stream in below:
        
        ...
        Unseal Key (will be auto-unsealed): <some_unseal_key_value>
        Root Token: hvs.xxxxxxxxxxxxxxxxxxxxxxxx 
        ...
        ```
    *   You primarily need the **Root Token**. Copy this value carefully. For the dev server, the "Unseal Key" is usually handled automatically, but the Root Token is what your application will use to authenticate.

4.  **Set Environment Variables:**
    *   In the terminal(s) where you will run your Python application scripts (`key_vault_manager.py`, `parallel_encryption_vault.py`, `layered_encryption_vault.py`, `test_vault_integration.py`), you need to set two environment variables:
        *   `VAULT_ADDR`: The API address Vault is listening on (usually `http://127.0.0.1:8200`).
        *   `VAULT_TOKEN`: The Root Token you noted in the previous step.

    *   **On Linux/macOS (bash/zsh):**
        ```bash
        export VAULT_ADDR='http://127.0.0.1:8200'
        export VAULT_TOKEN='<your_actual_root_token_here>' 
        ```
        (e.g., `export VAULT_TOKEN='hvs.xxxxxxxxxxxxxxxxxxxxxxxx'`)

    *   **On Windows (Command Prompt):**
        ```bash
        set VAULT_ADDR=http://127.0.0.1:8200
        set VAULT_TOKEN=<your_actual_root_token_here>
        ```

    *   **On Windows (PowerShell):**
        ```bash
        $env:VAULT_ADDR = "http://127.0.0.1:8200"
        $env:VAULT_TOKEN = "<your_actual_root_token_here>"
        ```
    *   These variables need to be set for each new terminal session unless you add them to your shell's profile configuration file (e.g., `.bashrc`, `.zshrc`, or Windows Environment Variables settings).

### Running the Key Management Tests

Once Vault is running and environment variables are set:

1.  **Test the Vault manager directly (optional quick check):**
    ```bash
    python key_vault_manager.py
    ```
    This script contains a basic inline test to store and retrieve keys.

2.  **Run inline tests for encryption modules (optional quick checks):**
    ```bash
    python parallel_encryption_vault.py
    python layered_encryption_vault.py
    ```

3.  **Run the comprehensive integration tests:**
    ```bash
    python -m unittest test_vault_integration.py
    ```
    All tests should pass if Vault is set up correctly and the code is working.
