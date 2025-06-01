# Hybrid Quantum-Resistant Encryption System PoC

This project implements a proof-of-concept (PoC) for an advanced, multi-layered quantum-resistant encryption system. It demonstrates the synergy of several cutting-edge cryptographic concepts to provide robust data protection against both classical and emerging quantum threats.

The system integrates:
1.  **Hybrid Cryptography (Epic 1):** Combines traditional AES-256 with post-quantum Key Encapsulation Mechanisms (ML-KEM/Kyber) in both parallel and layered configurations.
2.  **Advanced Key Derivation (Epic 1 & 3):** Derives strong encryption keys from user-provided passwords and multiple additional factors (e.g., device IDs, session data) using Argon2id or PBKDF2. This process is further enhanced by **Entropy Anchoring**, incorporating randomness extracted from real-world chaotic systems (simulated with solar flare data).
3.  **Quantum Noise Entropy (QNE) Infusion (Epic 2):** Adds an optional outer layer of security by using dynamic entropy (from a simulated Quantum Random Number Generator) as Authenticated Data (AAD) in an AES-GCM encryption scheme. This binds the ciphertext to a unique, time-sensitive entropy source.
4.  **Secure Key Management (Epic 1):** Utilizes HashiCorp Vault (in development mode for this PoC) for the basic storage and retrieval of KEM private keys, AES keys, and KDF salt components, identified by unique IDs.

## Core System Functionality

The primary capabilities are demonstrated through high-level wrapper functions (conceptually in `main_unified_poc.py` or a dedicated system logic module):

*   **Layered Encryption with QNE Infusion:**
    1.  Data is encrypted using AES-256. The AES key is the shared secret from an ML-KEM (Kyber) operation. The ML-KEM private key is stored in Vault.
    2.  The resulting ciphertext is then further encrypted using AES-256-GCM, with dynamic entropy from the QNE pool used as Authenticated Data (AAD).
*   **Parallel Encryption with Anchored KDF and QNE Infusion:**
    1.  Data is encrypted twice in parallel using AES-256:
        *   Path A: AES key (`K1`) is derived from a password and additional factors using an anchored KDF (Argon2id/PBKDF2 + chaotic entropy). KDF salts are stored in Vault.
        *   Path B: AES key (`K2`) is derived from an ML-KEM (Kyber) shared secret. The KEM private key is stored in Vault.
    2.  The combined ciphertext from these parallel paths is then further encrypted using AES-256-GCM, with dynamic entropy from the QNE pool used as Authenticated Data (AAD).

## Project Structure & Key Modules

*   **`hybrid_cipher_project/` (Root)**
    *   **`epic1_modules/`**: Core hybrid encryption, KDF, and Vault logic.
        *   `parallel_encryption_vault.py`: Implements the parallel hybrid scheme with Vault.
        *   `layered_encryption_vault.py`: Implements the layered hybrid scheme with Vault.
        *   `key_derivation.py`: Implements Argon2id/PBKDF2 KDFs, now anchored with Epic 3's `EntropyManager`.
        *   `key_vault_manager.py`: Handles Vault communication.
    *   **`epic2_qne/`**: Quantum Noise Entropy infusion components.
        *   `qrng.py`: QRNG interface, software simulators, and mock QRNG.
        *   `entropy_pool.py`: Manages a dynamic, thread-safe pool of entropy from a QRNG.
        *   `cipher_engine.py`: AES-256-GCM engine for encrypting data with optional AAD.
    *   **`epic3_entropy_anchoring/`**: Entropy anchoring components.
        *   `data_fetcher.py`: Fetches solar flare data from NOAA.
        *   `entropy_extractor.py`: Processes chaotic data into usable entropy.
        *   `secure_prng.py`: Contains `SecurePRNG` (AES-CTR based) and `EntropyManager`.
    *   **`tests/`**: Unit and integration tests for all epics.
        *   `epic1_tests/`, `epic2_tests/`, `epic3_tests/`
    *   **`docs/`**: Supporting documentation.
        *   `solar_flares_explanation.md`
        *   `security_considerations.md`
        *   `benchmark_report.md`
    *   **`main_unified_poc.py`**: Demonstrates the integrated system flows (Epic 1 + Epic 3, optionally wrapped by Epic 2).
    *   `main_epic2_demo.py`, `main_epic3_demo.py`: Standalone demos for those epics.
    *   `benchmark_encryption.py`: Performance testing script for Epic 1 schemes.
    *   `README.md` (this file), `.gitignore`, `venv/` (virtual environment, ignored).

## Setup and Running

### Prerequisites

*   Python 3.8+ (Python 3.13.1 used in development)
*   Pip (Python package installer)
*   Git
*   HashiCorp Vault (see instructions below for dev mode)
*   A C compiler (e.g., GCC for MinGW on Windows, Clang/GCC on Linux/macOS) - potentially required for `oqs` (liboqs) and `argon2-cffi`.
*   CMake - potentially required for building `liboqs`.

### Python Environment and Dependencies

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd hybrid_cipher_project 
    ```

2.  **Create and activate a Python virtual environment:**
    ```bash
    python -m venv venv
    # Windows: venv\Scripts\activate
    # macOS/Linux: source venv/bin/activate
    ```

3.  **Install required Python packages:**
    ```bash
    pip install cryptography oqs hvac uuid argon2-cffi requests psutil
    ```
    *   **OQS Version Note:** Ensure you install the `oqs` package from the **Open Quantum Safe project** (e.g., `pip install oqs==0.12.0` or `oqs==0.10.0`). Check `pip show oqs`.
    *   **Compilation Note:** `argon2-cffi` and `oqs` may require compilation. Ensure build tools are available. For `liboqs`, manual compilation and PATH setup for the shared library might be needed.

### Setting Up HashiCorp Vault (Development Mode)

This PoC uses Vault in **development mode only (NOT for production)**.

1.  **Install Vault:** Download from [vaultproject.io/downloads](https://www.vaultproject.io/downloads) and add to PATH. Verify with `vault --version`.
2.  **Run Vault Dev Server:** Open a new terminal:
    ```bash
    vault server -dev
    ```
    Keep this terminal open. Note the **Root Token** (e.g., `hvs.xxxxxxxx...`).
3.  **Set Environment Variables:** In the terminal where you'll run Python scripts:
    *   `VAULT_ADDR`: Usually `http://127.0.0.1:8200`.
    *   `VAULT_TOKEN`: The Root Token from the step above.
    *   **Linux/macOS (bash/zsh):**
        ```bash
        export VAULT_ADDR='http://127.0.0.1:8200'
        export VAULT_TOKEN='YOUR_VAULT_ROOT_TOKEN'
        ```
    *   **Windows (Command Prompt):**
        ```bash
        set VAULT_ADDR=http://127.0.0.1:8200
        set VAULT_TOKEN=YOUR_VAULT_ROOT_TOKEN
        ```
    *   **Windows (PowerShell):**
        ```bash
        $env:VAULT_ADDR = "http://127.0.0.1:8200"
        $env:VAULT_TOKEN = "YOUR_VAULT_ROOT_TOKEN"
        ```

### Running Demonstrations and Tests

**Always run Python commands from the project root directory (`hybrid_cipher_project/`) after activating your virtual environment and setting Vault variables.**

1.  **Fetch Initial Chaotic Data (for Epic 3 functionality):**
    ```bash
    python epic3_entropy_anchoring/data_fetcher.py
    ```
    This creates/updates `epic3_entropy_anchoring/solar_flares_data.json`.

2.  **Run the Unified PoC Demonstration (Recommended):**
    This script showcases the integrated features of Epic 1 (with anchored KDF from Epic 3) and can include the QNE layer from Epic 2.
    ```bash
    python main_unified_poc.py
    ```

3.  **Run Individual Epic Demos (Optional):**
    *   `python main_epic2_demo.py`
    *   `python main_epic3_demo.py`
    *   Inline tests within `epic1_modules` (run with `python -m epic1_modules.module_name`)

4.  **Run All Unit Tests:**
    ```bash
    python -m unittest discover -s tests -p "test_*.py"
    ```

5.  **Run Performance Benchmarks (Epic 1, Ticket 6):**
    ```bash
    python benchmark_encryption.py
    ```

## Documentation

*   **`docs/solar_flares_explanation.md`**: Details on using solar flare data for entropy anchoring.
*   **`docs/security_considerations.md`**: Important security aspects for evolving towards a real-world deployment.
*   **`docs/benchmark_report.md`**: Performance benchmark results for Epic 1 schemes.
*   (Future) API documentation, tutorials based on Epic 4.

## Future Work

*   **Epic 4: API and User Interface Development:** Build interfaces to make this system accessible.
*   **Production Hardening:** Address all points in `docs/security_considerations.md`, including robust Vault setup, certified QRNGs, and rigorous entropy analysis.
*   **Algorithm Updates:** Stay current with NIST PQC standardization and update cryptographic primitives as needed.

---