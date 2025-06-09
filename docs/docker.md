# Using Docker with the Hybrid Quantum-Resistant Encryption System

This guide provides instructions on how to build and run the application and its dependencies (HashiCorp Vault) using Docker and Docker Compose. This is highly recommended for creating a consistent development, testing, and potentially deployment environment.

## Prerequisites

*   **Docker Desktop:** Install Docker Desktop for your operating system (Windows, macOS, or Linux). This includes Docker Engine and Docker Compose.
    *   Download from [Docker's official website](https://www.docker.com/products/docker-desktop).
*   **Git:** To clone the project repository.
*   **A terminal/shell:** (e.g., Bash, PowerShell, CMD).

## Project Structure for Docker

Ensure your project has the following (or similar) structure at the root:

```
hybrid_cipher_project/
├── api_server/             # Your FastAPI application
│   ├── core/
│   ├── models.py
│   ├── routers/
│   └── main.py
├── epic1_modules/          # Core encryption logic
├── epic2_qne/              # QNE logic
├── epic3_entropy_anchoring/  # Entropy Anchoring logic
│   └── solar_flares_data.json # Data file (can be volume mounted or copied in Docker)
├── tests/                  # Your Pytest tests
├── Dockerfile              # Instructions to build your Python app image
├── docker-compose.yml      # Defines and runs multi-container Docker applications
├── requirements.txt        # Python dependencies
├── .dockerignore           # Specifies files/dirs to exclude from Docker build context
└── ... (README.md, .gitignore, etc.)
```

## Step 1: Create `requirements.txt`

If you don't have one, create it from your activated virtual environment:
```bash
pip freeze > requirements.txt
```
Ensure this file lists all necessary Python packages: `fastapi`, `uvicorn`, `cryptography`, `oqs`, `hvac`, `uuid`, `argon2-cffi`, `requests`, `psutil`, `python-dotenv` (if you choose to use it for the server).

## Step 2: Create `.dockerignore` File

This file tells Docker which files and directories to ignore when building the image, similar to `.gitignore`. Create `.dockerignore` in your project root:

```
# .dockerignore
__pycache__/
*.pyc
*.pyo
*.pyd
.git/
.gitignore
.vscode/
.idea/
venv/
.venv/
ENV/
env/
build/
dist/
*.egg-info/
htmlcov/
.pytest_cache/
.tox/
*.log
# Potentially large data files you don't want in the image context
# if they are mounted as volumes or generated at runtime.
# solar_flares_data.json # Decide if this should be copied or mounted
.env # Do not include .env file with secrets in the image
docs/ # If docs are not needed in the running container
tests/ # If tests are not run inside the container by default
liboqs-python/ # If this was a local source build for oqs
```

## Step 3: Create `Dockerfile`

This file contains instructions to build the Docker image for your Python FastAPI application. Place it in your project root.

```dockerfile
# Dockerfile

# 1. Choose a Python base image
FROM python:3.11-slim AS builder 
# Using a slim image. Adjust Python version if needed (e.g., 3.13 if stable slim version available)

# 2. Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1  # Prevents python from writing .pyc files
ENV PYTHONUNBUFFERED 1      # Force stdin, stdout, and stderr to be totally unbuffered

# 3. Set working directory in the container
WORKDIR /app

# 4. Install system dependencies (if any are needed for your Python packages)
# For example, liboqs C library might need build tools or specific system libs if not handled by pip wheel.
# For oqs and argon2-cffi, build-essentials might be needed if wheels are not found.
# RUN apt-get update && apt-get install -y --no-install-recommends \
#     build-essential \
#     cmake \
#     # Add any other system deps for liboqs or argon2 if necessary
#     && rm -rf /var/lib/apt/lists/*

# 5. Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 6. Copy your application code into the container
# This order (requirements first, then code) leverages Docker's build cache.
COPY . .
# If you want to be more specific:
# COPY api_server /app/api_server
# COPY epic1_modules /app/epic1_modules
# COPY epic2_qne /app/epic2_qne
# COPY epic3_entropy_anchoring /app/epic3_entropy_anchoring
# COPY main_unified_poc.py /app/ # If used by API server for logic

# 7. Expose the port your application runs on (Uvicorn's default is 8000)
EXPOSE 8000

# 8. Define the command to run your application
# This will be the command run when the container starts.
# Uvicorn needs to bind to 0.0.0.0 to be accessible from outside the container.
CMD ["uvicorn", "api_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
```
**Note on `liboqs` C library:** If `pip install oqs` doesn't fetch a wheel that includes `liboqs` or if it needs to compile `liboqs`, your Docker image might need C build tools like `cmake` and a C compiler (e.g., `build-essential` on Debian-based images). This can make the Dockerfile more complex. Try without system dependencies first; `pip` might handle it with pre-built wheels.

## Step 4: Create `docker-compose.yml`

This file defines and runs your multi-container application (Vault and your API server). Place it in your project root.

```yaml
# docker-compose.yml
version: '3.8'

services:
  vault:
    image: hashicorp/vault:latest # Use official Vault image
    container_name: qre_vault_dev
    ports:
      - "8200:8200" # Map host port 8200 to container port 8200
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: "mydevroot" # Sets a predictable root token
      VAULT_DEV_LISTEN_ADDRESS: "0.0.0.0:8200" # Ensures Vault listens on all interfaces inside container
      VAULT_DISABLE_MLOCK: "true" # Recommended for Docker environments
    cap_add:
      - IPC_LOCK # Capability needed by Vault
    volumes:
      - vault_data:/vault/file # Optional: persist Vault dev data (still in-memory by default for -dev)
                               # For true persistence, don't use -dev mode and configure a file/raft backend.

  api_server:
    container_name: qre_api_server
    build:
      context: .       # Path to the directory containing the Dockerfile
      dockerfile: Dockerfile # Specifies the Dockerfile to use
    ports:
      - "8000:8000"   # Map host port 8000 to container port 8000
    volumes:
      - .:/app        # Mount current directory (project root) into /app in the container
                      # This enables live reloading with Uvicorn if you change code on your host.
                      # For production, you'd typically COPY code in Dockerfile and not use a volume like this.
    environment:
      # These will be available to your FastAPI application
      VAULT_ADDR: "http://vault:8200" # 'vault' is the service name of the Vault container
      VAULT_TOKEN: "mydevroot"        # Matches VAULT_DEV_ROOT_TOKEN_ID in the vault service
      SERVER_API_KEY: "poc_super_secret_api_key_123!" # Your API key
      PYTHONUNBUFFERED: 1 # Ensures Python print statements show up directly
      # Add any other environment variables your application needs
    depends_on:
      - vault         # Ensures Vault starts before the api_server
    command: uvicorn api_server.main:app --host 0.0.0.0 --port 8000 --reload # For development

volumes:
  vault_data: # Defines a named volume for Vault data (optional for dev mode)

```

**Explanation of `docker-compose.yml`:**
*   **`services`**: Defines two services: `vault` and `api_server`.
*   **`vault` service**:
    *   Uses the official `hashicorp/vault:latest` image.
    *   Maps port 8200.
    *   Sets `VAULT_DEV_ROOT_TOKEN_ID` to `"mydevroot"` for a predictable token.
    *   `VAULT_DEV_LISTEN_ADDRESS` ensures it's accessible within the Docker network.
    *   `VAULT_DISABLE_MLOCK` and `cap_add: [IPC_LOCK]` are common settings for running Vault in Docker.
*   **`api_server` service**:
    *   `build`: Tells Docker Compose to build an image using the `Dockerfile` in the current directory (`.`).
    *   Maps port 8000.
    *   `volumes: [.:/app]`: This is key for development. It mounts your local project directory into `/app` inside the container. When Uvicorn's `--reload` is active, changes you make to your local Python files will be reflected immediately in the running container. For production, you would `COPY` code in the `Dockerfile` and not use this type of volume mount.
    *   `environment`: Sets the necessary environment variables for your FastAPI application. Note that `VAULT_ADDR` uses the service name `vault` because Docker Compose provides DNS resolution between services on the same network.
    *   `depends_on: [vault]`: Ensures the `vault` service is started before the `api_server` service.
    *   `command`: Overrides the `CMD` in the `Dockerfile` to run Uvicorn with `--reload` for development.

## Step 5: Running the Application with Docker Compose

1.  **Open your terminal** in the root of your `hybrid_cipher_project` directory (where `docker-compose.yml` is).
2.  **Build and start the services:**
    ```bash
    docker-compose up --build
    ```
    *   `--build`: Forces Docker Compose to rebuild your `api_server` image if the `Dockerfile` or its context (your project files) have changed. You can omit `--build` on subsequent runs if only Python code (covered by the volume mount) has changed.
    *   This command will show logs from both Vault and your FastAPI application in your terminal.

3.  **Accessing Services:**
    *   **API Server:** `http://localhost:8000`
    *   **API Docs:** `http://localhost:8000/docs`
    *   **Vault UI/API (if needed for inspection):** `http://localhost:8200` (Token: `mydevroot`)

4.  **Interacting with the API:**
    *   Use Postman, curl, or your `key_management_ui.html` (if you serve it or adjust its `API_BASE_URL` to `http://localhost:8000/api/v1` and ensure CORS in FastAPI allows your HTML's origin). Your API Key is `poc_super_secret_api_key_123!`.

5.  **Running Pytest Tests Against the Dockerized API:**
    *   Keep `docker-compose up` running.
    *   Open a **new terminal**.
    *   Navigate to your project root.
    *   Activate your local Python virtual environment (pytest and httpx are installed here).
    *   Set the `TEST_API_BASE_URL` and `TEST_SERVER_API_KEY` environment variables (or use a `.env` file with `pytest-dotenv`):
        ```bash
        export TEST_API_BASE_URL="http://localhost:8000/api/v1" 
        export TEST_SERVER_API_KEY="poc_super_secret_api_key_123!" 
        # Also ensure VAULT_ADDR and VAULT_TOKEN are set if tests directly interact with key_vault_manager.py
        # for verification steps, though for API tests, direct Vault interaction should be minimal.
        export VAULT_ADDR="http://localhost:8200" 
        export VAULT_TOKEN="mydevroot"
        ```
    *   Run pytest:
        ```bash
        pytest tests/api_tests/
        ```

6.  **Stopping the Services:**
    *   In the terminal where `docker-compose up` is running, press `Ctrl+C`.
    *   To ensure containers are stopped and removed (and the network):
        ```bash
        docker-compose down
        ```
        If you used a named volume for Vault and want to remove it too: `docker-compose down -v`.

## Notes

*   **Solar Flare Data:** The `epic3_entropy_anchoring/solar_flares_data.json` file will be copied into the `api_server` image if it exists when `docker build` runs (because of `COPY . .`). If `data_fetcher.py` is run *inside* the container (e.g., as part of a startup script or a separate scheduled task containerized), it would write to the container's filesystem or a mounted volume. For this PoC, copying it at build time is simplest if it doesn't change frequently.
*   **Development vs. Production:** The `docker-compose.yml` and `Dockerfile` provided are geared towards a development setup (e.g., using `uvicorn --reload`, volume mounting code for live changes). Production setups would be different (e.g., no `--reload`, code copied directly into the image, potentially a more robust Uvicorn setup with Gunicorn as a process manager).
*   **`liboqs` in Docker:** If `pip install oqs` inside the Docker build requires compiling `liboqs` from source, you'll need to add `cmake` and a C compiler (like `build-essential` for Debian-based Python images) to the `Dockerfile`'s system dependencies installation step.

This guide should give you a solid way to containerize your application with Docker, making it more portable and easier to manage its dependencies like Vault.
```

---

**Before you start creating these files:**

1.  **Make sure `requirements.txt` is up-to-date.**
2.  Review the `Dockerfile` for any system dependencies your Python packages might need during installation if pre-compiled wheels are not available (especially `oqs` which needs `liboqs`). You might need to add `RUN apt-get update && apt-get install -y cmake build-essential` or similar.
3.  The `docker-compose.yml` uses `VAULT_DEV_ROOT_TOKEN_ID: "mydevroot"`. This means Vault started by Docker Compose will use "mydevroot" as its token. Your API server's `VAULT_TOKEN` environment variable is also set to "mydevroot", so they will match.

This setup provides a much more integrated and reproducible development environment.