# api_server/main.py
import os
import sys
from fastapi import FastAPI
from contextlib import asynccontextmanager
from typing import Optional # Ensure this is imported
from fastapi.middleware.cors import CORSMiddleware

# --- Add project root to sys.path ---
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
# --- End sys.path modification ---

# --- Shared QNE Pool Management using lifespan (defined before app creation) ---
shared_qne_pool: Optional[EntropyPool] = None # Forward declare for lifespan

# Forward declare EntropyPool and SoftwareSimulatedQRNG if they are used in lifespan
# and their import is further down. Best to import them earlier.
try:
    from epic2_qne.entropy_pool import EntropyPool
    from epic2_qne.qrng import SoftwareSimulatedQRNG
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR for QNE components in api_server/main.py: {e}")
    # Define dummy classes if import fails so lifespan doesn't break,
    # but QNE pool won't work.
    class EntropyPool: pass 
    class SoftwareSimulatedQRNG: pass
    # This means API endpoints relying on QNE pool will fail gracefully later.


@asynccontextmanager
async def lifespan(app_instance: FastAPI): # Changed 'app' to 'app_instance' to avoid conflict
    # Startup actions
    global shared_qne_pool # To modify the global variable
    print("API Startup: Initializing QNE Pool...")
    try:
        # Ensure SoftwareSimulatedQRNG is defined or imported here
        shared_qne_pool = EntropyPool(qrng_instance=SoftwareSimulatedQRNG(), refresh_interval_sec=2.0)
        shared_qne_pool.start()
        app_instance.state.qne_pool = shared_qne_pool # Make pool accessible via app.state
        print("API Startup: QNE Pool started successfully.")
    except Exception as e:
        print(f"API Startup: CRITICAL ERROR - Failed to start QNE Pool: {e}")
        app_instance.state.qne_pool = None 
    
    yield # Application runs here
    
    # Shutdown actions
    # Access pool via app_instance.state if it was set
    pool_to_stop = getattr(app_instance.state, 'qne_pool', None) 
    if pool_to_stop:
        print("API Shutdown: Stopping QNE Pool...")
        pool_to_stop.stop()
        print("API Shutdown: QNE Pool stopped.")

# --- Initialize FastAPI app FIRST ---
app = FastAPI(
    title="Quantum-Resistant Encryption System API",
    description="API for performing hybrid quantum-resistant encryption, decryption, and basic key management.",
    version="0.1.0 (PoC)",
    lifespan=lifespan # Manages startup and shutdown events
)

# --- CORS Middleware Configuration (NOW app is defined) ---
origins = [
    "http://localhost", 
    "http://localhost:8080", 
    "http://127.0.0.1",
    "null", # Allow requests from file:/// origins
    # Add your React dev server origin here later, e.g., "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True, 
    allow_methods=["*"],    
    allow_headers=["*"],    
)

# --- Import and Include Routers (AFTER app and middleware) ---
try:
    from .routers import encryption, key_management # Relative import for routers
    app.include_router(encryption.router, prefix="/api/v1")
    app.include_router(key_management.router, prefix="/api/v1")
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR for routers in api_server/main.py: {e}")
    # Potentially exit or raise if routers are critical
    # exit(1)


@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Quantum-Resistant Encryption API PoC!"}

# To run this API server (from the hybrid_cipher_project/ directory):
# 1. Ensure Vault dev server is running.
# 2. Set environment variables: VAULT_ADDR, VAULT_TOKEN, SERVER_API_KEY.
# 3. Execute: uvicorn api_server.main:app --reload