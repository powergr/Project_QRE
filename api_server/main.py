# api_server/main.py
import os
import sys
from fastapi import FastAPI
from contextlib import asynccontextmanager
from typing import Optional 
from fastapi.middleware.cors import CORSMiddleware

# --- Add project root to sys.path to allow imports of epicX_modules ---
# This is a common way to handle imports when running an app from a subdirectory.
# It assumes 'api_server' is one level down from the project root.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
# --- End sys.path modification ---

# --- IMPORT QNE COMPONENTS EARLIER ---
# These are needed for the lifespan manager and type hinting.
QNE_COMPONENTS_LOADED = False # Default to False
try:
    from epic2_qne.entropy_pool import EntropyPool
    from epic2_qne.qrng import SoftwareSimulatedQRNG
    QNE_COMPONENTS_LOADED = True
    print("INFO [api_server/main.py]: QNE components (EntropyPool, SoftwareSimulatedQRNG) loaded successfully.")
except ImportError as e:
    print(f"WARNING [api_server/main.py]: Could not load QNE components (EntropyPool, SoftwareSimulatedQRNG): {e}")
    print("INFO [api_server/main.py]: QNE-dependent API endpoints might not function correctly.")
    # Define dummy/placeholder classes if import fails so type hints don't break,
    # and lifespan manager can check QNE_COMPONENTS_LOADED.
    class EntropyPool: # type: ignore
        def __init__(self, *args, **kwargs): pass
        def start(self): pass
        def stop(self): pass
    class SoftwareSimulatedQRNG: pass # type: ignore
# --- END QNE COMPONENT IMPORT ---


# --- Shared QNE Pool Management using lifespan ---
# Now EntropyPool should be defined (either real or dummy) when this line is parsed.
shared_qne_pool: Optional[EntropyPool] = None 

@asynccontextmanager
async def lifespan(app_instance: FastAPI): # Changed 'app' to 'app_instance' for clarity
    # Startup actions
    global shared_qne_pool # To modify the module-level global variable

    print("API Startup: Initializing QNE Pool...")
    if QNE_COMPONENTS_LOADED: # Only attempt to start if the real components were loaded
        try:
            # SoftwareSimulatedQRNG should be defined (real or dummy) here
            shared_qne_pool = EntropyPool(qrng_instance=SoftwareSimulatedQRNG(), refresh_interval_sec=2.0)
            shared_qne_pool.start()
            app_instance.state.qne_pool = shared_qne_pool # Make pool accessible via app.state
            print("API Startup: QNE Pool started successfully.")
        except Exception as e:
            print(f"API Startup: CRITICAL ERROR - Failed to start QNE Pool: {e}")
            # Ensure app.state.qne_pool is None if startup fails
            app_instance.state.qne_pool = None 
            shared_qne_pool = None # Also reset global shared_qne_pool
    else:
        print("API Startup: QNE components were not loaded. QNE Pool will not be started.")
        app_instance.state.qne_pool = None
        shared_qne_pool = None
    
    yield # Application runs here
    
    # Shutdown actions
    # Access pool via app_instance.state where it was set during startup
    pool_to_stop = getattr(app_instance.state, 'qne_pool', None) 
    if pool_to_stop and hasattr(pool_to_stop, 'stop'): # Check if it's a real pool with a stop method
        print("API Shutdown: Stopping QNE Pool...")
        pool_to_stop.stop()
        print("API Shutdown: QNE Pool stopped.")

# --- Initialize FastAPI app ---
app = FastAPI(
    title="Quantum-Resistant Encryption System API",
    description="API for performing hybrid quantum-resistant encryption, decryption, and basic key management.",
    version="0.1.0 (PoC)",
    lifespan=lifespan # Manages startup and shutdown events
)

# --- CORS Middleware Configuration ---
origins = [
    "http://localhost", 
    "http://localhost:8080", # Example if serving HTML on port 8080
    "http://127.0.0.1",
    "null", # Allow requests from file:/// origins (for local HTML files)
    # Add your React dev server origin here later, e.g., "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True, # Allow cookies if your API uses them (not in this PoC)
    allow_methods=["*"],    # Allow all methods (GET, POST, DELETE, etc.)
    allow_headers=["*"],    # Allow all headers (including X-API-Key)
)

# --- Import and Include Routers ---
# These imports should happen after sys.path is potentially modified
# and after 'app' is defined if routers need to access 'app' (though not typical for FastAPI routers).
try:
    from .routers import encryption, key_management # Relative import for routers within api_server package
    app.include_router(encryption.router, prefix="/api/v1")
    app.include_router(key_management.router, prefix="/api/v1")
    print("INFO [api_server/main.py]: Routers (encryption, key_management) included successfully.")
except ImportError as e:
    print(f"CRITICAL IMPORT ERROR for routers in api_server/main.py: {e}")
    print("INFO [api_server/main.py]: API will not have encryption/key management endpoints.")
    # Depending on severity, you might want to exit(1) here if routers are essential.


@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "Welcome to the Quantum-Resistant Encryption API PoC!"}

# To run this API server (from the hybrid_cipher_project/ directory):
# 1. Ensure Vault dev server is running.
# 2. Set environment variables: VAULT_ADDR, VAULT_TOKEN, SERVER_API_KEY.
# 3. Execute: uvicorn api_server.main:app --reload