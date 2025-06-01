# epic1_modules/key_derivation.py
import os
import hashlib 
from typing import List, Tuple, Optional 

from argon2 import low_level
from argon2.exceptions import Argon2Error 
from cryptography.hazmat.primitives import hashes as crypto_hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

try:
    from epic3_entropy_anchoring.secure_prng import EntropyManager
    from epic3_entropy_anchoring.data_fetcher import DEFAULT_SOLAR_FLARES_FILE
    _epic3_base_path_for_data = None
    try:
        import epic3_entropy_anchoring.entropy_extractor as ee_module
        _epic3_base_path_for_data = os.path.dirname(os.path.abspath(ee_module.__file__))
    except (ImportError, AttributeError): 
        _key_derivation_dir = os.path.dirname(os.path.abspath(__file__))
        _project_root_approx = os.path.dirname(_key_derivation_dir) 
        _epic3_base_path_for_data = os.path.join(_project_root_approx, "epic3_entropy_anchoring")
    CHAOTIC_DATA_FILE_PATH_FOR_EM = os.path.join(_epic3_base_path_for_data, DEFAULT_SOLAR_FLARES_FILE)
    ENTROPY_MANAGER_INSTANCE = EntropyManager(chaotic_data_file_path=CHAOTIC_DATA_FILE_PATH_FOR_EM)
    # print(f"DEBUG [key_derivation]: EntropyManager initialized, will look for chaotic data at: {CHAOTIC_DATA_FILE_PATH_FOR_EM}")
except ImportError:
    print("WARNING [key_derivation]: Epic 3 EntropyManager not found. KDF will use os.urandom for salt component.")
    ENTROPY_MANAGER_INSTANCE = None

ARGON2_TIME_COST = 4; ARGON2_MEMORY_COST_KB = 32768; ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32; ARGON2_TYPE = low_level.Type.ID
PBKDF2_ITERATIONS = 100000; PBKDF2_HASH_ALG = crypto_hashes.SHA256(); PBKDF2_KEY_LEN = 32 

def derive_key(
    password: bytes,
    additional_inputs: Optional[List[bytes]] = None,
    method: str = "Argon2id",
    _rederive_using_factors_hash: Optional[bytes] = None,
    _rederive_using_random_salt_component: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]: # Returns key, factors_hash_that_was_used, random_salt_component_that_was_used

    if not isinstance(password, bytes): raise ValueError("Password must be bytes.")
    if additional_inputs is not None and (not isinstance(additional_inputs, list) or not all(isinstance(inp, bytes) for inp in additional_inputs)):
        raise ValueError("If provided, additional_inputs must be a list of byte strings.")
    if method not in ["Argon2id", "PBKDF2"]: raise ValueError(f"Unsupported KDF method: {method}.")

    actual_additional_inputs_for_hash = additional_inputs if additional_inputs is not None else []

    if _rederive_using_random_salt_component is not None:
        # This is a re-derivation path (or test with fixed random_salt_component)
        random_salt_component_to_use = _rederive_using_random_salt_component
        if not isinstance(random_salt_component_to_use, bytes) or len(random_salt_component_to_use) != 16:
            raise ValueError("_rederive_using_random_salt_component must be 16 bytes.")

        if _rederive_using_factors_hash is not None:
            # True re-derivation of the original key: use the stored factors_hash
            factors_hash_to_use = _rederive_using_factors_hash
            if not isinstance(factors_hash_to_use, bytes) or len(factors_hash_to_use) != 32:
                raise ValueError("_rederive_using_factors_hash must be 32 bytes.")
            # print("DEBUG KDF: Re-deriving with STORED factors_hash and STORED random_salt_component.")
        else:
            # Re-deriving using the STORED random_salt_component BUT 
            # re-calculating factors_hash from the NEWLY PROVIDED additional_inputs.
            # This is the path for test_03f.
            concatenated_new_inputs = b''.join(actual_additional_inputs_for_hash)
            factors_hash_to_use = hashlib.sha256(concatenated_new_inputs).digest()
            # print(f"DEBUG KDF: Re-deriving with NEW factors_hash (from current additional_inputs) and STORED random_salt_component. New factors_hash: {factors_hash_to_use.hex()}")
    else:
        # Initial derivation path
        if _rederive_using_factors_hash is not None: # This combination makes no sense
            raise ValueError("Cannot provide _rederive_using_factors_hash for initial derivation if _rederive_using_random_salt_component is not also provided.")
        
        concatenated_initial_inputs = b''.join(actual_additional_inputs_for_hash)
        factors_hash_to_use = hashlib.sha256(concatenated_initial_inputs).digest()
        
        if ENTROPY_MANAGER_INSTANCE:
            random_salt_component_to_use = ENTROPY_MANAGER_INSTANCE.get_entropy(16)
            if len(random_salt_component_to_use) != 16: 
                # print(f"Warning KDF: EntropyManager provided {len(random_salt_component_to_use)} bytes for salt. Padding/regenerating.")
                random_salt_component_to_use = (random_salt_component_to_use + os.urandom(16))[:16]
        else:
            random_salt_component_to_use = os.urandom(16)
        # print(f"DEBUG KDF: Initial derivation. Factors_hash: {factors_hash_to_use.hex()}, Random_salt: {random_salt_component_to_use.hex()}")
    
    combined_salt_for_kdf = factors_hash_to_use + random_salt_component_to_use

    key: bytes
    if method == "Argon2id":
        try:
            key = low_level.hash_secret_raw(secret=password, salt=combined_salt_for_kdf, time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST_KB, parallelism=ARGON2_PARALLELISM, hash_len=ARGON2_HASH_LEN, type=ARGON2_TYPE)
        except Argon2Error as e: raise RuntimeError(f"Argon2id key derivation failed: {e}") from e
    elif method == "PBKDF2":
        try:
            kdf = PBKDF2HMAC(algorithm=PBKDF2_HASH_ALG, length=PBKDF2_KEY_LEN, salt=combined_salt_for_kdf, iterations=PBKDF2_ITERATIONS, backend=default_backend())
            key = kdf.derive(password)
        except Exception as e: raise RuntimeError(f"PBKDF2 key derivation failed: {e}")
    else: raise ValueError(f"Unsupported KDF method: {method}")

    return key, factors_hash_to_use, random_salt_component_to_use