import os
import hashlib # For SHA-256 of additional_inputs
from typing import List, Tuple, Union # Union for potential type hint refinements

# Argon2 imports
from argon2 import low_level
from argon2.exceptions import Argon2Error # For specific Argon2 error handling

# Cryptography library imports for PBKDF2
from cryptography.hazmat.primitives import hashes as crypto_hashes # Alias to avoid confusion
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend # Often needed, good practice

# In key_derivation.py

# Define KDF parameters as suggested or as module constants for clarity
ARGON2_TIME_COST = 4
ARGON2_MEMORY_COST_KB = 32768  # 32MB as per ticket (argon2-cffi takes KiB)
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32 # For AES-256 key
ARGON2_TYPE = low_level.Type.ID # For Argon2id

PBKDF2_ITERATIONS = 100000 # As per ticket, make this configurable if needed later
PBKDF2_HASH_ALG = crypto_hashes.SHA256()
PBKDF2_KEY_LEN = 32 # For AES-256 key

def derive_key(
    password: bytes,
    additional_inputs: List[bytes],
    method: str = "Argon2id",
    # The following parameter is added for testing re-derivation with a known salt.
    # For normal operation, a new random_salt is always generated.
    _test_fixed_random_salt: Union[bytes, None] = None
) -> Tuple[bytes, bytes]:
    """
    Derives a 32-byte cryptographic key from a password and additional inputs
    using the specified Key Derivation Function (KDF) method.

    Args:
        password: The primary secret (e.g., user-provided password) as bytes.
        additional_inputs: A list of byte strings representing other factors
                           (e.g., biometrics, environmental data).
        method: The KDF method to use. Supported: "Argon2id", "PBKDF2".
                Defaults to "Argon2id".
        _test_fixed_random_salt: Optional. If provided, this salt is used instead of
                                 generating a new random one. Primarily for testing consistency.

    Returns:
        A tuple containing:
            - key (bytes): The derived 32-byte key.
            - random_salt (bytes): The 16-byte random salt component that was generated
                                   (or the _test_fixed_random_salt if it was provided).
                                   This needs to be stored alongside the ciphertext.

    Raises:
        ValueError: If inputs are invalid (e.g., not bytes, unsupported method).
        RuntimeError: If the underlying KDF operation fails.
    """
    if not isinstance(password, bytes):
        raise ValueError("Password must be bytes.")
    if not isinstance(additional_inputs, list) or \
       not all(isinstance(inp, bytes) for inp in additional_inputs):
        raise ValueError("All additional_inputs must be a list of byte strings.")
    if method not in ["Argon2id", "PBKDF2"]:
        raise ValueError(f"Unsupported KDF method: {method}. Choose 'Argon2id' or 'PBKDF2'.")

    # 1. Input Processing: Concatenate and hash additional_inputs
    #    If additional_inputs is empty, b''.join results in b''
    concatenated_additional_inputs = b''.join(additional_inputs)
    factors_hash = hashlib.sha256(concatenated_additional_inputs).digest() # 32-byte hash

    # 2. Salt Generation
    if _test_fixed_random_salt is not None:
        if not isinstance(_test_fixed_random_salt, bytes) or len(_test_fixed_random_salt) != 16:
            raise ValueError("_test_fixed_random_salt must be a 16-byte string if provided.")
        random_salt_component = _test_fixed_random_salt
    else:
        random_salt_component = os.urandom(16) # 16-byte random salt

    # The "combined_salt" is what the KDF algorithm will actually use.
    # It incorporates variability from additional factors and a random per-derivation salt.
    combined_salt_for_kdf = factors_hash + random_salt_component # 32 + 16 = 48 bytes

    # 3. KDF Execution
    key: bytes
    if method == "Argon2id":
        try:
            key = low_level.hash_secret_raw(
                secret=password,
                salt=combined_salt_for_kdf,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST_KB,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
                type=ARGON2_TYPE
            )
        except Argon2Error as e:
            # Log detailed error if necessary: print(f"Argon2 internal error: {e.error_code}")
            raise RuntimeError("Argon2id key derivation failed.") from e
        except Exception as e: # Catch other potential low_level call errors
            raise RuntimeError(f"An unexpected error occurred during Argon2id derivation: {e}")
    
    elif method == "PBKDF2": # Default to PBKDF2 if not Argon2id (already validated)
        try:
            kdf = PBKDF2HMAC(
                algorithm=PBKDF2_HASH_ALG,
                length=PBKDF2_KEY_LEN,
                salt=combined_salt_for_kdf,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend() # Good practice to specify backend
            )
            key = kdf.derive(password)
        except Exception as e: # Catch potential errors from PBKDF2HMAC
            raise RuntimeError(f"PBKDF2 key derivation failed: {e}")
    else:
        # This case should not be reached due to the initial method check,
        # but as a safeguard:
        raise ValueError(f"Internal error: KDF method '{method}' not handled.")

    # 4. Output: Return the derived key and the random_salt component.
    # The random_salt_component is what needs to be stored with the ciphertext.
    return key, random_salt_component