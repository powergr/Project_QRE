# hybrid_cipher_project/epic3_entropy_anchoring/key_generator_anchored.py
"""
Key generation functions that incorporate entropy anchoring.
Uses an EntropyManager to fetch chaotic entropy (with PRNG fallback)
to enhance salts or input keying material for KDFs.
"""
import os
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from .secure_prng import EntropyManager
    from .entropy_extractor import DEFAULT_SOLAR_FLARES_FILE # For __main__ example path
except ImportError:
    print("Warning: Relative import failed in key_generator_anchored.py. Using direct.")
    from secure_prng import EntropyManager 
    from entropy_extractor import DEFAULT_SOLAR_FLARES_FILE


DEFAULT_KEY_LENGTH_BYTES = 32
PBKDF2_DEFAULT_ITERATIONS = 310000 
PBKDF2_DEFAULT_HASH = crypto_hashes.SHA256()
HKDF_DEFAULT_HASH = crypto_hashes.SHA256()

def generate_key_pbkdf2_anchored(
    password: bytes,
    salt: bytes | None = None,
    length: int = DEFAULT_KEY_LENGTH_BYTES,
    iterations: int = PBKDF2_DEFAULT_ITERATIONS,
    hash_algorithm = PBKDF2_DEFAULT_HASH,
    # Added for explicit path control if needed by EntropyManager
    chaotic_data_path_for_em: str | None = None 
    ) -> bytes:
    if not isinstance(password, bytes):
        raise TypeError("Password must be bytes.")
    if salt is not None and (not isinstance(salt, bytes) or len(salt) != 16):
        raise ValueError("User-provided salt must be a 16-byte string if specified.")
    
    entropy_mgr = EntropyManager(chaotic_data_file_path=chaotic_data_path_for_em)
    base_salt = salt if salt is not None else os.urandom(16)
    anchoring_entropy_for_salt = entropy_mgr.get_entropy(16) 
    
    if len(base_salt) != len(anchoring_entropy_for_salt):
        # This case should ideally not be hit if get_entropy(16) always returns 16 or fails.
        # If get_entropy returns less (e.g. from a short chaotic digest), XORing would be an issue.
        # For robustness, ensure anchoring_entropy_for_salt is 16 bytes, pad if necessary, or error.
        # Current EntropyManager.get_entropy for chaotic data will return min(num_bytes, len(digest))
        # If chaotic digest is 32 and we ask for 16, we get 16. OK.
        # If it fell back to PRNG, generate_bytes(16) gives 16. OK.
        raise ValueError(f"Salt components for XORing have mismatched lengths: "
                         f"base_salt={len(base_salt)}, anchor_salt={len(anchoring_entropy_for_salt)}")
                         
    combined_salt = bytes(s_byte ^ e_byte for s_byte, e_byte in zip(base_salt, anchoring_entropy_for_salt))
    
    kdf = PBKDF2HMAC(
        algorithm=hash_algorithm,
        length=length,
        salt=combined_salt,
        iterations=iterations
    )
    return kdf.derive(password)

def generate_key_hkdf_anchored(
    input_key_material: bytes,
    salt: bytes | None = None, 
    info_context: bytes = b"", 
    length: int = DEFAULT_KEY_LENGTH_BYTES,
    hash_algorithm = HKDF_DEFAULT_HASH,
    chaotic_data_path_for_em: str | None = None
    ) -> bytes:
    if not isinstance(input_key_material, bytes):
        raise TypeError("Input key material must be bytes.")
    if salt is not None and not isinstance(salt, bytes):
        raise TypeError("HKDF salt must be bytes if provided.")
    if not isinstance(info_context, bytes):
        raise TypeError("HKDF info_context must be bytes.")

    entropy_mgr = EntropyManager(chaotic_data_file_path=chaotic_data_path_for_em)
    anchoring_entropy_for_ikm = entropy_mgr.get_entropy(32) 
    combined_ikm = input_key_material + anchoring_entropy_for_ikm
    
    hkdf_salt = salt if salt is not None else os.urandom(hash_algorithm.digest_size)

    hkdf = HKDF(
        algorithm=hash_algorithm,
        length=length,
        salt=hkdf_salt, 
        info=info_context
    )
    return hkdf.derive(combined_ikm)

if __name__ == '__main__':
    print("\n--- Anchored Key Generator Demonstration ---")
    
    # Determine path to data file for the __main__ demo
    # Assumes solar_flares_data.json is in the same dir as entropy_extractor.py
    # which is also the same dir (epic3_entropy_anchoring) as this script.
    try:
        import epic3_entropy_anchoring.entropy_extractor as ee_module_main_kg
        extractor_module_dir_main_kg = os.path.dirname(os.path.abspath(ee_module_main_kg.__file__))
        demo_chaotic_file_path_kg = os.path.join(extractor_module_dir_main_kg, DEFAULT_SOLAR_FLARES_FILE)
    except Exception:
        demo_chaotic_file_path_kg = None # Will use EntropyManager's default logic

    print("\nTesting PBKDF2 Anchored Key Generation:")
    password_pbkdf2 = b"SuperSecretPassword123"
    user_salt_pbkdf2 = os.urandom(16)

    key1_pbkdf2, key2_pbkdf2 = None, None
    try:
        print("Generating key with user-provided salt component...")
        key1_pbkdf2 = generate_key_pbkdf2_anchored(
            password_pbkdf2, salt=user_salt_pbkdf2, chaotic_data_path_for_em=demo_chaotic_file_path_kg
        )
        print(f"PBKDF2 Key 1 (user salt): {key1_pbkdf2.hex()}")

        print("Generating key with auto-generated salt component...")
        key2_pbkdf2 = generate_key_pbkdf2_anchored(
            password_pbkdf2, chaotic_data_path_for_em=demo_chaotic_file_path_kg
        )
        print(f"PBKDF2 Key 2 (auto salt): {key2_pbkdf2.hex()}")
        
        if key1_pbkdf2 is not None and key2_pbkdf2 is not None:
            assert key1_pbkdf2 != key2_pbkdf2, \
                "PBKDF2 keys with different salt enhancements should generally differ."
    except Exception as e:
        print(f"Error during PBKDF2 demo: {e}")


    print("\nTesting HKDF Anchored Key Generation:")
    initial_material_hkdf = os.urandom(32)
    user_salt_hkdf = os.urandom(HKDF_DEFAULT_HASH.digest_size)
    app_info_hkdf = b"com.example.my_app_encryption_key_v1"
    key1_hkdf, key2_hkdf = None, None
    try:
        print("Generating HKDF key with user-provided salt...")
        key1_hkdf = generate_key_hkdf_anchored(
            initial_material_hkdf, salt=user_salt_hkdf, info_context=app_info_hkdf,
            chaotic_data_path_for_em=demo_chaotic_file_path_kg
        )
        print(f"HKDF Key 1 (user salt): {key1_hkdf.hex()}")

        print("Generating HKDF key with auto-generated salt for HKDF (if salt=None)...")
        key2_hkdf = generate_key_hkdf_anchored(
            initial_material_hkdf, info_context=app_info_hkdf,
            chaotic_data_path_for_em=demo_chaotic_file_path_kg
        )
        print(f"HKDF Key 2 (auto HKDF salt): {key2_hkdf.hex()}")
        
        if key1_hkdf is not None and key2_hkdf is not None:
            assert key1_hkdf != key2_hkdf, \
                "HKDF keys with different HKDF salts should generally differ."
    except Exception as e:
        print(f"Error during HKDF demo: {e}")

    print("\nDemonstration complete.")