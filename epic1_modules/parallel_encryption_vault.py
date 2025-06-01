# epic1_modules/parallel_encryption_vault.py

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
import oqs
import os
import uuid
from concurrent.futures import ThreadPoolExecutor 
from typing import Optional, List, Dict # Added Dict

# Import from our key management and KDF module using relative imports
from .key_vault_manager import store_keys, get_keys 
from .key_derivation import derive_key 

KEM_ALGORITHM_PARALLEL = "ML-KEM-512"

# Helper function for AES encryption, to be run in a thread
def _aes_encrypt_worker(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypts plaintext using AES-256-CBC and returns IV + ciphertext."""
    cipher_aes = Cipher(algorithms.AES(key), modes.CBC(iv))
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    encryptor = cipher_aes.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def parallel_encrypt_vault(
    plaintext: bytes,
    password: Optional[bytes] = None,
    additional_kdf_inputs: Optional[List[bytes]] = None
) -> bytes:
    """
    Parallel encryption: AES(K1) and AES(KEM-derived K2).
    If password is provided, K1 is derived using KDF (anchored).
    Keys/salts are stored in Vault. A key_id is prepended to ciphertext.
    """
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes.")

    key_id = uuid.uuid4().bytes
    keys_to_store: Dict[str, bytes] = {} 

    K1: bytes
    # k1_factors_hash_for_vault: Optional[bytes] = None # Not needed as variable here
    # k1_random_salt_component_for_vault: Optional[bytes] = None # Not needed as variable here

    if password is not None:
        if not isinstance(password, bytes):
            raise ValueError("Password must be bytes for KDF.")
        
        # derive_key now uses EntropyManager internally for its random_salt_component
        derived_k1, factors_hash_used, random_salt_comp_used = derive_key(
            password, 
            additional_inputs=additional_kdf_inputs if additional_kdf_inputs else [], 
            method="Argon2id" # Or make this configurable if desired
        )
        K1 = derived_k1
        # Store KDF salt components instead of K1 itself
        keys_to_store['K1_factors_hash'] = factors_hash_used
        keys_to_store['K1_random_salt'] = random_salt_comp_used
    else:
        K1 = os.urandom(32)
        keys_to_store['K1'] = K1 # Store randomly generated K1

    iv1 = os.urandom(16)

    # --- KEM for K2 ---
    try:
        kem_alice = oqs.KeyEncapsulation(KEM_ALGORITHM_PARALLEL)
        alice_public_key = kem_alice.generate_keypair()
        alice_private_key_bytes = kem_alice.export_secret_key()
        keys_to_store['Kyber_SK'] = alice_private_key_bytes # Always store KEM SK

        encapsulator_kem = oqs.KeyEncapsulation(KEM_ALGORITHM_PARALLEL)
        EK, SS = encapsulator_kem.encap_secret(alice_public_key)
    except oqs.MechanismNotSupportedError:
        raise RuntimeError(f"KEM algorithm '{KEM_ALGORITHM_PARALLEL}' is not supported by liboqs.")
    except Exception as e:
        raise RuntimeError(f"KEM operations failed in parallel_encrypt_vault: {e}")
    
    if len(SS) != 32: # ML-KEM-512 SS should be 32 bytes
        digest_k2 = hashes.Hash(hashes.SHA256())
        digest_k2.update(SS)
        K2 = digest_k2.finalize()
    else:
        K2 = SS
    iv2 = os.urandom(16)

    # --- Concurrent AES Encryptions ---
    C1: bytes
    C2: bytes
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_c1 = executor.submit(_aes_encrypt_worker, plaintext, K1, iv1)
        future_c2 = executor.submit(_aes_encrypt_worker, plaintext, K2, iv2)
        C1 = future_c1.result()
        C2 = future_c2.result()
    
    # --- Store keys/salts in Vault ---
    try:
        store_keys(key_id, keys_to_store)
    except Exception as e:
        raise RuntimeError(f"Failed to store keys/salts in Vault for parallel encryption: {e}")

    # --- Combine Ciphertext ---
    len_C1_bytes = len(C1).to_bytes(4, "big")
    len_EK_bytes = len(EK).to_bytes(4, "big")
    len_C2_bytes = len(C2).to_bytes(4, "big")

    return (key_id + 
            len_C1_bytes + C1 +
            len_EK_bytes + EK +
            len_C2_bytes + C2)

def parallel_decrypt_vault(
    ciphertext: bytes,
    password: Optional[bytes] = None,
    additional_kdf_inputs: Optional[List[bytes]] = None # These are the inputs provided at decryption time
) -> bytes:
    """
    Decrypts parallel encryption ciphertext.
    If password provided, K1 is re-derived using KDF, provided additional_kdf_inputs, 
    and the K1_random_salt retrieved from Vault.
    Otherwise, K1 is retrieved directly from Vault. PoC decrypts C1 path.
    """
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise ValueError("Ciphertext must be bytes and include at least a 16-byte key_id.")

    key_id = ciphertext[:16]
    actual_ciphertext_data = ciphertext[16:] 

    try:
        retrieved_keys_or_salts = get_keys(key_id)
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve keys/salts from Vault: {e}")

    K1: bytes
    if password is not None: 
        if not isinstance(password, bytes):
            raise ValueError("Password must be bytes for KDF re-derivation.")
        
        # For re-derivation using KDF, we need the original random_salt_component.
        # The factors_hash is re-derived based on the additional_kdf_inputs provided NOW.
        k1_random_salt_component_from_vault = retrieved_keys_or_salts.get('K1_random_salt')
        # k1_factors_hash_from_vault = retrieved_keys_or_salts.get('K1_factors_hash') # Not used if we re-hash current inputs

        if k1_random_salt_component_from_vault is None:
            raise RuntimeError("Required KDF random_salt_component (K1_random_salt) not found in Vault for KDF path.")
        
        # Call derive_key. It will use the provided additional_kdf_inputs to compute a factors_hash,
        # and combine it with the k1_random_salt_component_from_vault.
        # We DO NOT pass _rederive_using_factors_hash here, so that derive_key uses the
        # current 'additional_kdf_inputs' to compute a potentially different factors_hash.
        # This is specifically to make test_03f work as intended.
        # For a "true" decryption where inputs are assumed correct, one might pass the stored factors_hash.
        derived_k1, _, _ = derive_key(
            password,
            additional_inputs=additional_kdf_inputs if additional_kdf_inputs else [], 
            method="Argon2id", # Must match encryption method
            _rederive_using_random_salt_component=k1_random_salt_component_from_vault
            # _rederive_using_factors_hash is OMITTED here
        )
        K1 = derived_k1
        
    else: # K1 was stored directly (randomly generated path)
        K1 = retrieved_keys_or_salts.get('K1')
        if K1 is None:
            raise RuntimeError("K1 not found in Vault (and no password provided for KDF).")

    # Kyber_SK = retrieved_keys_or_salts.get('Kyber_SK') # For C2 decryption if implemented

    # --- Parse C1 ---
    ptr = 0
    try:
        len_C1 = int.from_bytes(actual_ciphertext_data[ptr : ptr + 4], "big")
        ptr += 4
        if ptr + len_C1 > len(actual_ciphertext_data):
             raise ValueError("Malformed ciphertext: C1 length exceeds available data.")
        c1_full = actual_ciphertext_data[ptr : ptr + len_C1]
        # For this PoC, we only decrypt C1. Don't need to parse further.
    except IndexError:
        raise ValueError("Malformed ciphertext: Error parsing C1 component after key_id.")
    except Exception as e: # Catch other parsing errors like struct.error
        raise ValueError(f"Malformed ciphertext: Error parsing C1 - {e}")


    if len(c1_full) < 16: 
        raise ValueError("Malformed ciphertext: C1 data is too short to contain an IV.")
    iv1 = c1_full[:16]
    encrypted_c1_data = c1_full[16:]

    cipher1_aes_dec = Cipher(algorithms.AES(K1), modes.CBC(iv1))
    decryptor1 = cipher1_aes_dec.decryptor()
    decrypted_padded_data1 = decryptor1.update(encrypted_c1_data) + decryptor1.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        original_plaintext = unpadder.update(decrypted_padded_data1) + unpadder.finalize()
    except ValueError as e: # Specifically for unpadding errors
        raise RuntimeError(f"Unpadding C1 failed (corrupted data or incorrect key K1?): {e}")
        
    return original_plaintext


if __name__ == '__main__':
    print("Running inline test for parallel_encryption_vault.py (with KDF integration)...")
    try:
        import oqs 
        if not (os.environ.get('VAULT_ADDR') and os.environ.get('VAULT_TOKEN')):
            print("ERROR: Set VAULT_ADDR and VAULT_TOKEN env vars before running.")
            exit(1)
            
        supported_kems = oqs.get_enabled_kem_mechanisms()
        if KEM_ALGORITHM_PARALLEL not in supported_kems:
            print(f"CRITICAL WARNING: KEM '{KEM_ALGORITHM_PARALLEL}' not enabled: {supported_kems}")
            exit(1)

        sample_plaintext = b"Test message for KDF-enhanced parallel vault encryption!"
        test_password = b"mySecurePasswordForK1"
        test_add_inputs = [b"factor1_data", b"factor2_env"]
        
        print(f"\nEncrypting with KDF-derived K1: \"{sample_plaintext.decode('utf-8', 'ignore')}\"")
        vault_ciphertext_kdf = parallel_encrypt_vault(
            sample_plaintext, 
            password=test_password, 
            additional_kdf_inputs=test_add_inputs
        )
        print(f"Ciphertext length (KDF K1): {len(vault_ciphertext_kdf)}")
        print("Encryption complete, K1 salt components & KEM SK stored in Vault.")

        print("Decrypting with KDF-derived K1 (correct inputs)...")
        decrypted_text_kdf = parallel_decrypt_vault(
            vault_ciphertext_kdf, 
            password=test_password, 
            additional_kdf_inputs=test_add_inputs
        )
        print(f"Decrypted (KDF K1): \"{decrypted_text_kdf.decode('utf-8', 'ignore')}\"")
        assert sample_plaintext == decrypted_text_kdf, "Parallel KDF decryption FAILED!"
        print("Parallel KDF encryption/decryption PASSED!")

        # Test with wrong additional inputs
        print("\nDecrypting with KDF-derived K1 (WRONG additional inputs)...")
        wrong_add_inputs = [b"wrong_factor"]
        try:
            decrypted_wrong = parallel_decrypt_vault(
                vault_ciphertext_kdf,
                password=test_password,
                additional_kdf_inputs=wrong_add_inputs
            )
            if decrypted_wrong == sample_plaintext:
                print("ERROR: Decryption with WRONG additional inputs produced ORIGINAL plaintext!")
            else:
                print(f"Decryption with WRONG additional inputs produced DIFFERENT plaintext (expected): {decrypted_wrong.decode('utf-8','ignore')}")
        except RuntimeError as e:
            print(f"Decryption with WRONG additional inputs FAILED as expected: {e}")


        print(f"\nEncrypting with randomly generated K1: \"{sample_plaintext.decode('utf-8', 'ignore')}\"")
        vault_ciphertext_random = parallel_encrypt_vault(sample_plaintext) 
        print(f"Ciphertext length (Random K1): {len(vault_ciphertext_random)}")
        print("Encryption complete, random K1 & KEM SK stored in Vault.")

        print("Decrypting with random K1...")
        decrypted_text_random = parallel_decrypt_vault(vault_ciphertext_random) 
        print(f"Decrypted (Random K1): \"{decrypted_text_random.decode('utf-8', 'ignore')}\"")
        assert sample_plaintext == decrypted_text_random, "Parallel Random K1 decryption FAILED!"
        print("Parallel Random K1 encryption/decryption PASSED!")


    except EnvironmentError as ee: print(f"ENVIRONMENT ERROR: {ee}")
    except ConnectionError as ce: print(f"VAULT CONNECTION ERROR: {ce}")
    except RuntimeError as re: print(f"RUNTIME ERROR: {re}")
    except ValueError as ve: print(f"VALUE ERROR: {ve}")
    except oqs.MechanismNotSupportedError as oqs_e: print(f"OQS Mechanism Not Supported ERROR: {oqs_e}")
    except Exception as e:
        print(f"An UNEXPECTED ERROR occurred: {e}")
        import traceback
        traceback.print_exc()