# parallel_encryption_vault.py (Updated with concurrency)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
import oqs
import os
import uuid
from concurrent.futures import ThreadPoolExecutor # For concurrency

from key_vault_manager import store_keys, get_keys # Import from our new module

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

def parallel_encrypt_vault(plaintext: bytes) -> bytes:
    """
    Modified parallel encryption: encrypts with AES(K1) and AES(KEM-derived K2)
    concurrently, stores K1 and KEM private key in Vault, 
    and prepends a key_id to ciphertext.
    """
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes.")

    key_id = uuid.uuid4().bytes

    # --- Key Generation (done sequentially before threading) ---
    K1 = os.urandom(32)
    iv1 = os.urandom(16)

    kem_alice = oqs.KeyEncapsulation(KEM_ALGORITHM_PARALLEL)
    alice_public_key = kem_alice.generate_keypair()
    alice_private_key_bytes = kem_alice.export_secret_key()

    encapsulator_kem = oqs.KeyEncapsulation(KEM_ALGORITHM_PARALLEL)
    EK, SS = encapsulator_kem.encap_secret(alice_public_key)
    
    if len(SS) != 32:
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
        # Submit both AES encryption tasks
        future_c1 = executor.submit(_aes_encrypt_worker, plaintext, K1, iv1)
        future_c2 = executor.submit(_aes_encrypt_worker, plaintext, K2, iv2)
        
        # Retrieve results
        # This will block until each future completes
        C1 = future_c1.result()
        C2 = future_c2.result()
    
    # --- Store keys in Vault (after crypto ops) ---
    keys_to_store = {'K1': K1, 'Kyber_SK': alice_private_key_bytes}
    try:
        store_keys(key_id, keys_to_store)
    except Exception as e:
        raise RuntimeError(f"Failed to store keys in Vault for parallel encryption: {e}")

    # --- Combine Ciphertext ---
    len_C1_bytes = len(C1).to_bytes(4, "big")
    len_EK_bytes = len(EK).to_bytes(4, "big")
    len_C2_bytes = len(C2).to_bytes(4, "big")

    return (key_id + 
            len_C1_bytes + C1 +
            len_EK_bytes + EK +
            len_C2_bytes + C2)

# parallel_decrypt_vault function remains the same as before
# (no concurrency needed for decryption in this scheme as it chooses one path)
def parallel_decrypt_vault(ciphertext: bytes) -> bytes:
    """
    Decrypts parallel encryption ciphertext using keys retrieved from Vault.
    For PoC, this will attempt to decrypt C1.
    """
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16: # Must have at least key_id
        raise ValueError("Ciphertext must be bytes and include at least a 16-byte key_id.")

    key_id = ciphertext[:16]
    actual_ciphertext_data = ciphertext[16:] 

    try:
        retrieved_keys = get_keys(key_id)
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve keys from Vault for parallel decryption: {e}")

    K1 = retrieved_keys.get('K1')
    Kyber_SK = retrieved_keys.get('Kyber_SK') # Retrieve for potential C2 decryption path test

    if K1 is None: # For this PoC, we prioritize C1 based on Ticket 5 sample
        raise RuntimeError("K1 not found in retrieved keys from Vault for C1 decryption path.")

    # --- Parse C1 (and other components for completeness, even if only C1 is decrypted here) ---
    ptr = 0
    try:
        len_C1 = int.from_bytes(actual_ciphertext_data[ptr : ptr + 4], "big")
        ptr += 4
        if ptr + len_C1 > len(actual_ciphertext_data):
             raise ValueError("Malformed ciphertext: C1 length exceeds available data.")
        c1_full = actual_ciphertext_data[ptr : ptr + len_C1]
        ptr += len_C1
        
        # Although Ticket 5 sample only decrypts C1, robust parsing should account for all fields
        len_EK = int.from_bytes(actual_ciphertext_data[ptr : ptr + 4], "big")
        ptr += 4
        if ptr + len_EK > len(actual_ciphertext_data):
            raise ValueError("Malformed ciphertext: EK length exceeds available data.")
        # EK = actual_ciphertext_data[ptr : ptr + len_EK] # Not used if only C1
        ptr += len_EK

        len_C2 = int.from_bytes(actual_ciphertext_data[ptr : ptr + 4], "big")
        ptr += 4
        if ptr + len_C2 > len(actual_ciphertext_data):
            raise ValueError("Malformed ciphertext: C2 length exceeds available data.")
        # c2_full = actual_ciphertext_data[ptr : ptr + len_C2] # Not used if only C1

    except IndexError:
        raise ValueError("Malformed ciphertext: Error parsing component lengths or data after key_id.")


    # --- Decrypt C1 (as per Ticket 5 sample for parallel_decrypt) ---
    if len(c1_full) < 16: # IV is 16 bytes
        raise ValueError("Malformed ciphertext: C1 data is too short to contain an IV.")
    iv1 = c1_full[:16]
    encrypted_c1_data = c1_full[16:]

    cipher1_aes_dec = Cipher(algorithms.AES(K1), modes.CBC(iv1))
    decryptor1 = cipher1_aes_dec.decryptor()
    decrypted_padded_data1 = decryptor1.update(encrypted_c1_data) + decryptor1.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        original_plaintext = unpadder.update(decrypted_padded_data1) + unpadder.finalize()
    except ValueError as e:
        raise RuntimeError(f"Unpadding C1 failed (corrupted data or incorrect key K1?): {e}")
        
    return original_plaintext


# Main block for testing (should be updated to import oqs if not already at module level)
if __name__ == '__main__':
    print("Running inline test for parallel_encryption_vault.py (with concurrency)...")
    try:
        import oqs # Ensure oqs is imported for this block
        supported_kems = oqs.get_enabled_kem_mechanisms()
        if KEM_ALGORITHM_PARALLEL not in supported_kems:
            print(f"CRITICAL WARNING: KEM '{KEM_ALGORITHM_PARALLEL}' not enabled: {supported_kems}")
            exit(1)

        sample_plaintext = b"This is a top secret message for concurrent parallel vault encryption!"
        print(f"Encrypting: \"{sample_plaintext.decode('utf-8', 'ignore')}\"")
        
        vault_ciphertext = parallel_encrypt_vault(sample_plaintext)
        print(f"Ciphertext length (incl. key_id): {len(vault_ciphertext)}")
        print("Encryption complete, keys stored in Vault.")

        print("Decrypting (C1 path for PoC)...")
        decrypted_text = parallel_decrypt_vault(vault_ciphertext)
        print(f"Decrypted: \"{decrypted_text.decode('utf-8', 'ignore')}\"")

        assert sample_plaintext == decrypted_text, "Parallel vault decryption FAILED!"
        print("Parallel encryption/decryption (concurrent AES) with Vault PASSED!")

    except EnvironmentError as ee:
        print(f"ENVIRONMENT ERROR: {ee}")
    except ConnectionError as ce:
        print(f"VAULT CONNECTION ERROR: {ce}")
    except RuntimeError as re:
        print(f"RUNTIME ERROR: {re}")
    except ValueError as ve:
        print(f"VALUE ERROR: {ve}")
    except oqs.MechanismNotSupportedError as oqs_e:
        print(f"OQS Mechanism Not Supported ERROR: {oqs_e}")
    except Exception as e:
        print(f"An UNEXPECTED ERROR occurred: {e}")
        import traceback
        traceback.print_exc()