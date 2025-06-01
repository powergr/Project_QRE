# system_core_logic.py (New File or part of main_unified_poc.py)

import os
from typing import List, Optional, Tuple

# Epic 1 imports
from epic1_modules.parallel_encryption_vault import parallel_encrypt_vault, parallel_decrypt_vault
from epic1_modules.layered_encryption_vault import layered_encrypt_vault, layered_decrypt_vault
# from epic1_modules.key_derivation import derive_key # Not directly called by these wrappers

# Epic 2 imports
from epic2_qne.cipher_engine import (
    generate_aes_gcm_key, 
    encrypt_with_optional_aad, 
    decrypt_with_optional_aad,
    # Import constants if needed for parsing the QNE layer's output directly
    AAD_LEN_FIELD_BYTES,
    GCM_NONCE_SIZE_BYTES
)
from epic2_qne.entropy_pool import EntropyPool # For type hinting, pool passed in
from epic2_qne.qrng import SoftwareSimulatedQRNG # For creating a default pool if needed

# --- Constants for this wrapper layer ---
QNE_AAD_REQUEST_LENGTH = 32 # How much entropy to request for AAD

# --- Helper for QNE AES-GCM Key ---
# For this PoC integration, the QNE layer's AES key will be generated and returned.
# In a production system, this key would need robust management (Vault, KDF, etc.)

def encrypt_layered_with_qne(
    plaintext: bytes, 
    qne_pool: EntropyPool
) -> Tuple[bytes, bytes]: # Returns final_ciphertext, qne_aes_gcm_key_for_poc
    """
    Step 1: Encrypts with Epic 1's Layered scheme (KEM SK stored in Vault).
    Step 2: Encrypts the result with Epic 2's QNE-infused AES-GCM.
    Returns the final ciphertext and the transient AES-GCM key used for the QNE layer (for PoC).
    """
    print("  Phase 1: Performing Epic 1 Layered Encryption...")
    epic1_ciphertext = layered_encrypt_vault(plaintext)
    # epic1_ciphertext format is: epic1_key_id | len_EK | EK | IV | encrypted_data
    print(f"  Phase 1: Epic 1 Layered Ciphertext length: {len(epic1_ciphertext)}")

    print("  Phase 2: Applying Epic 2 QNE Infusion Layer...")
    qne_aes_gcm_key = generate_aes_gcm_key()
    qne_aad_data = qne_pool.get_entropy(QNE_AAD_REQUEST_LENGTH)

    if qne_aad_data:
        print(f"    Using QNE AAD ({len(qne_aad_data)} bytes): {qne_aad_data.hex()[:16]}...")
    else:
        print("    Warning: Could not get AAD from QNE pool. Proceeding without AAD for QNE layer.")
        qne_aad_data = None # encrypt_with_optional_aad handles None as no AAD

    # The "plaintext" for the QNE layer is the entire ciphertext from Epic 1
    final_ciphertext_payload = encrypt_with_optional_aad(
        qne_aes_gcm_key, 
        epic1_ciphertext, # Epic 1's output is the data for Epic 2's engine
        qne_aad_data
    )
    # final_ciphertext_payload format: [qne_aad_len] | [qne_aad_data] | qne_nonce | qne_encrypted_epic1_ct
    print(f"  Phase 2: QNE layer added. Final Ciphertext length: {len(final_ciphertext_payload)}")
    
    return final_ciphertext_payload, qne_aes_gcm_key


def decrypt_layered_with_qne(
    final_ciphertext_payload: bytes, 
    qne_aes_gcm_key: bytes # Passed in for PoC
) -> bytes:
    """
    Step 1: Decrypts Epic 2's QNE-infused AES-GCM layer.
    Step 2: Decrypts the inner Epic 1 Layered scheme ciphertext (KEM SK from Vault).
    """
    print("  Phase 1: Decrypting Epic 2 QNE Infusion Layer...")
    # The payload for decrypt_with_optional_aad is final_ciphertext_payload
    epic1_ciphertext = decrypt_with_optional_aad(qne_aes_gcm_key, final_ciphertext_payload)

    if epic1_ciphertext is None:
        raise RuntimeError("QNE Layer Decryption Failed (InvalidTag or malformed QNE payload).")
    print(f"  Phase 1: QNE layer decrypted. Inner Epic 1 Ciphertext length: {len(epic1_ciphertext)}")

    print("  Phase 2: Performing Epic 1 Layered Decryption...")
    original_plaintext = layered_decrypt_vault(epic1_ciphertext)
    print("  Phase 2: Epic 1 Layered Decryption complete.")
    return original_plaintext


def encrypt_parallel_kdf_with_qne(
    plaintext: bytes,
    password: bytes,
    additional_kdf_inputs: List[bytes],
    qne_pool: EntropyPool
) -> Tuple[bytes, bytes]: # Returns final_ciphertext, qne_aes_gcm_key_for_poc
    """
    Step 1: Encrypts with Epic 1's Parallel scheme (K1 via KDF, K2 via KEM; keys/salts in Vault).
    Step 2: Encrypts the result with Epic 2's QNE-infused AES-GCM.
    """
    print("  Phase 1: Performing Epic 1 Parallel Encryption (KDF for K1)...")
    epic1_ciphertext = parallel_encrypt_vault(
        plaintext, 
        password=password, 
        additional_kdf_inputs=additional_kdf_inputs
    )
    print(f"  Phase 1: Epic 1 Parallel Ciphertext length: {len(epic1_ciphertext)}")

    print("  Phase 2: Applying Epic 2 QNE Infusion Layer...")
    qne_aes_gcm_key = generate_aes_gcm_key()
    qne_aad_data = qne_pool.get_entropy(QNE_AAD_REQUEST_LENGTH)

    if qne_aad_data:
        print(f"    Using QNE AAD ({len(qne_aad_data)} bytes): {qne_aad_data.hex()[:16]}...")
    else:
        print("    Warning: Could not get AAD from QNE pool. Proceeding without AAD for QNE layer.")
        qne_aad_data = None
    
    final_ciphertext_payload = encrypt_with_optional_aad(
        qne_aes_gcm_key,
        epic1_ciphertext,
        qne_aad_data
    )
    print(f"  Phase 2: QNE layer added. Final Ciphertext length: {len(final_ciphertext_payload)}")

    return final_ciphertext_payload, qne_aes_gcm_key


def decrypt_parallel_kdf_with_qne(
    final_ciphertext_payload: bytes,
    password: bytes,
    additional_kdf_inputs: List[bytes],
    qne_aes_gcm_key: bytes # Passed in for PoC
) -> bytes:
    """
    Step 1: Decrypts Epic 2's QNE-infused AES-GCM layer.
    Step 2: Decrypts the inner Epic 1 Parallel scheme ciphertext (K1 via KDF, keys/salts from Vault).
    """
    print("  Phase 1: Decrypting Epic 2 QNE Infusion Layer...")
    epic1_ciphertext = decrypt_with_optional_aad(qne_aes_gcm_key, final_ciphertext_payload)

    if epic1_ciphertext is None:
        raise RuntimeError("QNE Layer Decryption Failed (InvalidTag or malformed QNE payload).")
    print(f"  Phase 1: QNE layer decrypted. Inner Epic 1 Ciphertext length: {len(epic1_ciphertext)}")

    print("  Phase 2: Performing Epic 1 Parallel Decryption (KDF for K1)...")
    original_plaintext = parallel_decrypt_vault(
        epic1_ciphertext,
        password=password,
        additional_kdf_inputs=additional_kdf_inputs
    )
    print("  Phase 2: Epic 1 Parallel Decryption complete.")
    return original_plaintext

# You can add similar wrappers for parallel_encrypt_vault with *random K1* if needed.