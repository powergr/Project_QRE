# main_unified_poc.py (Updated)

import os
import time # For QNE pool
from typing import List, Optional, Tuple

# --- Ensure correct modules are imported based on project structure ---
try:
    # Epic 1 direct use (for scenarios without QNE layer)
    from epic1_modules.parallel_encryption_vault import parallel_encrypt_vault, parallel_decrypt_vault
    from epic1_modules.layered_encryption_vault import layered_encrypt_vault, layered_decrypt_vault
    from epic1_modules.key_vault_manager import VAULT_ADDR_ENV, VAULT_TOKEN_ENV 
    
    # Epic 2 components for QNE
    from epic2_qne.entropy_pool import EntropyPool
    from epic2_qne.qrng import SoftwareSimulatedQRNG # Or your preferred QRNG

    # New System Core Logic with QNE integration
    # Assuming system_core_logic.py is at the project root or this file is moved
    # If system_core_logic.py is created, import from it:
    # from system_core_logic import (
    #     encrypt_layered_with_qne, decrypt_layered_with_qne,
    #     encrypt_parallel_kdf_with_qne, decrypt_parallel_kdf_with_qne
    # )
    # For now, I'll copy the wrapper functions directly into this main demo for simplicity
    # to avoid creating another file just for this step. You can move them later.

    # --- Copied Wrapper Functions (Ideally these are in system_core_logic.py) ---
    from epic2_qne.cipher_engine import generate_aes_gcm_key, encrypt_with_optional_aad, decrypt_with_optional_aad
    QNE_AAD_REQUEST_LENGTH = 32

    def encrypt_layered_with_qne(plaintext: bytes, qne_pool: EntropyPool) -> Tuple[bytes, bytes]:
        print("  Phase 1: Performing Epic 1 Layered Encryption...")
        epic1_ciphertext = layered_encrypt_vault(plaintext)
        print(f"  Phase 1: Epic 1 Layered Ciphertext length: {len(epic1_ciphertext)}")
        print("  Phase 2: Applying Epic 2 QNE Infusion Layer...")
        qne_aes_gcm_key = generate_aes_gcm_key()
        qne_aad_data = qne_pool.get_entropy(QNE_AAD_REQUEST_LENGTH)
        if qne_aad_data: print(f"    Using QNE AAD ({len(qne_aad_data)} bytes): {qne_aad_data.hex()[:16]}...")
        else: print("    Warning: Could not get AAD from QNE pool."); qne_aad_data = None
        final_ciphertext_payload = encrypt_with_optional_aad(qne_aes_gcm_key, epic1_ciphertext, qne_aad_data)
        print(f"  Phase 2: QNE layer added. Final Ciphertext length: {len(final_ciphertext_payload)}")
        return final_ciphertext_payload, qne_aes_gcm_key

    def decrypt_layered_with_qne(final_ciphertext_payload: bytes, qne_aes_gcm_key: bytes) -> bytes:
        print("  Phase 1: Decrypting Epic 2 QNE Infusion Layer...")
        epic1_ciphertext = decrypt_with_optional_aad(qne_aes_gcm_key, final_ciphertext_payload)
        if epic1_ciphertext is None: raise RuntimeError("QNE Layer Decryption Failed.")
        print(f"  Phase 1: QNE layer decrypted. Inner Epic 1 Ciphertext length: {len(epic1_ciphertext)}")
        print("  Phase 2: Performing Epic 1 Layered Decryption...")
        original_plaintext = layered_decrypt_vault(epic1_ciphertext)
        print("  Phase 2: Epic 1 Layered Decryption complete.")
        return original_plaintext

    def encrypt_parallel_kdf_with_qne(plaintext: bytes, password: bytes, additional_kdf_inputs: List[bytes], qne_pool: EntropyPool) -> Tuple[bytes, bytes]:
        print("  Phase 1: Performing Epic 1 Parallel Encryption (KDF for K1)...")
        epic1_ciphertext = parallel_encrypt_vault(plaintext, password=password, additional_kdf_inputs=additional_kdf_inputs)
        print(f"  Phase 1: Epic 1 Parallel Ciphertext length: {len(epic1_ciphertext)}")
        print("  Phase 2: Applying Epic 2 QNE Infusion Layer...")
        qne_aes_gcm_key = generate_aes_gcm_key()
        qne_aad_data = qne_pool.get_entropy(QNE_AAD_REQUEST_LENGTH)
        if qne_aad_data: print(f"    Using QNE AAD ({len(qne_aad_data)} bytes): {qne_aad_data.hex()[:16]}...")
        else: print("    Warning: Could not get AAD from QNE pool."); qne_aad_data = None
        final_ciphertext_payload = encrypt_with_optional_aad(qne_aes_gcm_key, epic1_ciphertext, qne_aad_data)
        print(f"  Phase 2: QNE layer added. Final Ciphertext length: {len(final_ciphertext_payload)}")
        return final_ciphertext_payload, qne_aes_gcm_key

    def decrypt_parallel_kdf_with_qne(final_ciphertext_payload: bytes, password: bytes, additional_kdf_inputs: List[bytes], qne_aes_gcm_key: bytes) -> bytes:
        print("  Phase 1: Decrypting Epic 2 QNE Infusion Layer...")
        epic1_ciphertext = decrypt_with_optional_aad(qne_aes_gcm_key, final_ciphertext_payload)
        if epic1_ciphertext is None: raise RuntimeError("QNE Layer Decryption Failed.")
        print(f"  Phase 1: QNE layer decrypted. Inner Epic 1 Ciphertext length: {len(epic1_ciphertext)}")
        print("  Phase 2: Performing Epic 1 Parallel Decryption (KDF for K1)...")
        original_plaintext = parallel_decrypt_vault(epic1_ciphertext, password=password, additional_kdf_inputs=additional_kdf_inputs)
        print("  Phase 2: Epic 1 Parallel Decryption complete.")
        return original_plaintext
    # --- End Copied Wrapper Functions ---

except ImportError as e:
    print(f"ImportError in main_unified_poc.py: {e}. Please check paths and __init__.py files.")
    exit(1)

def check_vault_configured_for_demo():
    if not (os.environ.get(VAULT_ADDR_ENV) and os.environ.get(VAULT_TOKEN_ENV)):
        print("! VAULT ENVIRONMENT VARIABLES NOT SET !"); return False
    return True

def run_unified_poc_demo():
    print("=" * 60); print(" Unified PoC: Epic 1 (Anchored KDF, Vault) + Epic 2 (QNE)"); print("=" * 60)
    if not check_vault_configured_for_demo(): return

    sample_plaintext = b"Unified PoC: End-to-end test with all epics!"
    user_password = b"KDF_P@sswOrd_Unified!"
    additional_factors = [b"factor_unified_A", b"factor_unified_B"]
    print(f"\nOriginal Plaintext: \"{sample_plaintext.decode('utf-8', 'ignore')}\"")

    # Initialize QNE Pool for the demo
    qne_source_for_demo = SoftwareSimulatedQRNG() # Or MockQRNG for predictable AAD
    with EntropyPool(qrng_instance=qne_source_for_demo, max_size_bytes=64, refresh_interval_sec=1.5) as demo_qne_pool:
        print("[Setup] QNE Entropy Pool active for demo. Allowing initial fill...")
        time.sleep(0.2) # Brief pause for pool

        # --- Test Scenario: Layered Encryption followed by QNE Infusion ---
        print("\n--- Test 1: Layered Encryption (Epic 1) + QNE Infusion (Epic 2) ---")
        try:
            print("Encrypting...")
            final_ct_layered_qne, qne_key_layered = encrypt_layered_with_qne(sample_plaintext, demo_qne_pool)
            print(f"  Final Layered+QNE Ciphertext (sample last 32B): ...{final_ct_layered_qne[-32:].hex()}")
            
            print("Decrypting...")
            decrypted_pt_layered_qne = decrypt_layered_with_qne(final_ct_layered_qne, qne_key_layered)
            assert decrypted_pt_layered_qne == sample_plaintext
            print(f"  SUCCESS: Layered+QNE Decryption. Plaintext: \"{decrypted_pt_layered_qne.decode('utf-8', 'ignore')}\"")
        except Exception as e:
            print(f"  ERROR in Layered+QNE Test: {e}")
            import traceback; traceback.print_exc()

        # --- Test Scenario: Parallel Encryption (KDF K1) followed by QNE Infusion ---
        print("\n--- Test 2: Parallel Encryption (KDF K1, Epic 1) + QNE Infusion (Epic 2) ---")
        try:
            print(f"Encrypting (Password: '{user_password.decode()}', Factors: {[f.decode() for f in additional_factors]})...")
            final_ct_parallel_qne, qne_key_parallel = encrypt_parallel_kdf_with_qne(
                sample_plaintext, user_password, additional_factors, demo_qne_pool
            )
            print(f"  Final Parallel(KDF)+QNE Ciphertext (sample last 32B): ...{final_ct_parallel_qne[-32:].hex()}")

            print("Decrypting...")
            decrypted_pt_parallel_qne = decrypt_parallel_kdf_with_qne(
                final_ct_parallel_qne, user_password, additional_factors, qne_key_parallel
            )
            assert decrypted_pt_parallel_qne == sample_plaintext
            print(f"  SUCCESS: Parallel(KDF)+QNE Decryption. Plaintext: \"{decrypted_pt_parallel_qne.decode('utf-8', 'ignore')}\"")
        except Exception as e:
            print(f"  ERROR in Parallel(KDF)+QNE Test: {e}")
            import traceback; traceback.print_exc()
        
        print("\n[Cleanup] QNE Pool will stop automatically.")
    print("\n=" * 60); print(" Unified PoC Demonstration (with QNE) Finished."); print("=" * 60)

if __name__ == "__main__":
    run_unified_poc_demo()