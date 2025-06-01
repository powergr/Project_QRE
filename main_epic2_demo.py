# qne_project/main.py
"""
Main script to demonstrate the integration of QRNG simulation,
Dynamic Entropy Pool, and the AES-GCM Cipher Engine.
"""
import time
from epic2_qne.qrng import SoftwareSimulatedQRNG, MockQRNG, OsUrandomQRNG # Import QRNG implementations
from epic2_qne.entropy_pool import EntropyPool
from epic2_qne.cipher_engine import (
    generate_aes_gcm_key, 
    encrypt_with_optional_aad, 
    decrypt_with_optional_aad,
    AAD_LEN_FIELD_BYTES,      # <--- ADD THIS
    GCM_NONCE_SIZE_BYTES      # <--- AND THIS
)
def run_full_demo():
    print("=" * 50)
    print(" Quantum Noise Entropy (QNE) Enhanced Encryption PoC Demo")
    print("=" * 50)

    # --- Setup ---
    # 1. Choose and Initialize a QRNG source
    # qrng_source = SoftwareSimulatedQRNG()
    # qrng_source = OsUrandomQRNG()
    qrng_source = MockQRNG(seed_byte=0xB0, increment=True) # Use Mock for predictable "randomness"
    print(f"\n[Setup] Using QRNG source: {qrng_source.__class__.__name__}")

    # 2. Initialize Dynamic Entropy Pool
    # Pool size of 64 bytes, refreshes every 2 seconds for this demo.
    # Using 'with' statement for automatic start and stop of the pool's thread.
    with EntropyPool(qrng_instance=qrng_source,
                     max_size_bytes=64,  # As per demo setup in ticket
                     refresh_interval_sec=2.0) as qne_pool: # Use float
        print(f"[Setup] Dynamic Entropy Pool initialized (Max Size: {qne_pool.max_size}B, "
              f"Refresh Interval: {qne_pool.refresh_interval}s).")
        print("[Setup] Allowing a moment for initial entropy pool fill...")
        time.sleep(0.5) # Give pool a moment for the first fill, especially if QRNG is slow

        # 3. Generate an AES-256 GCM encryption key for the session
        encryption_key = generate_aes_gcm_key()
        print(f"[Setup] AES-256 GCM Key generated: {encryption_key.hex()[:16]}... (showing first 8 bytes)")

        # --- Test Data ---
        sensitive_data = b"Project Chimera: Launch codes are Alpha-Zulu-7! Confirmation: Sierra-Tango-November."
        print(f"\n[Data] Original Plaintext: '{sensitive_data.decode()}'")

        # --- Scenario 1: Encrypt WITH dynamic entropy from the pool ---
        print("\n--- Scenario 1: Encryption WITH Dynamic Entropy (AAD) ---")
        print("[Action] Waiting for entropy pool to potentially refresh for fresh entropy...")
        time.sleep(qne_pool.refresh_interval + 0.2) # Wait a bit longer than refresh interval

        # Request entropy for AAD. The ticket example uses 64B, let's use 32B for demo.
        num_aad_bytes = 32 
        entropy_for_aad = qne_pool.get_entropy(num_aad_bytes) 
        
        if entropy_for_aad:
            print(f"[Action] Retrieved {len(entropy_for_aad)} bytes of entropy for AAD: {entropy_for_aad.hex()}")
            ciphertext_v1 = encrypt_with_optional_aad(encryption_key, sensitive_data, entropy_for_aad)
            print(f"[Result] Ciphertext (with QNE AAD): ...{ciphertext_v1.hex()[-64:]} (showing last 32 bytes)")

            # Decryption attempt for Scenario 1
            print("[Action] Decrypting Scenario 1 ciphertext...")
            decrypted_v1 = decrypt_with_optional_aad(encryption_key, ciphertext_v1)
            if decrypted_v1 == sensitive_data:
                print(f"SUCCESS: Decrypted data matches original: '{decrypted_v1.decode()}'")
            else:
                print(f"FAILURE: Decryption FAILED or data mismatch! Decrypted: {decrypted_v1}")
        else:
            print("FAILURE: Could not retrieve sufficient entropy from the pool for Scenario 1.")

        # --- Scenario 2: Encrypt WITHOUT dynamic entropy (AAD is None) ---
        # This demonstrates compatibility where QNE might not be available or desired.
        print("\n--- Scenario 2: Encryption WITHOUT Dynamic Entropy (No AAD) ---")
        # Pass None or omit entropy_as_aad for no AAD
        ciphertext_v2 = encrypt_with_optional_aad(encryption_key, sensitive_data, None) 
        print(f"[Result] Ciphertext (no QNE AAD): ...{ciphertext_v2.hex()[-64:]} (showing last 32 bytes)")

        # Decryption attempt for Scenario 2
        print("[Action] Decrypting Scenario 2 ciphertext...")
        decrypted_v2 = decrypt_with_optional_aad(encryption_key, ciphertext_v2)
        if decrypted_v2 == sensitive_data:
            print(f"SUCCESS: Decrypted data matches original: '{decrypted_v2.decode()}'")
        else:
            print(f"FAILURE: Decryption FAILED or data mismatch! Decrypted: {decrypted_v2}")

        # --- Scenario 3: Decryption Failure Cases (Illustrative) ---
        print("\n--- Scenario 3: Illustrating Decryption Failures ---")
        if 'ciphertext_v1' in locals() and ciphertext_v1: # Ensure ciphertext_v1 was created
            # Attempt 3a: Decryption with a WRONG KEY
            wrong_key = generate_aes_gcm_key() # A different AES key
            print(f"[Action] Attempting decryption of Scenario 1 ciphertext with a WRONG AES key...")
            decrypted_wrong_key = decrypt_with_optional_aad(wrong_key, ciphertext_v1)
            if decrypted_wrong_key is None: # AES-GCM decrypt returns None on InvalidTag
                print("SUCCESS (expected): Decryption with WRONG KEY failed (InvalidTag / auth failure).")
            else:
                print("FAILURE (unexpected): Decryption with WRONG KEY somehow succeeded?! This should not happen.")

            # Attempt 3b: Decryption of TAMPERED ciphertext
            if len(ciphertext_v1) > (AAD_LEN_FIELD_BYTES + GCM_NONCE_SIZE_BYTES + 5): # Ensure payload is long enough
                tampered_payload_list = list(ciphertext_v1)
                # Flip a bit in the ciphertext part (after AAD_LEN, AAD, and NONCE)
                # Tampering the GCM tag or the ciphertext body should cause InvalidTag.
                # Let's tamper a byte towards the end (likely in the tag or ciphertext body).
                tamper_index = len(tampered_payload_list) - 5
                tampered_payload_list[tamper_index] = tampered_payload_list[tamper_index] ^ 0x01 
                tampered_ciphertext = bytes(tampered_payload_list)
                
                print(f"[Action] Attempting decryption of TAMPERED Scenario 1 ciphertext...")
                decrypted_tampered = decrypt_with_optional_aad(encryption_key, tampered_ciphertext)
                if decrypted_tampered is None:
                    print("SUCCESS (expected): Decryption of TAMPERED ciphertext failed (InvalidTag / auth failure).")
                else:
                    print("FAILURE (unexpected): Decryption of tampered data somehow succeeded?! This should not happen.")
        else:
            print("Skipping Scenario 3 (tampering tests) as Scenario 1 ciphertext was not generated.")

        print("\n[Cleanup] Stopping entropy pool...")
    # EntropyPool's __exit__ method will call stop()
    print("Dynamic Entropy Pool stopped.")
    print("\nQNE PoC Demo finished.")

if __name__ == "__main__":
    run_full_demo()