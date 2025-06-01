# tests/epic1_tests/test_vault_integration.py
import unittest
import os
import uuid
import time # For QNE pool in new tests
from typing import List, Optional 

# Epic 1 modules
from epic1_modules.key_vault_manager import store_keys, get_keys, VAULT_ADDR_ENV, VAULT_TOKEN_ENV
from epic1_modules.parallel_encryption_vault import parallel_encrypt_vault, parallel_decrypt_vault, KEM_ALGORITHM_PARALLEL
from epic1_modules.layered_encryption_vault import layered_encrypt_vault, layered_decrypt_vault, KEM_ALGORITHM_LAYERED

# Epic 2 components (needed for testing the QNE-integrated wrappers)
from epic2_qne.entropy_pool import EntropyPool
from epic2_qne.qrng import MockQRNG # For predictable AAD in these specific tests

# Import the new wrapper functions.
# OPTION 1: If you created system_core_logic.py in the project root:
# from system_core_logic import (
#     encrypt_layered_with_qne, decrypt_layered_with_qne,
#     encrypt_parallel_kdf_with_qne, decrypt_parallel_kdf_with_qne
# )
# OPTION 2: If the wrapper functions are in main_unified_poc.py (and it's importable):
# (Make sure main_unified_poc.py's demo run is under 'if __name__ == "__main__":')
try:
    from main_unified_poc import ( # Adjust if your file name is different or it's in a package
        encrypt_layered_with_qne, decrypt_layered_with_qne,
        encrypt_parallel_kdf_with_qne, decrypt_parallel_kdf_with_qne
    )
    UNIFIED_WRAPPERS_AVAILABLE = True
except ImportError:
    print("WARNING [test_vault_integration]: Could not import unified wrapper functions "
          "(e.g., encrypt_layered_with_qne). Skipping QNE integration tests in this suite.")
    UNIFIED_WRAPPERS_AVAILABLE = False
    # Define dummy functions if import fails so tests can be skipped gracefully by decorator later
    def encrypt_layered_with_qne(*args, **kwargs): raise NotImplementedError("Wrapper not imported")
    def decrypt_layered_with_qne(*args, **kwargs): raise NotImplementedError("Wrapper not imported")
    def encrypt_parallel_kdf_with_qne(*args, **kwargs): raise NotImplementedError("Wrapper not imported")
    def decrypt_parallel_kdf_with_qne(*args, **kwargs): raise NotImplementedError("Wrapper not imported")


def is_vault_configured():
    return os.environ.get(VAULT_ADDR_ENV) and os.environ.get(VAULT_TOKEN_ENV)

@unittest.skipUnless(is_vault_configured(), 
                     "VAULT_ADDR and VAULT_TOKEN environment variables must be set to run Vault integration tests.")
class TestVaultKeyManagementAndEncryption(unittest.TestCase):
    SAMPLE_PLAINTEXT = b"This is some sample plaintext for various tests!"
    LARGE_PLAINTEXT = os.urandom(100 * 1024) 
    TEST_PASSWORD = b"aVeryStrongPasswordForKDF!123$%"
    TEST_ADDITIONAL_INPUTS_1 = [b"user_id_abc", b"device_fingerprint_xyz"]
    TEST_ADDITIONAL_INPUTS_2 = [b"session_token_123", b"location_data_jfk", b"timestamp_val"]

    # ... (test_01 to test_06b remain exactly the same as the last version that passed)
    def test_01_store_and_get_keys_directly(self):
        key_id = uuid.uuid4().bytes; aes_key = os.urandom(32); kyber_sk_len = 1632
        kem_sk = os.urandom(kyber_sk_len); kdf_factors_hash = os.urandom(32); kdf_random_salt = os.urandom(16)
        keys_to_store = {
            "aes_test_key": aes_key, "kem_test_sk": kem_sk,
            "kdf_factors_hash_test": kdf_factors_hash, "kdf_random_salt_test": kdf_random_salt
        }
        store_keys(key_id, keys_to_store)
        retrieved_keys = get_keys(key_id)
        self.assertEqual(retrieved_keys["aes_test_key"], aes_key)
        self.assertEqual(retrieved_keys["kem_test_sk"], kem_sk)
        self.assertEqual(retrieved_keys["kdf_factors_hash_test"], kdf_factors_hash)
        self.assertEqual(retrieved_keys["kdf_random_salt_test"], kdf_random_salt)

    def test_02_get_non_existent_key(self):
        non_existent_key_id = uuid.uuid4().bytes
        with self.assertRaisesRegex(ValueError, 
                                     f"No keys found in Vault for key_id: {non_existent_key_id.hex()}"):
            get_keys(non_existent_key_id)

    def test_03a_parallel_encryption_random_k1_cycle(self):
        ciphertext = parallel_encrypt_vault(self.SAMPLE_PLAINTEXT)
        decrypted_plaintext = parallel_decrypt_vault(ciphertext)
        self.assertEqual(decrypted_plaintext, self.SAMPLE_PLAINTEXT)

    def test_03b_parallel_large_data_random_k1(self):
        ciphertext = parallel_encrypt_vault(self.LARGE_PLAINTEXT)
        decrypted_plaintext = parallel_decrypt_vault(ciphertext)
        self.assertEqual(decrypted_plaintext, self.LARGE_PLAINTEXT)

    def test_03c_parallel_encryption_kdf_k1_cycle(self):
        ciphertext = parallel_encrypt_vault(self.SAMPLE_PLAINTEXT, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_1)
        decrypted_plaintext = parallel_decrypt_vault(ciphertext, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_1)
        self.assertEqual(decrypted_plaintext, self.SAMPLE_PLAINTEXT)

    def test_03d_parallel_large_data_kdf_k1(self):
        ciphertext = parallel_encrypt_vault(self.LARGE_PLAINTEXT, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_2)
        decrypted_plaintext = parallel_decrypt_vault(ciphertext, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_2)
        self.assertEqual(decrypted_plaintext, self.LARGE_PLAINTEXT)

    def test_03e_parallel_kdf_k1_wrong_password(self):
        ciphertext = parallel_encrypt_vault(self.SAMPLE_PLAINTEXT, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_1)
        wrong_password = b"IncorrectPassword"
        with self.assertRaisesRegex(RuntimeError, r"Unpadding C1 failed \(corrupted data or incorrect key K1\?\): Invalid padding bytes\."):
            parallel_decrypt_vault(ciphertext, password=wrong_password, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_1)

    def test_03f_parallel_kdf_k1_wrong_additional_inputs(self):
        ciphertext = parallel_encrypt_vault(self.SAMPLE_PLAINTEXT, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_1)
        wrong_additional_inputs = [b"completely", b"different", b"factors"]
        try:
            decrypted_plaintext = parallel_decrypt_vault(ciphertext, password=self.TEST_PASSWORD, additional_kdf_inputs=wrong_additional_inputs)
            self.assertNotEqual(decrypted_plaintext, self.SAMPLE_PLAINTEXT, "Decryption with wrong additional_inputs should not yield original plaintext if no unpadding error occurs.")
        except RuntimeError as e:
            self.assertIn("Unpadding C1 failed", str(e), "Expected an unpadding error due to wrong K1 from KDF with wrong additional_inputs.")
    
    def test_03g_parallel_kdf_k1_missing_password_for_kdf_decrypt(self):
        ciphertext = parallel_encrypt_vault(self.SAMPLE_PLAINTEXT, password=self.TEST_PASSWORD, additional_kdf_inputs=self.TEST_ADDITIONAL_INPUTS_1)
        with self.assertRaisesRegex(RuntimeError, r"K1 not found in Vault \(and no password provided for KDF\)\."): 
            parallel_decrypt_vault(ciphertext)

    def test_04a_layered_encryption_cycle(self):
        ciphertext = layered_encrypt_vault(self.SAMPLE_PLAINTEXT)
        decrypted_plaintext = layered_decrypt_vault(ciphertext)
        self.assertEqual(decrypted_plaintext, self.SAMPLE_PLAINTEXT)

    def test_04b_layered_large_data(self):
        ciphertext = layered_encrypt_vault(self.LARGE_PLAINTEXT)
        decrypted_plaintext = layered_decrypt_vault(ciphertext)
        self.assertEqual(decrypted_plaintext, self.LARGE_PLAINTEXT)

    def test_05a_parallel_decrypt_key_id_not_in_vault(self):
        non_existent_key_id = uuid.uuid4().bytes
        dummy_c1 = b'\0'*32; dummy_ek = b'\0'*768; dummy_c2 = b'\0'*32
        malformed_ciphertext = ( non_existent_key_id + len(dummy_c1).to_bytes(4, "big") + dummy_c1 +
            len(dummy_ek).to_bytes(4, "big") + dummy_ek + len(dummy_c2).to_bytes(4, "big") + dummy_c2 )
        with self.assertRaisesRegex(RuntimeError, r"Failed to retrieve keys/salts from Vault: No keys found in Vault for key_id: [0-9a-f]+"):
            parallel_decrypt_vault(malformed_ciphertext)

    def test_05b_parallel_decrypt_malformed_data_after_valid_key_id(self):
        valid_ciphertext_full = parallel_encrypt_vault(self.SAMPLE_PLAINTEXT)
        valid_key_id = valid_ciphertext_full[:16]
        bad_data_segment = os.urandom(10) 
        malformed_ciphertext = valid_key_id + bad_data_segment
        with self.assertRaisesRegex(ValueError, "Malformed ciphertext: C1 length exceeds available data."):
            parallel_decrypt_vault(malformed_ciphertext)

    def test_06a_layered_decrypt_key_id_not_in_vault(self):
        non_existent_key_id = uuid.uuid4().bytes
        dummy_ek = b'\0'*768; dummy_iv = b'\0'*16; dummy_encrypted_data = b'\0'*16
        malformed_ciphertext = ( non_existent_key_id + len(dummy_ek).to_bytes(4, "big") + dummy_ek +
            dummy_iv + dummy_encrypted_data )
        with self.assertRaisesRegex(RuntimeError, r"Failed to retrieve keys from Vault for layered decryption: No keys found in Vault for key_id: [0-9a-f]+"):
            layered_decrypt_vault(malformed_ciphertext)

    def test_06b_layered_decrypt_malformed_data_after_valid_key_id(self):
        valid_ciphertext_full = layered_encrypt_vault(self.SAMPLE_PLAINTEXT)
        valid_key_id = valid_ciphertext_full[:16]
        bad_data_segment = os.urandom(10) 
        malformed_ciphertext = valid_key_id + bad_data_segment
        with self.assertRaisesRegex(ValueError, "Malformed ciphertext: Error parsing components - Malformed ciphertext: EK length exceeds data bounds."):
            layered_decrypt_vault(malformed_ciphertext)

    # --- NEW TESTS for QNE-Integrated Wrappers ---
    @unittest.skipUnless(UNIFIED_WRAPPERS_AVAILABLE, "Unified wrapper functions not imported, skipping QNE integration tests.")
    def test_07_system_encrypt_decrypt_layered_with_qne(self):
        """Test the layered_with_qne wrapper (Epic 1 + Epic 2) end-to-end."""
        mock_qrng_for_pool = MockQRNG(seed_byte=0xCA) # Use a mock for predictable AAD if any
        with EntropyPool(qrng_instance=mock_qrng_for_pool, max_size_bytes=64, refresh_interval_sec=0.05) as qne_pool:
            time.sleep(0.01) # Tiny pause for pool's thread to potentially do one fill
            
            # encrypt_layered_with_qne returns: final_ciphertext, qne_aes_gcm_key_for_poc
            final_ciphertext, qne_poc_key = encrypt_layered_with_qne(self.SAMPLE_PLAINTEXT, qne_pool)
            self.assertIsInstance(final_ciphertext, bytes)
            self.assertIsInstance(qne_poc_key, bytes)
            
            decrypted_plaintext = decrypt_layered_with_qne(final_ciphertext, qne_poc_key)
            self.assertEqual(decrypted_plaintext, self.SAMPLE_PLAINTEXT)

    @unittest.skipUnless(UNIFIED_WRAPPERS_AVAILABLE, "Unified wrapper functions not imported, skipping QNE integration tests.")
    def test_08_system_encrypt_decrypt_parallel_kdf_with_qne(self):
        """Test the parallel_kdf_with_qne wrapper (Epic 1 + Epic 3 KDF + Epic 2) end-to-end."""
        mock_qrng_for_pool = MockQRNG(seed_byte=0xCB)
        with EntropyPool(qrng_instance=mock_qrng_for_pool, max_size_bytes=64, refresh_interval_sec=0.05) as qne_pool:
            time.sleep(0.01)

            final_ciphertext, qne_poc_key = encrypt_parallel_kdf_with_qne(
                self.SAMPLE_PLAINTEXT, self.TEST_PASSWORD, self.TEST_ADDITIONAL_INPUTS_1, qne_pool
            )
            self.assertIsInstance(final_ciphertext, bytes)
            self.assertIsInstance(qne_poc_key, bytes)

            decrypted_plaintext = decrypt_parallel_kdf_with_qne(
                final_ciphertext, self.TEST_PASSWORD, self.TEST_ADDITIONAL_INPUTS_1, qne_poc_key
            )
            self.assertEqual(decrypted_plaintext, self.SAMPLE_PLAINTEXT)

    @unittest.skipUnless(UNIFIED_WRAPPERS_AVAILABLE, "Unified wrapper functions not imported, skipping QNE integration tests.")
    def test_09_qne_decryption_fails_with_wrong_qne_key(self):
        """Test that the QNE layer fails decryption with a wrong QNE AES key."""
        mock_qrng_for_pool = MockQRNG(seed_byte=0xCC)
        with EntropyPool(qrng_instance=mock_qrng_for_pool, max_size_bytes=32, refresh_interval_sec=0.05) as qne_pool:
            time.sleep(0.01)
            final_ciphertext, _ = encrypt_layered_with_qne(self.SAMPLE_PLAINTEXT, qne_pool) # Don't need the correct key
            
            wrong_qne_key = os.urandom(32) # Generate a different AES-GCM key
            
            with self.assertRaisesRegex(RuntimeError, "QNE Layer Decryption Failed"):
                decrypt_layered_with_qne(final_ciphertext, wrong_qne_key)


if __name__ == '__main__':
    if not is_vault_configured():
        print("Skipping Vault integration tests: VAULT_ADDR and/or VAULT_TOKEN not set.")
    else:
        print("VAULT_ADDR and VAULT_TOKEN are set. Proceeding with tests.")
        # oqs import for KEM algorithm name constants if they were defined in the oqs module,
        # or for get_enabled_kem_mechanisms().
        # For this test file, it's mainly the latter if KEM_ALGORITHM_... constants are directly used.
        # However, KEM_ALGORITHM_PARALLEL and KEM_ALGORITHM_LAYERED are defined in their respective modules.
        # So, direct 'oqs' import here is primarily for get_enabled_kem_mechanisms if used.
        try:
            import oqs 
            supported_kems = oqs.get_enabled_kem_mechanisms()
            # Check KEMs used by the modules this test file IMPORTS
            if KEM_ALGORITHM_PARALLEL not in supported_kems:
                print(f"WARNING: KEM '{KEM_ALGORITHM_PARALLEL}' (for parallel scheme) "
                      f"not in enabled KEMs: {supported_kems}")
            if KEM_ALGORITHM_LAYERED not in supported_kems:
                 print(f"WARNING: KEM '{KEM_ALGORITHM_LAYERED}' (for layered scheme) "
                       f"not in enabled KEMs: {supported_kems}")
        except ImportError: 
            print("WARNING: Could not import 'oqs' module to check KEM support.")
        except Exception as e: 
            print(f"WARNING: Error checking OQS KEM support: {e}")
            
        unittest.main()