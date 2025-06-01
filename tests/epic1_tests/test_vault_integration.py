# test_vault_integration.py
import unittest
import os
import uuid
import base64
import hvac # To potentially interact with Vault directly for some test setups/assertions if needed

# Import functions from your refactored/newly named modules
from epic1_modules.key_vault_manager import store_keys, get_keys, VAULT_ADDR_ENV, VAULT_TOKEN_ENV
from epic1_modules.parallel_encryption_vault import parallel_encrypt_vault, parallel_decrypt_vault, KEM_ALGORITHM_PARALLEL
from epic1_modules.layered_encryption_vault import layered_encrypt_vault, layered_decrypt_vault, KEM_ALGORITHM_LAYERED

# Helper to check if Vault is configured via environment variables
def is_vault_configured():
    return os.environ.get(VAULT_ADDR_ENV) and os.environ.get(VAULT_TOKEN_ENV)

@unittest.skipUnless(is_vault_configured(), 
                     "VAULT_ADDR and VAULT_TOKEN environment variables must be set to run Vault integration tests.")
class TestVaultKeyManagement(unittest.TestCase):
    """
    Test suite for key management with Vault and integrated encryption schemes.
    Requires a running HashiCorp Vault dev server and VAULT_ADDR/VAULT_TOKEN env vars.
    """
    
    def setUp(self):
        """Optional: Clear any known test keys before each test if necessary, or use unique IDs."""
        # For simplicity, tests will use unique UUIDs, minimizing cleanup needs.
        # If specific key_ids were reused, cleanup would be more important.
        pass

    def test_01_store_and_get_keys_directly(self):
        """Test direct storage and retrieval of keys using key_vault_manager."""
        key_id = uuid.uuid4().bytes
        aes_key = os.urandom(32)
        # Use actual KEM SK length for ML-KEM-512 (Kyber512)
        # From oqs.KeyEncapsulation(KEM_ALGORITHM_LAYERED).details['length_secret_key']
        # ML-KEM-512 SK length is 1632 bytes
        kyber_sk_len = 1632 
        kem_sk = os.urandom(kyber_sk_len) 

        keys_to_store = {"aes_test_key": aes_key, "kem_test_sk": kem_sk}
        store_keys(key_id, keys_to_store)
        
        retrieved_keys = get_keys(key_id)
        self.assertEqual(retrieved_keys["aes_test_key"], aes_key)
        self.assertEqual(retrieved_keys["kem_test_sk"], kem_sk)
        self.assertEqual(len(retrieved_keys["kem_test_sk"]), kyber_sk_len, "Max key size test (Kyber SK length).")

    def test_02_get_non_existent_key(self):
        """Test that retrieving a non-existent key_id raises ValueError."""
        non_existent_key_id = uuid.uuid4().bytes
        with self.assertRaisesRegex(ValueError, f"No keys found in Vault for key_id: {non_existent_key_id.hex()}"):
            get_keys(non_existent_key_id)

    def test_03_parallel_encryption_decryption_with_vault(self):
        """Test the full parallel encrypt/decrypt cycle with Vault key storage."""
        plaintext = b"Parallel encryption test data with Vault!"
        
        ciphertext = parallel_encrypt_vault(plaintext)
        decrypted_plaintext = parallel_decrypt_vault(ciphertext)
        
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_04_layered_encryption_decryption_with_vault(self):
        """Test the full layered encrypt/decrypt cycle with Vault key storage."""
        plaintext = b"Layered encryption test data with Vault!"
        
        ciphertext = layered_encrypt_vault(plaintext)
        decrypted_plaintext = layered_decrypt_vault(ciphertext)
        
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_05_parallel_large_data_with_vault(self):
        """Test parallel encryption with large data and Vault."""
        plaintext = os.urandom(100 * 1024) # 100KB
        ciphertext = parallel_encrypt_vault(plaintext)
        decrypted_plaintext = parallel_decrypt_vault(ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)
        
    def test_06_layered_large_data_with_vault(self):
        """Test layered encryption with large data and Vault."""
        plaintext = os.urandom(100 * 1024) # 100KB
        ciphertext = layered_encrypt_vault(plaintext)
        decrypted_plaintext = layered_decrypt_vault(ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)

    def test_07a_parallel_decrypt_key_id_not_in_vault(self):
        """Test parallel_decrypt_vault when key_id from ciphertext is not in Vault."""
        non_existent_key_id = uuid.uuid4().bytes
        # Create a dummy ciphertext structure with this non-existent key_id
        # The rest of the data doesn't matter much as key retrieval will fail first.
        dummy_c1 = b'\0'*32 # IV + one block
        dummy_ek = b'\0'*768 # Approx ML-KEM-512 EK
        dummy_c2 = b'\0'*32 # IV + one block
        malformed_ciphertext = (
            non_existent_key_id +
            len(dummy_c1).to_bytes(4, "big") + dummy_c1 +
            len(dummy_ek).to_bytes(4, "big") + dummy_ek +
            len(dummy_c2).to_bytes(4, "big") + dummy_c2
        )
        # Expecting RuntimeError because get_keys() will raise ValueError, wrapped by decrypt func
        with self.assertRaisesRegex(RuntimeError, "Failed to retrieve keys from Vault"):
            parallel_decrypt_vault(malformed_ciphertext)

    def test_07b_parallel_decrypt_malformed_data_after_valid_key_id(self):
        """Test parallel_decrypt_vault with a valid key_id but malformed subsequent data."""
        plaintext = b"data for good key"
        valid_ciphertext_full = parallel_encrypt_vault(plaintext)
        valid_key_id = valid_ciphertext_full[:16] 

        bad_data_segment = os.urandom(10) # Too short for len_C1, C1, etc.
        malformed_ciphertext = valid_key_id + bad_data_segment
        
        # Expecting an error related to IV processing or early parsing due to insufficient data.
        # The actual error was "Invalid IV size (X) for CBC."
        with self.assertRaisesRegex(ValueError, r"Invalid IV size \(\d+\) for CBC|Malformed ciphertext: C1 data is too short to contain an IV."):
            parallel_decrypt_vault(malformed_ciphertext)

    def test_08a_layered_decrypt_key_id_not_in_vault(self):
        """Test layered_decrypt_vault when key_id from ciphertext is not in Vault."""
        non_existent_key_id = uuid.uuid4().bytes
        dummy_ek = b'\0'*768
        dummy_iv = b'\0'*16
        dummy_encrypted_data = b'\0'*16
        malformed_ciphertext = (
            non_existent_key_id +
            len(dummy_ek).to_bytes(4, "big") + dummy_ek +
            dummy_iv + dummy_encrypted_data
        )
        with self.assertRaisesRegex(RuntimeError, "Failed to retrieve keys from Vault"):
            layered_decrypt_vault(malformed_ciphertext)

    def test_08b_layered_decrypt_malformed_data_after_valid_key_id(self):
        """Test layered_decrypt_vault with a valid key_id but malformed subsequent data."""
        plaintext = b"data for good layered key"
        valid_ciphertext_full = layered_encrypt_vault(plaintext)
        valid_key_id = valid_ciphertext_full[:16]

        bad_data_segment = os.urandom(10) # Too short for len_EK, EK, IV, etc.
        malformed_ciphertext = valid_key_id + bad_data_segment
        
        # Expecting the specific parsing error from layered_decrypt_vault
        with self.assertRaisesRegex(ValueError, "Malformed ciphertext: Error parsing components - Malformed ciphertext: EK length exceeds data bounds."):
            layered_decrypt_vault(malformed_ciphertext)

if __name__ == '__main__':
    # Ensure Vault is running and VAULT_ADDR/VAULT_TOKEN are set in your environment
    # before running these tests.
    if not is_vault_configured():
        print("Skipping Vault integration tests: VAULT_ADDR and/or VAULT_TOKEN not set.")
        print("Please start Vault dev server and set environment variables.")
    else:
        print("VAULT_ADDR and VAULT_TOKEN are set. Proceeding with tests.")
        # Check OQS KEM support (can be more granular per test if different KEMs are used)
        try:
            import oqs # <--- ADD THIS IMPORT HERE
            supported_kems_parallel = oqs.get_enabled_kem_mechanisms()
            if KEM_ALGORITHM_PARALLEL not in supported_kems_parallel:
                print(f"WARNING: {KEM_ALGORITHM_PARALLEL} (used in parallel_encryption_vault.py) "
                      f"not in enabled KEMs: {supported_kems_parallel}")
            
            # No need to call get_enabled_kem_mechanisms() again if it's the same list
            if KEM_ALGORITHM_LAYERED not in supported_kems_parallel: # Use the already fetched list
                 print(f"WARNING: {KEM_ALGORITHM_LAYERED} (used in layered_encryption_vault.py) "
                       f"not in enabled KEMs: {supported_kems_parallel}")
        # except NameError: # This was for oqs not being defined, import above fixes this.
        #    pass          # No longer needed if oqs is imported within this block.
        except ImportError: # If 'import oqs' itself fails (e.g., not installed)
            print("WARNING: Could not import 'oqs' module to check KEM support.")
        except Exception as e: # Catch any other errors from oqs calls
            print(f"WARNING: Error checking OQS KEM support: {e}")
            
        unittest.main()