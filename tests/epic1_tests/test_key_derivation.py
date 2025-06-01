# tests/epic1_tests/test_key_derivation.py
import unittest
import os
import hashlib # For creating expected factors_hash in tests
from typing import List # For type hints
from epic1_modules.key_derivation import derive_key, ARGON2_TIME_COST, PBKDF2_ITERATIONS # Import constants if needed for specific tests
# Assuming ENTROPY_MANAGER_INSTANCE is handled within key_derivation.py
# We might need to mock it if we want to test with predictable "anchored" salt components.
from unittest.mock import patch

# Path to where EntropyManager is imported by key_derivation.py
ENTROPY_MANAGER_MODULE_PATH = 'epic1_modules.key_derivation.ENTROPY_MANAGER_INSTANCE'

class TestKeyDerivation(unittest.TestCase):
    """Test suite for the Key Derivation Function (KDF) in key_derivation.py."""

    def calculate_expected_factors_hash(self, additional_inputs: List[bytes] | None) -> bytes:
        """Helper to calculate factors_hash for test comparisons."""
        current_additional_inputs = additional_inputs if additional_inputs is not None else []
        concatenated = b''.join(current_additional_inputs)
        return hashlib.sha256(concatenated).digest()

    @patch(ENTROPY_MANAGER_MODULE_PATH) # Mock the global instance
    def test_successful_derivation_argon2id(self, mock_em_instance):
        """Test successful key derivation with Argon2id and check output format."""
        mock_em_instance.get_entropy.return_value = b'\x00'*16 # Predictable random_salt_component

        password = b"mysecretpassword"
        additional_inputs = [b"biometric_data_sample", b"device_id_xyz789"]
        
        key, factors_hash, random_salt = derive_key(
            password, additional_inputs, method="Argon2id"
        )
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32, "Derived key should be 32 bytes for AES-256.")
        self.assertIsInstance(factors_hash, bytes)
        self.assertEqual(len(factors_hash), 32) # SHA256 hash
        self.assertEqual(factors_hash, self.calculate_expected_factors_hash(additional_inputs))
        self.assertIsInstance(random_salt, bytes)
        self.assertEqual(len(random_salt), 16, "Random salt component should be 16 bytes.")
        self.assertEqual(random_salt, b'\x00'*16) # Check it used the mocked value
        mock_em_instance.get_entropy.assert_called_once_with(16)


    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_successful_derivation_pbkdf2(self, mock_em_instance):
        """Test successful key derivation with PBKDF2 and check output format."""
        mock_em_instance.get_entropy.return_value = b'\x01'*16

        password = b"anotherSecurePass123!"
        additional_inputs = [b"env_factor_alpha", b"user_specific_token_beta"]
        
        key, factors_hash, random_salt = derive_key(
            password, additional_inputs, method="PBKDF2"
        )
        
        self.assertIsInstance(key, bytes); self.assertEqual(len(key), 32)
        self.assertIsInstance(factors_hash, bytes); self.assertEqual(len(factors_hash), 32)
        self.assertEqual(factors_hash, self.calculate_expected_factors_hash(additional_inputs))
        self.assertIsInstance(random_salt, bytes); self.assertEqual(len(random_salt), 16)
        self.assertEqual(random_salt, b'\x01'*16)
        mock_em_instance.get_entropy.assert_called_once_with(16)


    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_consistency_with_same_rederive_components(self, mock_em_instance):
        """
        Verify that re-deriving with the same password, factors_hash, and random_salt_component
        produces the exact same key. EntropyManager should not be called for re-derivation.
        """
        password = b"consistentPass"
        # Simulate original derivation (we don't need EM for this part of the test logic)
        original_additional_inputs = [b"factor1", b"factor2"]
        original_factors_hash = self.calculate_expected_factors_hash(original_additional_inputs)
        original_random_salt_component = os.urandom(16) # This was the original random part

        # Key 1 (re-derivation)
        key1_argon2, fh1, rs1 = derive_key(
            password, 
            additional_inputs=original_additional_inputs, # Should be ignored if rederive_factors_hash provided
            method="Argon2id", 
            _rederive_using_factors_hash=original_factors_hash,
            _rederive_using_random_salt_component=original_random_salt_component
        )
        self.assertEqual(fh1, original_factors_hash)
        self.assertEqual(rs1, original_random_salt_component)
        
        # Key 2 (re-derivation with same components)
        key2_argon2, fh2, rs2 = derive_key(
            password, 
            additional_inputs=[b"different", b"inputs"], # These should be ignored by derive_key
            method="Argon2id", 
            _rederive_using_factors_hash=original_factors_hash,
            _rederive_using_random_salt_component=original_random_salt_component
        )
        self.assertEqual(fh2, original_factors_hash)
        self.assertEqual(rs2, original_random_salt_component)
        self.assertEqual(key1_argon2, key2_argon2, "Argon2id keys should be identical with same re-derive components.")
        
        # Ensure EntropyManager's get_entropy was NOT called during re-derivation
        mock_em_instance.get_entropy.assert_not_called()


    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_rederive_with_new_factors_hash(self, mock_em_instance):
        """
        Test re-deriving with a fixed random_salt_component but allowing additional_inputs
        to form a new factors_hash.
        """
        password = b"rederiveNewFactors"
        original_random_salt_component = os.urandom(16)
        
        inputs1 = [b"input_set_1"]
        expected_fh1 = self.calculate_expected_factors_hash(inputs1)
        key1, fh1, rs1 = derive_key(
            password, inputs1, method="Argon2id",
            _rederive_using_random_salt_component=original_random_salt_component
            # _rederive_using_factors_hash is NOT provided
        )
        self.assertEqual(fh1, expected_fh1)
        self.assertEqual(rs1, original_random_salt_component)

        inputs2 = [b"input_set_2_different"] # Different inputs
        expected_fh2 = self.calculate_expected_factors_hash(inputs2)
        key2, fh2, rs2 = derive_key(
            password, inputs2, method="Argon2id",
            _rederive_using_random_salt_component=original_random_salt_component
        )
        self.assertEqual(fh2, expected_fh2)
        self.assertEqual(rs2, original_random_salt_component)
        
        self.assertNotEqual(key1, key2, "Keys should differ if factors_hash differs but random_salt is same.")
        # EntropyManager should not be called as random_salt_component is provided
        mock_em_instance.get_entropy.assert_not_called()


    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_different_random_salt_produces_different_keys(self, mock_em_instance):
        """Confirm that different auto-generated random_salt components produce different keys."""
        password = b"saltTestPassKDF"
        additional_inputs = [b"uniqueFactorKDF"]

        # Call 1
        mock_em_instance.get_entropy.return_value = b'\x11'*16
        key1, fh1, salt1 = derive_key(password, additional_inputs, method="Argon2id")
        
        # Call 2
        mock_em_instance.get_entropy.return_value = b'\x22'*16 # Different salt from EM
        key2, fh2, salt2 = derive_key(password, additional_inputs, method="Argon2id")
        
        self.assertEqual(fh1, fh2, "Factors_hash should be the same for same additional_inputs.")
        self.assertNotEqual(salt1, salt2, "Random salt components from EM should differ (mocked).")
        self.assertNotEqual(key1, key2, "Keys from different random_salt components should differ.")
        self.assertEqual(mock_em_instance.get_entropy.call_count, 2)


    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_empty_additional_inputs(self, mock_em_instance):
        """Test key derivation with an empty list of additional_inputs."""
        mock_em_instance.get_entropy.return_value = b'\x33'*16
        password = b"emptyFactorsPassKDF"
        expected_factors_hash = self.calculate_expected_factors_hash([])
        
        key_argon2, factors_hash_argon2, salt_argon2 = derive_key(password, [], method="Argon2id")
        self.assertEqual(len(key_argon2), 32)
        self.assertEqual(factors_hash_argon2, expected_factors_hash)
        self.assertEqual(salt_argon2, b'\x33'*16)

        # Reset mock for next KDF method if get_entropy is called again by same mock_em_instance
        mock_em_instance.get_entropy.reset_mock() 
        mock_em_instance.get_entropy.return_value = b'\x44'*16
        key_pbkdf2, factors_hash_pbkdf2, salt_pbkdf2 = derive_key(password, [], method="PBKDF2")
        self.assertEqual(len(key_pbkdf2), 32)
        self.assertEqual(factors_hash_pbkdf2, expected_factors_hash)
        self.assertEqual(salt_pbkdf2, b'\x44'*16)

    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_multiple_additional_inputs(self, mock_em_instance):
        """Test with more than two additional inputs."""
        mock_em_instance.get_entropy.return_value = b'\x55'*16
        password = b"multiFactorPassKDF"
        additional_inputs = [b"factorA", b"factorB", b"factorC", b"factorD"]
        expected_factors_hash = self.calculate_expected_factors_hash(additional_inputs)
        
        key_argon2, factors_hash_argon2, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(key_argon2), 32)
        self.assertEqual(factors_hash_argon2, expected_factors_hash)

    def test_invalid_inputs_raise_valueerror(self):
        """Test ValueError for invalid input types or unsupported method."""
        with self.assertRaisesRegex(ValueError, "Password must be bytes."):
            derive_key("not_bytes", [b"a"], method="Argon2id") # type: ignore
        
        with self.assertRaisesRegex(ValueError, "If provided, additional_inputs must be a list of byte strings."):
            derive_key(b"pass", ["not_bytes_either"], method="Argon2id") # type: ignore
        with self.assertRaisesRegex(ValueError, "If provided, additional_inputs must be a list of byte strings."):
            derive_key(b"pass", [b"valid", "invalid"], method="Argon2id") # type: ignore
        with self.assertRaisesRegex(ValueError, "If provided, additional_inputs must be a list of byte strings."):
            derive_key(b"pass", b"not_a_list", method="Argon2id") # type: ignore
            
        with self.assertRaisesRegex(ValueError, "Unsupported KDF method: InvalidMethod"):
            derive_key(b"pass", [b"a"], method="InvalidMethod")
        
        # Test re-derivation parameter errors
        with self.assertRaisesRegex(ValueError, "_rederive_using_random_salt_component must be 16 bytes."):
            derive_key(b"p", _rederive_using_random_salt_component=b"short")
        with self.assertRaisesRegex(ValueError, "_rederive_using_factors_hash must be 32 bytes."):
            derive_key(b"p", _rederive_using_random_salt_component=b"0"*16, _rederive_using_factors_hash=b"short")
        with self.assertRaisesRegex(ValueError, "Cannot provide _rederive_using_factors_hash for initial derivation if _rederive_using_random_salt_component is not also provided."):
            derive_key(b"p", _rederive_using_factors_hash=b"0"*32)


    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_edge_case_empty_password(self, mock_em_instance):
        """Test with an empty password (should still derive a key)."""
        mock_em_instance.get_entropy.return_value = b'\x66'*16
        password = b""
        additional_inputs = [b"some_factor_kdf"]
        
        key_argon2, _, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(key_argon2), 32)

        mock_em_instance.get_entropy.reset_mock() # Reset for next call
        mock_em_instance.get_entropy.return_value = b'\x77'*16
        key_pbkdf2, _, _ = derive_key(password, additional_inputs, method="PBKDF2")
        self.assertEqual(len(key_pbkdf2), 32)

    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_edge_case_large_additional_input(self, mock_em_instance):
        """Test with a large additional input (e.g., 1KB)."""
        mock_em_instance.get_entropy.return_value = b'\x88'*16
        password = b"largeInputPassKDF"
        large_factor = os.urandom(1024) 
        additional_inputs = [b"small_factor_kdf", large_factor]
        
        key_argon2, _, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(key_argon2), 32)

    # --- Integration Test (within this module, focused on KDF output) ---
    @patch(ENTROPY_MANAGER_MODULE_PATH)
    def test_integration_with_aes_encryption(self, mock_em_instance):
        """
        Integration test: Use the derived key with AES-256-CBC to encrypt
        and decrypt sample data successfully.
        """
        mock_em_instance.get_entropy.return_value = b'\x99'*16 # For random_salt_component for K1_argon2
        
        password = b"integrationTestPassKDF"
        additional_inputs = [b"integration_factor_kdf"]
        plaintext = b"This is some data to encrypt for the KDF integration test."

        # Test with Argon2id derived key
        derived_key_argon2, _, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(derived_key_argon2), 32)
        
        # AES specific imports for this test
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding

        iv_argon2 = os.urandom(16)
        cipher_argon2 = Cipher(algorithms.AES(derived_key_argon2), modes.CBC(iv_argon2))
        
        padder_argon2 = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data_argon2 = padder_argon2.update(plaintext) + padder_argon2.finalize()
        encryptor_argon2 = cipher_argon2.encryptor()
        ciphertext_argon2 = encryptor_argon2.update(padded_data_argon2) + encryptor_argon2.finalize()
        
        decryptor_argon2 = cipher_argon2.decryptor()
        decrypted_padded_argon2 = decryptor_argon2.update(ciphertext_argon2) + decryptor_argon2.finalize()
        unpadder_argon2 = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_plaintext_argon2 = unpadder_argon2.update(decrypted_padded_argon2) + unpadder_argon2.finalize()
        
        self.assertEqual(decrypted_plaintext_argon2, plaintext, "AES integration failed for Argon2id key.")

        # Test with PBKDF2 derived key
        mock_em_instance.get_entropy.reset_mock() # Reset for next call
        mock_em_instance.get_entropy.return_value = b'\xAA'*16 # For random_salt_component for K1_pbkdf2
        derived_key_pbkdf2, _, _ = derive_key(password, additional_inputs, method="PBKDF2")
        self.assertEqual(len(derived_key_pbkdf2), 32)

        iv_pbkdf2 = os.urandom(16) 
        cipher_pbkdf2 = Cipher(algorithms.AES(derived_key_pbkdf2), modes.CBC(iv_pbkdf2))

        padder_pbkdf2 = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data_pbkdf2 = padder_pbkdf2.update(plaintext) + padder_pbkdf2.finalize()
        encryptor_pbkdf2 = cipher_pbkdf2.encryptor()
        ciphertext_pbkdf2 = encryptor_pbkdf2.update(padded_data_pbkdf2) + encryptor_pbkdf2.finalize()
        
        decryptor_pbkdf2 = cipher_pbkdf2.decryptor()
        decrypted_padded_pbkdf2 = decryptor_pbkdf2.update(ciphertext_pbkdf2) + decryptor_pbkdf2.finalize()
        unpadder_pbkdf2 = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_plaintext_pbkdf2 = unpadder_pbkdf2.update(decrypted_padded_pbkdf2) + unpadder_pbkdf2.finalize()

        self.assertEqual(decrypted_plaintext_pbkdf2, plaintext, "AES integration failed for PBKDF2 key.")

if __name__ == "__main__":
    unittest.main()