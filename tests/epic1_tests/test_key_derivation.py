# In test_key_derivation.py
import unittest
import os
from epic1_modules.key_derivation import derive_key, ARGON2_TYPE # Import ARGON2_TYPE if you want to check it specifically
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding 

class TestKeyDerivation(unittest.TestCase):
    """Test suite for the Key Derivation Function (KDF)."""

    def test_successful_derivation_argon2id(self):
        """Test successful key derivation with Argon2id and check output format."""
        password = b"mysecretpassword"
        additional_inputs = [b"biometric_data_sample", b"device_id_xyz789"]
        
        key, random_salt = derive_key(password, additional_inputs, method="Argon2id")
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32, "Derived key should be 32 bytes for AES-256.")
        self.assertIsInstance(random_salt, bytes)
        self.assertEqual(len(random_salt), 16, "Random salt component should be 16 bytes.")

    def test_successful_derivation_pbkdf2(self):
        """Test successful key derivation with PBKDF2 and check output format."""
        password = b"anotherSecurePass123!"
        additional_inputs = [b"env_factor_alpha", b"user_specific_token_beta"]
        
        key, random_salt = derive_key(password, additional_inputs, method="PBKDF2")
        
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32, "Derived key should be 32 bytes.")
        self.assertIsInstance(random_salt, bytes)
        self.assertEqual(len(random_salt), 16, "Random salt component should be 16 bytes.")

    def test_consistency_with_same_salt(self):
        """
        Verify that the same password, additional_inputs, method, and *the same random_salt component*
        produce the exact same key. This simulates re-derivation during decryption.
        """
        password = b"consistentPass"
        additional_inputs = [b"factor1", b"factor2"]
        fixed_random_salt = os.urandom(16) # Generate a salt once for this test

        # Derive key for Argon2id with the fixed random_salt component
        key1_argon2, salt1_argon2 = derive_key(
            password, additional_inputs, method="Argon2id", _test_fixed_random_salt=fixed_random_salt
        )
        self.assertEqual(salt1_argon2, fixed_random_salt, "Argon2id did not use the provided fixed salt.")
        
        key2_argon2, salt2_argon2 = derive_key(
            password, additional_inputs, method="Argon2id", _test_fixed_random_salt=fixed_random_salt
        )
        self.assertEqual(salt2_argon2, fixed_random_salt)
        self.assertEqual(key1_argon2, key2_argon2, "Argon2id keys should be identical with the same inputs and salt.")

        # Derive key for PBKDF2 with the fixed random_salt component
        key1_pbkdf2, salt1_pbkdf2 = derive_key(
            password, additional_inputs, method="PBKDF2", _test_fixed_random_salt=fixed_random_salt
        )
        self.assertEqual(salt1_pbkdf2, fixed_random_salt, "PBKDF2 did not use the provided fixed salt.")

        key2_pbkdf2, salt2_pbkdf2 = derive_key(
            password, additional_inputs, method="PBKDF2", _test_fixed_random_salt=fixed_random_salt
        )
        self.assertEqual(salt2_pbkdf2, fixed_random_salt)
        self.assertEqual(key1_pbkdf2, key2_pbkdf2, "PBKDF2 keys should be identical with the same inputs and salt.")

    def test_different_random_salt_produces_different_keys(self):
        """Confirm that different auto-generated random_salt components produce different keys."""
        password = b"saltTestPass"
        additional_inputs = [b"uniqueFactor"]

        key1_argon2, salt1_argon2 = derive_key(password, additional_inputs, method="Argon2id")
        key2_argon2, salt2_argon2 = derive_key(password, additional_inputs, method="Argon2id")
        
        self.assertNotEqual(salt1_argon2, salt2_argon2, "Random salts for Argon2id should differ.")
        self.assertNotEqual(key1_argon2, key2_argon2, "Keys from different salts for Argon2id should differ.")

        key1_pbkdf2, salt1_pbkdf2 = derive_key(password, additional_inputs, method="PBKDF2")
        key2_pbkdf2, salt2_pbkdf2 = derive_key(password, additional_inputs, method="PBKDF2")

        self.assertNotEqual(salt1_pbkdf2, salt2_pbkdf2, "Random salts for PBKDF2 should differ.")
        self.assertNotEqual(key1_pbkdf2, key2_pbkdf2, "Keys from different salts for PBKDF2 should differ.")

    def test_empty_additional_inputs(self):
        """Test key derivation with an empty list of additional_inputs."""
        password = b"emptyFactorsPass"
        # factors_hash will be SHA256(b'')
        
        key_argon2, salt_argon2 = derive_key(password, [], method="Argon2id")
        self.assertEqual(len(key_argon2), 32)
        self.assertEqual(len(salt_argon2), 16)

        key_pbkdf2, salt_pbkdf2 = derive_key(password, [], method="PBKDF2")
        self.assertEqual(len(key_pbkdf2), 32)
        self.assertEqual(len(salt_pbkdf2), 16)

    def test_multiple_additional_inputs(self):
        """Test with more than two additional inputs."""
        password = b"multiFactorPass"
        additional_inputs = [b"factorA", b"factorB", b"factorC", b"factorD"]
        
        key_argon2, salt_argon2 = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(key_argon2), 32)

        key_pbkdf2, salt_pbkdf2 = derive_key(password, additional_inputs, method="PBKDF2")
        self.assertEqual(len(key_pbkdf2), 32)

    def test_invalid_inputs_raise_valueerror(self):
        """Test ValueError for invalid input types or unsupported method."""
        # Non-bytes password
        with self.assertRaisesRegex(ValueError, "Password must be bytes."):
            derive_key("not_bytes", [b"a"], method="Argon2id")
        
        # Non-bytes in additional_inputs
        with self.assertRaisesRegex(ValueError, "All additional_inputs must be a list of byte strings."):
            derive_key(b"pass", ["not_bytes_either"], method="Argon2id")
        with self.assertRaisesRegex(ValueError, "All additional_inputs must be a list of byte strings."):
            derive_key(b"pass", [b"valid", "invalid"], method="Argon2id")

        # Not a list for additional_inputs
        with self.assertRaisesRegex(ValueError, "All additional_inputs must be a list of byte strings."):
            derive_key(b"pass", b"not_a_list", method="Argon2id")
            
        # Unsupported method
        with self.assertRaisesRegex(ValueError, "Unsupported KDF method: InvalidMethod"):
            derive_key(b"pass", [b"a"], method="InvalidMethod")

    def test_edge_case_empty_password(self):
        """Test with an empty password (should still derive a key)."""
        password = b""
        additional_inputs = [b"some_factor"]
        # Argon2 and PBKDF2 should handle empty passwords, though not recommended practice.
        key_argon2, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(key_argon2), 32)

        key_pbkdf2, _ = derive_key(password, additional_inputs, method="PBKDF2")
        self.assertEqual(len(key_pbkdf2), 32)

    def test_edge_case_large_additional_input(self):
        """Test with a large additional input (e.g., 1KB)."""
        password = b"largeInputPass"
        # SHA-256 should handle large inputs fine for factors_hash.
        large_factor = os.urandom(1024) # 1KB
        additional_inputs = [b"small_factor", large_factor]
        
        key_argon2, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(key_argon2), 32)

        key_pbkdf2, _ = derive_key(password, additional_inputs, method="PBKDF2")
        self.assertEqual(len(key_pbkdf2), 32)

    # --- Integration Test ---
    def test_integration_with_aes_encryption(self):
        """
        Integration test: Use the derived key with AES-256-CBC to encrypt
        and decrypt sample data successfully.
        """
        password = b"integrationTestPass"
        additional_inputs = [b"integration_factor"]
        plaintext = b"This is some data to encrypt for the integration test."

        # Test with Argon2id derived key
        derived_key_argon2, _ = derive_key(password, additional_inputs, method="Argon2id")
        self.assertEqual(len(derived_key_argon2), 32)
        
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
        derived_key_pbkdf2, _ = derive_key(password, additional_inputs, method="PBKDF2")
        self.assertEqual(len(derived_key_pbkdf2), 32)

        iv_pbkdf2 = os.urandom(16) # Use a new IV
        cipher_pbkdf2 = Cipher(algorithms.AES(derived_key_pbkdf2), modes.CBC(iv_pbkdf2))

        padder_pbkdf2 = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data_pbkdf2 = padder_pbkdf2.update(plaintext) + padder_pbkdf2.finalize()
        encryptor_pbkdf2 = cipher_pbkdf2.encryptor() # Typo here, should be cipher_pbkdf2
        ciphertext_pbkdf2 = encryptor_pbkdf2.update(padded_data_pbkdf2) + encryptor_pbkdf2.finalize()
        
        decryptor_pbkdf2 = cipher_pbkdf2.decryptor()
        decrypted_padded_pbkdf2 = decryptor_pbkdf2.update(ciphertext_pbkdf2) + decryptor_pbkdf2.finalize()
        unpadder_pbkdf2 = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_plaintext_pbkdf2 = unpadder_pbkdf2.update(decrypted_padded_pbkdf2) + unpadder_pbkdf2.finalize()

        self.assertEqual(decrypted_plaintext_pbkdf2, plaintext, "AES integration failed for PBKDF2 key.")

if __name__ == "__main__":
    unittest.main()