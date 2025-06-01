# hybrid_cipher_project/tests/epic3_tests/test_key_generator_anchored.py
import unittest
import os
from unittest.mock import patch, MagicMock

from epic3_entropy_anchoring.key_generator_anchored import (
    generate_key_pbkdf2_anchored,
    generate_key_hkdf_anchored,
    DEFAULT_KEY_LENGTH_BYTES
)
# No need to import PBKDF2_DEFAULT_ITERATIONS unless specifically testing against them.

MOCK_ENTROPY_MANAGER_PATH = 'epic3_entropy_anchoring.key_generator_anchored.EntropyManager'

class TestKeyGeneratorAnchored(unittest.TestCase):

    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_pbkdf2_anchored_basic_derivation(self, MockEntropyManager):
        password = b"testpassword_pbkdf2"
        mock_anchoring_entropy = os.urandom(16)
        
        mock_em_instance = MockEntropyManager.return_value # The instance created inside the KDF
        mock_em_instance.get_entropy.return_value = mock_anchoring_entropy
            
        key = generate_key_pbkdf2_anchored(password)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), DEFAULT_KEY_LENGTH_BYTES)
        mock_em_instance.get_entropy.assert_called_once_with(16) # For salt enhancement

    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_pbkdf2_anchored_with_user_salt(self, MockEntropyManager):
        password = b"testpassword_user_salt"
        user_salt = os.urandom(16)
        mock_anchoring_entropy = os.urandom(16)

        mock_em_instance = MockEntropyManager.return_value
        mock_em_instance.get_entropy.return_value = mock_anchoring_entropy
            
        key = generate_key_pbkdf2_anchored(password, salt=user_salt)
        self.assertEqual(len(key), 32)
        mock_em_instance.get_entropy.assert_called_once_with(16)


    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_pbkdf2_anchored_consistency(self, MockEntropyManager):
        password = b"consistency_pbkdf2"
        user_salt = os.urandom(16)
        fixed_anchoring_entropy = b'\xAA' * 16

        # Ensure get_entropy returns the same fixed value for both calls
        mock_em_instance = MockEntropyManager.return_value
        mock_em_instance.get_entropy.return_value = fixed_anchoring_entropy
            
        key1 = generate_key_pbkdf2_anchored(password, salt=user_salt)
        # The mock is for the class; a new instance is made each time generate_key is called.
        # So, the mock_em_instance.get_entropy will be configured for each new instance.
        key2 = generate_key_pbkdf2_anchored(password, salt=user_salt)
        self.assertEqual(key1, key2)

    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_pbkdf2_anchored_different_anchor_diff_key(self, MockEntropyManager):
        password = b"diff_anchor_pbkdf2"
        user_salt = os.urandom(16)

        # Make EntropyManager() return different mock instances for each call
        mock_instance1 = MagicMock()
        mock_instance1.get_entropy.return_value = b'\xAA' * 16
        
        mock_instance2 = MagicMock()
        mock_instance2.get_entropy.return_value = b'\xBB' * 16
            
        MockEntropyManager.side_effect = [mock_instance1, mock_instance2]
            
        key1 = generate_key_pbkdf2_anchored(password, salt=user_salt)
        key2 = generate_key_pbkdf2_anchored(password, salt=user_salt)
        self.assertNotEqual(key1, key2)


    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_hkdf_anchored_basic_derivation(self, MockEntropyManager):
        ikm = b"initial_key_material_hkdf"
        mock_anchoring_entropy = os.urandom(32) # HKDF uses 32 for IKM anchor

        mock_em_instance = MockEntropyManager.return_value
        mock_em_instance.get_entropy.return_value = mock_anchoring_entropy
            
        key = generate_key_hkdf_anchored(ikm)
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), DEFAULT_KEY_LENGTH_BYTES)
        mock_em_instance.get_entropy.assert_called_once_with(32) # For IKM enhancement

    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_hkdf_anchored_consistency(self, MockEntropyManager):
        ikm = b"hkdf_consistency_anchor"
        hkdf_salt = os.urandom(16)
        info = b"hkdf_info_anchor"
        fixed_anchoring_entropy = b'\xCC' * 32

        mock_em_instance = MockEntropyManager.return_value
        mock_em_instance.get_entropy.return_value = fixed_anchoring_entropy
            
        key1 = generate_key_hkdf_anchored(ikm, salt=hkdf_salt, info_context=info)
        key2 = generate_key_hkdf_anchored(ikm, salt=hkdf_salt, info_context=info)
        self.assertEqual(key1, key2)

    @patch(MOCK_ENTROPY_MANAGER_PATH)
    def test_hkdf_anchored_different_anchor_diff_key(self, MockEntropyManager):
        ikm = b"hkdf_diff_anchor_test"
        hkdf_salt = os.urandom(16)
        info = b"hkdf_info_diff_anchor"

        mock_instance1 = MagicMock()
        mock_instance1.get_entropy.return_value = b'\xCC' * 32
        
        mock_instance2 = MagicMock()
        mock_instance2.get_entropy.return_value = b'\xDD' * 32
            
        MockEntropyManager.side_effect = [mock_instance1, mock_instance2]
            
        key1 = generate_key_hkdf_anchored(ikm, salt=hkdf_salt, info_context=info)
        key2 = generate_key_hkdf_anchored(ikm, salt=hkdf_salt, info_context=info)
        self.assertNotEqual(key1, key2)

    def test_invalid_inputs_pbkdf2(self):
        with self.assertRaises(TypeError):
            generate_key_pbkdf2_anchored("not_bytes_pass") # type: ignore
        with self.assertRaises(ValueError): # Salt must be 16 bytes if provided
            generate_key_pbkdf2_anchored(b"password", salt=b"short") 

    def test_invalid_inputs_hkdf(self):
        with self.assertRaises(TypeError):
            generate_key_hkdf_anchored("not_bytes_ikm") # type: ignore
        with self.assertRaises(TypeError):
            generate_key_hkdf_anchored(b"ikm", salt="not_bytes_salt") # type: ignore
        with self.assertRaises(TypeError):
            generate_key_hkdf_anchored(b"ikm", info_context="not_bytes_info") # type: ignore

if __name__ == '__main__':
    unittest.main()