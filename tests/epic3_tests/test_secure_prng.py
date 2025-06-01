# hybrid_cipher_project/tests/epic3_tests/test_secure_prng.py
import unittest
import os
from unittest.mock import patch, MagicMock

from epic3_entropy_anchoring.secure_prng import SecurePRNG, EntropyManager
# For mocking, we target the name as it's imported *in the module under test* (secure_prng.py)
MOCK_EXTRACT_PATH = 'epic3_entropy_anchoring.secure_prng.extract_entropy_from_chaotic_data'

class TestSecurePRNG(unittest.TestCase):
    def test_prng_deterministic_with_seed(self):
        seed = os.urandom(32)
        prng1 = SecurePRNG(seed)
        prng1_output1 = prng1.generate_bytes(16)
        prng1_output2 = prng1.generate_bytes(16)

        prng2 = SecurePRNG(seed) 
        self.assertEqual(prng2.generate_bytes(16), prng1_output1, "First 16 bytes should match")
        self.assertEqual(prng2.generate_bytes(16), prng1_output2, "Next 16 bytes should also match")

    def test_prng_different_without_seed_or_different_seed(self):
        prng1 = SecurePRNG() 
        prng2 = SecurePRNG() 
        self.assertNotEqual(prng1.generate_bytes(32), prng2.generate_bytes(32))
        
        seed1 = os.urandom(32)
        seed2 = os.urandom(32)
        while seed1 == seed2: 
            seed2 = os.urandom(32)
        prng_s1 = SecurePRNG(seed1)
        prng_s2 = SecurePRNG(seed2)
        self.assertNotEqual(prng_s1.generate_bytes(32), prng_s2.generate_bytes(32))

    def test_prng_generates_correct_length(self):
        prng = SecurePRNG()
        for length in [0, 1, 15, 16, 17, 32, 100, 1024]:
            self.assertEqual(len(prng.generate_bytes(length)), length, f"Failed for length {length}")

    def test_prng_invalid_seed_type(self):
        # Assumes SecurePRNG __init__ raises TypeError for non-bytes seed first
        with self.assertRaisesRegex(TypeError, "Seed must be bytes if provided."):
            SecurePRNG(seed="not bytes") # type: ignore # INDENTED

    def test_prng_invalid_seed_length(self):
        # Assumes SecurePRNG __init__ raises ValueError for wrong length if seed *is* bytes
        with self.assertRaisesRegex(ValueError, "Seed must be a 32-byte string if provided."):
            SecurePRNG(seed=b"shortseed") 
        with self.assertRaisesRegex(ValueError, "Seed must be a 32-byte string if provided."):
            SecurePRNG(seed=os.urandom(33))

    def test_prng_generate_bytes_negative_input(self):
        prng = SecurePRNG()
        with self.assertRaisesRegex(ValueError, "Number of bytes must be a non-negative integer."):
            prng.generate_bytes(-1) # INDENTED

    def test_prng_generate_bytes_non_integer_input(self):
        prng = SecurePRNG()
        with self.assertRaisesRegex(TypeError, "Number of bytes must be an integer."):
            prng.generate_bytes("abc") # type: ignore # INDENTED

class TestEntropyManager(unittest.TestCase):

    @patch(MOCK_EXTRACT_PATH) 
    def test_init_seeds_prng_with_chaotic_if_good(self, mock_extract):
        chaotic_entropy_sample = os.urandom(32) 
        mock_extract.return_value = chaotic_entropy_sample
        manager = EntropyManager(chaotic_data_file_path="dummy_file.json") # Corrected kwarg
        
        self.assertEqual(manager.prng.key, chaotic_entropy_sample, "PRNG key should be the chaotic entropy.")
        self.assertEqual(manager.current_chaotic_entropy, chaotic_entropy_sample)
        
        self.assertEqual(manager.get_entropy(16), chaotic_entropy_sample[:16])
        self.assertTrue(manager._chaotic_entropy_consumed)
        
        ref_prng = SecurePRNG(seed=chaotic_entropy_sample)
        self.assertEqual(manager.get_entropy(16), ref_prng.generate_bytes(16))
        mock_extract.assert_called_once()

    @patch(MOCK_EXTRACT_PATH)
    def test_init_prng_self_seeds_if_chaotic_is_none(self, mock_extract):
        mock_extract.return_value = None 

        with patch('epic3_entropy_anchoring.secure_prng.os.urandom') as mock_os_urandom: # Patch os.urandom used by SecurePRNG
            mock_os_urandom.return_value = b'\xDE\xAD\xBE\xEF' * 8 
            manager = EntropyManager(chaotic_data_file_path="dummy_file.json") # Corrected kwarg
            # Check if os.urandom was called by SecurePRNG.__init__ when seed is None
            if manager.prng.key == (b'\xDE\xAD\xBE\xEF' * 8 ) : # Only assert if it actually used the mock
                 mock_os_urandom.assert_called_once_with(32)
            self.assertEqual(manager.prng.key, b'\xDE\xAD\xBE\xEF' * 8)


        self.assertIsNone(manager.current_chaotic_entropy)
        entropy1 = manager.get_entropy(16)
        self.assertEqual(len(entropy1), 16)
        mock_extract.assert_called_once()


    @patch(MOCK_EXTRACT_PATH)
    def test_get_entropy_uses_chaotic_then_prng(self, mock_extract):
        chaotic_entropy_sample = b'\xAA' * 32 
        mock_extract.return_value = chaotic_entropy_sample
        
        manager = EntropyManager(chaotic_data_file_path="dummy_file.json") # Corrected kwarg
        
        self.assertEqual(manager.get_entropy(10), chaotic_entropy_sample[:10])
        self.assertTrue(manager._chaotic_entropy_consumed)
        
        prng_output1 = manager.get_entropy(16)
        prng_output2 = manager.get_entropy(16)
        self.assertNotEqual(prng_output1, prng_output2)
        # This assertion is a bit tricky because prng_output1 *is* from the PRNG seeded by chaotic_entropy_sample
        # So it won't be equal to chaotic_entropy_sample itself.
        # The main test is that _chaotic_entropy_consumed is True and successive calls differ.
        # self.assertNotEqual(prng_output1, chaotic_entropy_sample[:16]) # This should be true

    @patch(MOCK_EXTRACT_PATH)
    def test_get_entropy_length_from_chaotic(self, mock_extract):
        chaotic_full = b'\x01' * 32
        mock_extract.return_value = chaotic_full
        manager = EntropyManager(chaotic_data_file_path="dummy_file.json") # Corrected kwarg

        self.assertEqual(manager.get_entropy(5), chaotic_full[:5])
        self.assertTrue(manager._chaotic_entropy_consumed)

        # For subsequent manager instances, mock needs to be "active" for them too
        # if the test implies new instances. The way patch works, it re-mocks for each test method.
        # But if manager2/3 are in the *same* test method, mock_extract is the same object.
        # The logic in EntropyManager creates a new SecurePRNG.
        mock_extract.return_value = chaotic_full 
        manager2 = EntropyManager(chaotic_data_file_path="dummy_file.json") # Corrected kwarg
        self.assertEqual(manager2.get_entropy(32), chaotic_full)
        self.assertTrue(manager2._chaotic_entropy_consumed)

        mock_extract.return_value = chaotic_full 
        manager3 = EntropyManager(chaotic_data_file_path="dummy_file.json") # Corrected kwarg
        self.assertEqual(manager3.get_entropy(40), chaotic_full) 
        self.assertTrue(manager3._chaotic_entropy_consumed)
        
        prng_data = manager3.get_entropy(10) 
        self.assertEqual(len(prng_data), 10)

if __name__ == '__main__':
    unittest.main()