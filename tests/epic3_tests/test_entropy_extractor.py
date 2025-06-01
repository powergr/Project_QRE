# hybrid_cipher_project/tests/epic3_tests/test_entropy_extractor.py
import unittest
import json
import os
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

# Adjust import path based on your project structure and how you run tests
from epic3_entropy_anchoring.entropy_extractor import (
    is_data_fresh_enough,
    contains_high_class_flares, # Assuming this is corrected in SUT
    extract_entropy_from_chaotic_data,
    entropy_quality_check, # Assuming this is corrected in SUT
    # DEFAULT_SOLAR_FLARES_FILE # Not directly used in these mock-based tests
)

class TestEntropyExtractor(unittest.TestCase):

    def test_is_data_fresh_enough(self):
        fresh_data = {"retrieved_at_utc": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()}
        stale_data = {"retrieved_at_utc": (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()}
        self.assertTrue(is_data_fresh_enough(fresh_data))
        self.assertFalse(is_data_fresh_enough(stale_data))
        self.assertFalse(is_data_fresh_enough(None)) # Test with None dataset
        self.assertFalse(is_data_fresh_enough({})) # No timestamp
        self.assertFalse(is_data_fresh_enough({"retrieved_at_utc": "invalid_date_format"}))
        z_suffix_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.assertTrue(is_data_fresh_enough({"retrieved_at_utc": z_suffix_time}))


    def test_contains_high_class_flares(self):
        """Test the corrected contains_high_class_flares logic."""
        # Assumes contains_high_class_flares in SUT is corrected to look for M/X
        # and use min_high_flares parameter correctly.
        data_with_m_flare = {"data_entries": [{"class_type": "M1.0"}, {"class_type": "C1.0"}]}
        data_with_x_flare = {"data_entries": [{"class_type": "X2.5"}]}
        data_only_c_flares = {"data_entries": [{"class_type": "C1.0"}, {"class_type": "B1.0"}]}
        data_empty_entries = {"data_entries": []}
        
        self.assertTrue(contains_high_class_flares(data_with_m_flare))
        self.assertTrue(contains_high_class_flares(data_with_x_flare))
        self.assertFalse(contains_high_class_flares(data_only_c_flares)) 
        self.assertFalse(contains_high_class_flares(data_empty_entries))
        self.assertFalse(contains_high_class_flares(None)) # Test with None dataset
        self.assertFalse(contains_high_class_flares({})) 
        
        two_m_flares = {"data_entries": [{"class_type": "M1.0"}, {"class_type": "M2.0"}]}
        self.assertTrue(contains_high_class_flares(two_m_flares, min_high_flares=1))
        self.assertTrue(contains_high_class_flares(two_m_flares, min_high_flares=2))
        self.assertFalse(contains_high_class_flares(data_with_m_flare, min_high_flares=2))

    @patch('epic3_entropy_anchoring.entropy_extractor.load_chaotic_data')
    def test_extract_entropy_success(self, mock_load_data):
        """Test successful entropy extraction when data is fresh and volatile."""
        mock_dataset = {
            "retrieved_at_utc": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "data_entries": [
                {"peak_time": "2023-01-01T12:00:00Z", "peak_cflux": 1.0e-6, "class_type": "M1.0"},
                {"peak_time": "2023-01-01T13:00:00Z", "peak_cflux": 2.0e-5, "class_type": "X1.5"}
            ]
        }
        mock_load_data.return_value = mock_dataset
        
        entropy = extract_entropy_from_chaotic_data(
            data_filename="dummy.json", # This is passed to load_chaotic_data by SUT
            required_freshness=True,
            required_volatility=True
        )
        self.assertIsNotNone(entropy)
        self.assertEqual(len(entropy), 32) 
        self.assertTrue(entropy_quality_check(entropy))
        mock_load_data.assert_called_once_with("dummy.json") # SUT calls load_chaotic_data with this

    @patch('epic3_entropy_anchoring.entropy_extractor.load_chaotic_data')
    def test_extract_entropy_returns_none_if_stale(self, mock_load_data):
        mock_dataset = {
            "retrieved_at_utc": (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat(),
            "data_entries": [{"class_type": "M1.0"}]
        }
        mock_load_data.return_value = mock_dataset
        entropy = extract_entropy_from_chaotic_data(
            data_filename="dummy.json", required_freshness=True, required_volatility=True
        )
        self.assertIsNone(entropy)
        mock_load_data.assert_called_once_with("dummy.json")


    @patch('epic3_entropy_anchoring.entropy_extractor.load_chaotic_data')
    def test_extract_entropy_returns_none_if_not_volatile(self, mock_load_data):
        mock_dataset = {
            "retrieved_at_utc": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "data_entries": [{"class_type": "C1.0"}] # Assumes corrected contains_high_class_flares
        }
        mock_load_data.return_value = mock_dataset
        entropy = extract_entropy_from_chaotic_data(
            data_filename="dummy.json", required_freshness=True, required_volatility=True
        )
        self.assertIsNone(entropy)
        mock_load_data.assert_called_once_with("dummy.json")


    @patch('epic3_entropy_anchoring.entropy_extractor.load_chaotic_data')
    def test_extract_entropy_returns_none_if_no_data_loaded(self, mock_load_data):
        mock_load_data.return_value = None 
        entropy = extract_entropy_from_chaotic_data(data_filename="dummy.json")
        self.assertIsNone(entropy)
        mock_load_data.assert_called_once_with("dummy.json")


    @patch('epic3_entropy_anchoring.entropy_extractor.load_chaotic_data')
    def test_extract_entropy_no_processable_events(self, mock_load_data):
        mock_dataset = {
            "retrieved_at_utc": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "data_entries": [] 
        }
        mock_load_data.return_value = mock_dataset
        entropy = extract_entropy_from_chaotic_data(
            data_filename="dummy.json", required_freshness=False, required_volatility=False
        ) # Turn off checks to ensure it's the lack of events causing None
        self.assertIsNone(entropy)
        mock_load_data.assert_called_once_with("dummy.json")

    def test_entropy_quality_check(self):
        """Test the corrected entropy_quality_check."""
        # Assumes entropy_quality_check in SUT is corrected
        good_entropy = os.urandom(32) 
        bad_entropy_short = b'\x00\x01\x02'
        bad_entropy_all_same = b'\xAA' * 32
        bad_entropy_low_unique = bytes([i // 2 for i in range(32)]) # 16 unique values

        self.assertTrue(entropy_quality_check(good_entropy))
        self.assertFalse(entropy_quality_check(None))
        self.assertFalse(entropy_quality_check(b"")) 
        self.assertFalse(entropy_quality_check(bad_entropy_short)) 
        self.assertFalse(entropy_quality_check(bad_entropy_all_same))
        self.assertFalse(entropy_quality_check(bad_entropy_low_unique)) 
        self.assertTrue(entropy_quality_check(bytes(range(32))))

if __name__ == '__main__':
    unittest.main()