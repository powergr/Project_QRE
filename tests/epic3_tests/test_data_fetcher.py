# hybrid_cipher_project/tests/epic3_tests/test_data_fetcher.py
import unittest
from unittest.mock import patch, mock_open, MagicMock
import json
import os
from datetime import datetime, timezone, timedelta # Ensure timezone is imported
# Adjust import path based on your project structure and how you run tests
from epic3_entropy_anchoring.data_fetcher import (
    fetch_latest_xray_flares, 
    save_flare_data,
    DEFAULT_SOLAR_FLARES_FILE # Ensure this is correctly defined in data_fetcher.py
)
import requests # For requests.exceptions

# For tests that might write files, use a dedicated temp area if needed,
# but for save_flare_data, we'll mock 'open' and 'json.dump'.

class TestDataFetcher(unittest.TestCase):

    @patch('epic3_entropy_anchoring.data_fetcher.requests.get')
    def test_fetch_latest_xray_flares_success(self, mock_get):
        """Test successful fetching of flare data."""
        mock_response_data = [{"time_tag": "2023-01-01T00:00:00Z", "satellite": 18, "current_class": "C1.0"}]
        mock_response = MagicMock()
        mock_response.json.return_value = mock_response_data
        mock_response.raise_for_status = MagicMock() 
        mock_get.return_value = mock_response

        data = fetch_latest_xray_flares()
        self.assertIsNotNone(data)
        self.assertEqual(data, mock_response_data)
        mock_get.assert_called_once_with(
            "https://services.swpc.noaa.gov/json/goes/primary/xray-flares-latest.json",
            timeout=10
        )

    @patch('epic3_entropy_anchoring.data_fetcher.requests.get')
    def test_fetch_latest_xray_flares_http_error(self, mock_get):
        """Test handling of HTTP errors during fetch."""
        mock_response = MagicMock()
        # Configure the mock response object for the status_code attribute used in error message
        mock_response.status_code = 404 
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("Test HTTP Error", response=mock_response)
        mock_get.return_value = mock_response
        
        data = fetch_latest_xray_flares()
        self.assertIsNone(data)

    @patch('epic3_entropy_anchoring.data_fetcher.requests.get')
    def test_fetch_latest_xray_flares_connection_error(self, mock_get):
        """Test handling of connection errors."""
        mock_get.side_effect = requests.exceptions.ConnectionError("Test Connection Error")
        data = fetch_latest_xray_flares()
        self.assertIsNone(data)

    @patch('epic3_entropy_anchoring.data_fetcher.requests.get')
    def test_fetch_latest_xray_flares_timeout(self, mock_get):
        """Test handling of timeout errors."""
        mock_get.side_effect = requests.exceptions.Timeout("Test Timeout Error")
        data = fetch_latest_xray_flares()
        self.assertIsNone(data)
        
    @patch('epic3_entropy_anchoring.data_fetcher.requests.get')
    def test_fetch_latest_xray_flares_json_decode_error(self, mock_get):
        """Test handling of JSON decoding errors."""
        mock_response = MagicMock()
        mock_response.json.side_effect = json.JSONDecodeError("Test JSON Error", "doc", 0)
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        data = fetch_latest_xray_flares()
        self.assertIsNone(data)

    def test_save_flare_data_success(self):
        """Test successful saving of flare data using mock_open."""
        sample_data = [{"time_tag": "2023-01-01T01:00:00Z", "satellite": 18, "current_class": "M1.5"}]
        
        m = mock_open()
        with patch('builtins.open', m):
            with patch('json.dump') as mock_json_dump:
                result = save_flare_data(sample_data, filename="dummy_test_output.json")
                self.assertTrue(result)
                m.assert_called_once_with("dummy_test_output.json", 'w', encoding='utf-8')
                
                # Check the structure of the object passed to json.dump
                args_list = mock_json_dump.call_args_list
                self.assertEqual(len(args_list), 1) # Should be called once
                call_args = args_list[0][0] # Get positional arguments of the first call
                
                saved_object = call_args[0] # The object to be dumped
                self.assertIn("retrieved_at_utc", saved_object)
                self.assertIn("flare_data_source", saved_object)
                self.assertEqual(saved_object["data_entries"], sample_data)
                # Verify timestamp is recent (optional, but good)
                saved_time = datetime.fromisoformat(saved_object["retrieved_at_utc"])
                self.assertTrue(datetime.now(timezone.utc) - saved_time < timedelta(seconds=5))


    def test_save_flare_data_no_data(self):
        """Test saving when no data (None) is provided."""
        m = mock_open()
        with patch('builtins.open', m): # Mock open even if not expected to be called
            self.assertFalse(save_flare_data(None, filename="no_data_test.json"))
            m.assert_not_called()


    def test_save_flare_data_invalid_data_type(self):
        """Test saving with invalid data type (not a list)."""
        m = mock_open()
        with patch('builtins.open', m):
            self.assertFalse(save_flare_data({"not_a": "list"}, filename="invalid_data_test.json")) # type: ignore
            m.assert_not_called()

    @patch('builtins.open', side_effect=IOError("Simulated write error"))
    def test_save_flare_data_io_error(self, mock_file_open_ioerror):
        """Test handling of IOError during file save."""
        sample_data = [{"time_tag": "2023-01-01T01:00:00Z"}]
        result = save_flare_data(sample_data, filename="io_error_test.json")
        self.assertFalse(result)
        mock_file_open_ioerror.assert_called_once_with("io_error_test.json", 'w', encoding='utf-8')

if __name__ == '__main__':
    unittest.main()