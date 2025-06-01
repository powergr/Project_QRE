# hybrid_cipher_project/epic3_entropy_anchoring/data_fetcher.py
"""
Fetches solar flare data from the NOAA GOES X-ray flare API
and saves it locally with a timestamp.
"""
import requests
import json
# import time # Not strictly used in this version, but often useful for API interactions
from datetime import datetime, timezone # Use timezone-aware datetime
import os # For path operations

# Default filename for storing the fetched data
DEFAULT_SOLAR_FLARES_FILE = "solar_flares_data.json"

def fetch_latest_xray_flares(timeout_seconds: int = 10) -> list | None:
    """
    Fetches the latest GOES primary X-ray flare data from NOAA.

    Args:
        timeout_seconds: Timeout for the HTTP request in seconds.

    Returns:
        A list of flare data dictionaries if successful, None otherwise.
    """
    base_url = "https://services.swpc.noaa.gov/json/goes/primary/xray-flares-latest.json"
    print(f"Fetching data from: {base_url}")
    try:
        response = requests.get(base_url, timeout=timeout_seconds)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching data: {http_err} - Status: {response.status_code if 'response' in locals() and hasattr(response, 'status_code') else 'N/A'}")
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    except requests.exceptions.Timeout as timeout_err:
        print(f"Request timed out: {timeout_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"An unexpected error occurred during data fetching: {req_err}")
    except json.JSONDecodeError as json_err: # Catch JSON decoding errors
        print(f"Error decoding JSON response: {json_err}")
    return None

def save_flare_data(data: list | None, filename: str = DEFAULT_SOLAR_FLARES_FILE) -> bool:
    """
    Saves the fetched flare data to a JSON file, along with a retrieval timestamp.

    Args:
        data: The list of flare data to save. Can be None.
        filename: The name of the file to save the data to.

    Returns:
        True if saving was successful, False otherwise.
    """
    if data is None:
        print("No data provided to save.")
        return False
    if not isinstance(data, list): # Ensure data is a list if not None
        print("Invalid data format; expected a list of flare entries.")
        return False

    timestamp_utc = datetime.now(timezone.utc).isoformat()
    
    data_to_save = {
        "retrieved_at_utc": timestamp_utc,
        "flare_data_source": "NOAA GOES Primary X-ray Flares (latest)",
        "data_entries": data
    }

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data_to_save, f, indent=4)
        print(f"Data saved successfully to '{filename}' at {timestamp_utc}")
        return True
    except IOError as io_err:
        print(f"Error writing data to file '{filename}': {io_err}")
    except Exception as e:
        print(f"An unexpected error occurred while saving data: {e}")
    return False

if __name__ == "__main__":
    print("--- Solar Flare Data Fetcher ---")
    
    # Determine path to save file within the same directory as this script
    script_dir = "."
    if "__file__" in locals(): # Check if __file__ is defined (not in some interactive environments)
        script_dir = os.path.dirname(os.path.abspath(__file__))
    
    output_filename = os.path.join(script_dir, DEFAULT_SOLAR_FLARES_FILE)
    
    print(f"Output file will be: {output_filename}")

    latest_flares = fetch_latest_xray_flares()
    
    if latest_flares is not None: # Check explicitly for None
        if save_flare_data(latest_flares, filename=output_filename):
            print("Process completed: Data fetched and saved.")
        else:
            print("Process completed: Data fetched but failed to save.")
    else:
        print("Process completed: No data was retrieved from NOAA.")