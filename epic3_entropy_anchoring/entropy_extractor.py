# hybrid_cipher_project/epic3_entropy_anchoring/entropy_extractor.py
"""
Extracts cryptographic entropy from stored chaotic data (e.g., solar flares)
using SHA3-256 and performs basic quality checks.
"""
import hashlib
import json
import os
from datetime import datetime, timezone, timedelta

try:
    # Relative import for when this module is part of the package
    from .data_fetcher import DEFAULT_SOLAR_FLARES_FILE
except ImportError: 
    # Fallback for direct execution or if relative import fails (e.g. running script directly)
    DEFAULT_SOLAR_FLARES_FILE = "solar_flares_data.json"

MAX_DATA_AGE_HOURS = 24

def load_chaotic_data(data_file_path: str) -> dict | None: # Takes full path now
    """Loads the chaotic data from the specified JSON file path."""
    if not os.path.exists(data_file_path):
        # print(f"Data file '{data_file_path}' not found.")
        return None
    try:
        with open(data_file_path, 'r', encoding='utf-8') as f:
            dataset = json.load(f)
        return dataset
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading or parsing data file '{data_file_path}': {e}")
    except Exception as e:
        print(f"An unexpected error occurred loading data from '{data_file_path}': {e}")
    return None

def is_data_fresh_enough(dataset: dict | None) -> bool:
    """Checks if the dataset timestamp is within an acceptable age."""
    if not dataset or "retrieved_at_utc" not in dataset:
        return False
    try:
        timestamp_str = dataset["retrieved_at_utc"]
        if timestamp_str.endswith('Z'): 
            timestamp_str = timestamp_str[:-1] + '+00:00'
        
        data_timestamp = datetime.fromisoformat(timestamp_str)
        if data_timestamp.tzinfo is None: # Ensure timezone aware
            data_timestamp = data_timestamp.replace(tzinfo=timezone.utc)

        current_time_utc = datetime.now(timezone.utc)
        age = current_time_utc - data_timestamp
        return age < timedelta(hours=MAX_DATA_AGE_HOURS)
    except Exception as e:
        print(f"Error processing data timestamp '{dataset.get('retrieved_at_utc')}': {e}")
        return False

def contains_high_class_flares(dataset: dict | None, min_high_flares: int = 1) -> bool:
    """
    Checks if the dataset contains a minimum number of high-class (M or X) solar flares.
    """
    if not dataset or "data_entries" not in dataset or not isinstance(dataset["data_entries"], list):
        return False
    
    flare_entries = dataset["data_entries"]
    if not flare_entries and min_high_flares > 0: # No flares but expecting some
        return False
    if min_high_flares <= 0: # If 0 or negative are requested, trivially true if flare_entries exists
        return True

    high_flare_count = 0
    for flare in flare_entries:
        if isinstance(flare, dict) and "class_type" in flare and isinstance(flare["class_type"], str):
            if flare["class_type"].startswith("M") or flare["class_type"].startswith("X"):
                high_flare_count += 1
    
    return high_flare_count >= min_high_flares

def entropy_quality_check(entropy_bytes: bytes | None) -> bool:
    """
    Performs basic validation on the extracted entropy bytes (typically a hash digest).
    """
    if not entropy_bytes or len(entropy_bytes) < 16: # Minimum sensible length for entropy
        return False
    
    unique_byte_values = len(set(entropy_bytes))
    
    # For a 32-byte (256-bit) hash output, expect high entropy.
    # Threshold: e.g., at least 20 unique byte values for a 32-byte string.
    # For shorter strings, this threshold might be relaxed proportionally or set differently.
    min_unique_required = 0
    if len(entropy_bytes) >= 32:
        min_unique_required = 20 
    elif len(entropy_bytes) >= 16:
        min_unique_required = 10 
    else: # For very short byte strings, this check is less meaningful but ensure some uniqueness
        min_unique_required = len(entropy_bytes) // 2 

    if unique_byte_values < min_unique_required:
        # print(f"Quality check failed: Insufficient unique bytes ({unique_byte_values}/{len(entropy_bytes)}, needed {min_unique_required}).")
        return False
    
    # Check if it's not all the same byte (already somewhat covered by unique check if min_unique_required > 1)
    if len(entropy_bytes) > 1 and len(set(entropy_bytes)) == 1:
        # print(f"Quality check failed: Entropy consists of a single repeated byte value.")
        return False
        
    return True

def extract_entropy_from_chaotic_data(
    # data_file_relative_to_script is now just data_filename, assuming it's in a known location
    # or an absolute path is passed by EntropyManager.
    # The SUT (System Under Test) will construct the full path.
    data_filename: str = DEFAULT_SOLAR_FLARES_FILE,
    required_freshness: bool = True,
    required_volatility: bool = True 
    ) -> bytes | None:
    """
    Extracts entropy from a chaotic data file if data is fresh and volatile enough.
    The file path is constructed relative to this script's directory.

    Args:
        data_filename: Filename of the JSON data (e.g., "solar_flares_data.json").
                       This function expects it to be in the same directory as this script
                       or an absolute path.
        required_freshness: If True, data must be within MAX_DATA_AGE_HOURS.
        required_volatility: If True, data must pass contains_high_class_flares check.

    Returns:
        SHA3-256 hash (32 bytes) of processed data as entropy, or None.
    """
    # Path construction: assumes data_filename is either absolute or relative to cwd.
    # For module usage, the caller (EntropyManager) should resolve the path.
    # This function will now assume data_filename *is the path to use*.
    # The default DEFAULT_SOLAR_FLARES_FILE will be sought in the CWD if no path given.
    # Let's make it explicit that this function now needs a full path or a path
    # that 'load_chaotic_data' can find.
    # For simplicity, let's assume 'data_filename' is the direct path.
    
    # This script_dir logic is more for the __main__ block of this file.
    # script_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."
    # full_data_file_path = os.path.join(script_dir, data_filename)
    # For use by EntropyManager, it's better if EntropyManager resolves the path fully.
    # So, we'll just use `data_filename` as the path here.

    dataset = load_chaotic_data(data_filename) # Assumes data_filename is a usable path
    if not dataset:
        return None

    if required_freshness and not is_data_fresh_enough(dataset):
        print(f"Data in '{data_filename}' is considered stale (older than {MAX_DATA_AGE_HOURS} hours).")
        return None
    
    if required_volatility and not contains_high_class_flares(dataset):
        print(f"Data in '{data_filename}' did not meet volatility criteria.")
        return None

    entropy_input_str_parts = []
    if "data_entries" in dataset and isinstance(dataset["data_entries"], list):
        for flare_event in dataset["data_entries"]:
            if isinstance(flare_event, dict):
                peak_time = flare_event.get("peak_time", "")
                peak_cflux = str(flare_event.get("peak_cflux", 0.0)) 
                class_type = flare_event.get("class_type", "")
                entropy_input_str_parts.append(peak_time)
                entropy_input_str_parts.append(peak_cflux)
                entropy_input_str_parts.append(class_type)
    
    if not entropy_input_str_parts:
        # print("No processable flare event data found to build entropy input.")
        return None

    full_entropy_input_string = "".join(entropy_input_str_parts)
    entropy_input_bytes = full_entropy_input_string.encode('utf-8', 'ignore')

    extracted_bytes = hashlib.sha3_256(entropy_input_bytes).digest()
    
    if entropy_quality_check(extracted_bytes):
        return extracted_bytes
    else:
        # print(f"Extracted entropy from '{data_filename}' failed basic quality check.")
        return None

if __name__ == "__main__":
    print("\n--- Entropy Extractor Demonstration ---")
    # This __main__ block assumes 'solar_flares_data.json' is in the same directory
    # as this script when run directly.
    script_dir_main = os.path.dirname(os.path.abspath(__file__)) if "__file__" in locals() else "."
    data_file_for_demo = os.path.join(script_dir_main, DEFAULT_SOLAR_FLARES_FILE)
    
    if not os.path.exists(data_file_for_demo):
        print(f"\n'{data_file_for_demo}' not found.")
        print("Please run 'data_fetcher.py' first to download solar flare data (it should save it here).")
    else:
        print(f"\nAttempting to extract entropy from '{data_file_for_demo}' (relative to this script)...")
        entropy = extract_entropy_from_chaotic_data(
            data_filename=data_file_for_demo, # Pass the full path for clarity here
            required_freshness=False, 
            required_volatility=False
        )
        if entropy:
            print(f"Successfully extracted entropy (SHA3-256 digest): {entropy.hex()}")
        else:
            print("Failed to extract quality entropy from the data file for demo.")