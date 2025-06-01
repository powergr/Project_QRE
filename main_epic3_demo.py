# hybrid_cipher_project/main_epic3_demo.py
"""
Main demonstration script for Epic 3: Entropy Anchoring.
This script shows the conceptual flow:
1. (Assumes data_fetcher.py has run to create solar_flares_data.json)
2. Uses EntropyManager (which internally uses entropy_extractor and secure_prng)
3. Uses key_generator_anchored to derive keys.
"""
import os
# Assuming this script is run from the project root (hybrid_cipher_project/)
from epic3_entropy_anchoring.key_generator_anchored import (
    generate_key_pbkdf2_anchored, 
    generate_key_hkdf_anchored
)
from epic3_entropy_anchoring.secure_prng import EntropyManager # For direct demo if needed
from epic3_entropy_anchoring.data_fetcher import fetch_latest_xray_flares, save_flare_data, DEFAULT_SOLAR_FLARES_FILE
from epic3_entropy_anchoring.entropy_extractor import extract_entropy_from_chaotic_data

def run_epic3_demonstration():
    print("=" * 60)
    print(" Epic 3: Entropy Anchoring Demonstration")
    print("=" * 60)

    # --- Part 1: Ensure Chaotic Data is Available (Simulate a recent fetch) ---
    # In a real system, data_fetcher.py would run on a schedule.
    # For this demo, we'll try to fetch it if the file is missing or very old,
    # but primarily rely on an existing file.

    # Determine path for the data file within the epic3 package
    # This assumes main_epic3_demo.py is in the project root.
    epic3_pkg_dir = os.path.join(os.path.dirname(__file__), "epic3_entropy_anchoring")
    solar_data_filepath = os.path.join(epic3_pkg_dir, DEFAULT_SOLAR_FLARES_FILE)
    
    print(f"\nChecking for chaotic data file: {solar_data_filepath}")
    if not os.path.exists(solar_data_filepath): # Basic check, could add age check too
        print("Solar flare data file not found. Attempting to fetch fresh data...")
        flare_data = fetch_latest_xray_flares()
        if flare_data:
            save_flare_data(flare_data, filename=solar_data_filepath)
        else:
            print("Could not fetch fresh solar flare data. Entropy anchoring might rely on PRNG fallback.")
    else:
        print("Existing solar flare data file found.")
        # Optionally, add logic here to re-fetch if existing data is too old.

    # --- Part 2: Demonstrate EntropyManager (which uses extractor and PRNG) ---
    print("\n--- Demonstrating EntropyManager ---")
    # EntropyManager will try to use the data file specified by its default.
    # It needs to know where entropy_extractor expects the file.
    # The current entropy_extractor builds the path from its own location.
    # So, this should work if solar_data_filepath is correctly placed by data_fetcher.
    
    # Note: EntropyManager is instantiated inside key_generator functions.
    # We can also instantiate it here for a direct demo of get_entropy.
    try:
        print("Initializing EntropyManager (will attempt to load chaotic data)...")
        entropy_mgr_demo = EntropyManager(chaotic_data_file_path=DEFAULT_SOLAR_FLARES_FILE)
        
        print("\nRequesting 16 bytes of entropy from manager (might be chaotic or PRNG):")
        entropy_sample1 = entropy_mgr_demo.get_entropy(16)
        print(f"Sample 1 (16B): {entropy_sample1.hex()}")

        print("\nRequesting another 16 bytes (will be PRNG if chaotic was used once):")
        entropy_sample2 = entropy_mgr_demo.get_entropy(16)
        print(f"Sample 2 (16B): {entropy_sample2.hex()}")
        if entropy_sample1 != entropy_sample2:
            print("Note: Sample 1 and 2 differ, as expected.")
        
        print("\nRequesting 32 bytes (likely PRNG, or full chaotic digest if first call):")
        entropy_sample3 = entropy_mgr_demo.get_entropy(32)
        print(f"Sample 3 (32B): {entropy_sample3.hex()}")

    except Exception as e:
        print(f"Error during EntropyManager demonstration: {e}")


    # --- Part 3: Demonstrate Anchored Key Generation ---
    print("\n--- Demonstrating Anchored Key Generation ---")
    
    password_for_kdf = b"myComplexPasswordWithSymbols!@#"
    user_provided_salt_component = os.urandom(16) # For PBKDF2 example
    initial_key_material_for_hkdf = os.urandom(32) # For HKDF example
    hkdf_salt_val = os.urandom(32) # SHA256 digest size for HKDF salt
    hkdf_info_val = b"user_auth_key_generation"

    print(f"\nPassword (example): {password_for_kdf.decode(errors='ignore')}")

    print("\n1. PBKDF2 Anchored Key Generation (with user salt component):")
    try:
        pbkdf2_key1 = generate_key_pbkdf2_anchored(password_for_kdf, salt=user_provided_salt_component)
        print(f"   Derived PBKDF2 Key 1 (32B): {pbkdf2_key1.hex()}")
    except Exception as e:
        print(f"   Error generating PBKDF2 Key 1: {e}")

    print("\n2. PBKDF2 Anchored Key Generation (auto salt component):")
    try:
        pbkdf2_key2 = generate_key_pbkdf2_anchored(password_for_kdf) # Will generate internal base_salt
        print(f"   Derived PBKDF2 Key 2 (32B): {pbkdf2_key2.hex()}")
        if 'pbkdf2_key1' in locals() and pbkdf2_key1 != pbkdf2_key2:
            print("   Note: Key 1 and Key 2 differ due to different salt components, as expected.")
    except Exception as e:
        print(f"   Error generating PBKDF2 Key 2: {e}")


    print(f"\n\nInitial Key Material for HKDF (example): {initial_key_material_for_hkdf.hex()}")
    print("\n3. HKDF Anchored Key Generation (with user HKDF salt & info):")
    try:
        hkdf_key1 = generate_key_hkdf_anchored(
            initial_key_material_for_hkdf, 
            salt=hkdf_salt_val, 
            info_context=hkdf_info_val
        )
        print(f"   Derived HKDF Key 1 (32B): {hkdf_key1.hex()}")
    except Exception as e:
        print(f"   Error generating HKDF Key 1: {e}")
        
    print("\n4. HKDF Anchored Key Generation (auto HKDF salt, with info):")
    try:
        # HKDF salt will be os.urandom() inside the function if salt=None
        hkdf_key2 = generate_key_hkdf_anchored(initial_key_material_for_hkdf, info_context=hkdf_info_val)
        print(f"   Derived HKDF Key 2 (32B): {hkdf_key2.hex()}")
        if 'hkdf_key1' in locals() and hkdf_key1 != hkdf_key2:
            print("   Note: Key 1 and Key 2 differ due to different HKDF salts, as expected.")
    except Exception as e:
        print(f"   Error generating HKDF Key 2: {e}")

    print("\n--- End of Epic 3 Demonstration ---")


if __name__ == "__main__":
    run_epic3_demonstration()