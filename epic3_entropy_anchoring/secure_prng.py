# hybrid_cipher_project/epic3_entropy_anchoring/secure_prng.py
"""
Provides a secure Pseudo-Random Number Generator (PRNG) based on AES-CTR
and an EntropyManager that combines chaotic entropy with this PRNG as a fallback.
"""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

try:
    from .entropy_extractor import extract_entropy_from_chaotic_data, DEFAULT_SOLAR_FLARES_FILE
except ImportError:
    # This case might occur if the script is run directly and not as part of the package
    # Or if the test environment doesn't correctly resolve relative package imports.
    # For production, ensure proper package structure and PYTHONPATH.
    print("Warning: Relative import for entropy_extractor failed in secure_prng.py. Using direct.")
    from entropy_extractor import extract_entropy_from_chaotic_data, DEFAULT_SOLAR_FLARES_FILE


class SecurePRNG:
    """
    A Pseudo-Random Number Generator based on AES-256 in Counter (CTR) mode.
    """
    def __init__(self, seed: bytes | None = None):
        if seed is not None:
            if not isinstance(seed, bytes): # Check type first
                raise TypeError("Seed must be bytes if provided.")
            if len(seed) != 32: # Then check length
                raise ValueError("Seed must be a 32-byte string if provided.")
            self.key = seed
        else:
            self.key = os.urandom(32)
        self.counter_int = 0

    def generate_bytes(self, num_bytes: int) -> bytes:
        if not isinstance(num_bytes, int):
            raise TypeError("Number of bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("Number of bytes must be a non-negative integer.")
        if num_bytes == 0:
            return b""

        output_bytes = bytearray()
        block_size = algorithms.AES.block_size // 8 

        while len(output_bytes) < num_bytes:
            nonce_counter_bytes = self.counter_int.to_bytes(16, 'big')
            cipher = Cipher(algorithms.AES(self.key), modes.CTR(nonce_counter_bytes))
            encryptor = cipher.encryptor()
            keystream_block = encryptor.update(b'\x00' * block_size) 
            output_bytes.extend(keystream_block)
            self.counter_int += 1
        return bytes(output_bytes[:num_bytes])

class EntropyManager:
    def __init__(self, chaotic_data_file_path: str | None = None):
        """
        Initializes the EntropyManager.
        Args:
            chaotic_data_file_path: Absolute or resolvable path to the chaotic data file.
                                     If None, uses a default path logic.
        """
        if chaotic_data_file_path is None:
            # Default path logic: assumes solar_flares_data.json is in the same dir as entropy_extractor.py
            # This needs to be robust. Let's get the dir of entropy_extractor.py
            try:
                import epic3_entropy_anchoring.entropy_extractor as ee_module
                extractor_module_dir = os.path.dirname(os.path.abspath(ee_module.__file__))
                self.chaotic_data_file_to_load = os.path.join(extractor_module_dir, DEFAULT_SOLAR_FLARES_FILE)
            except Exception: # Fallback if module path finding fails
                self.chaotic_data_file_to_load = DEFAULT_SOLAR_FLARES_FILE # Relative to CWD
        else:
            self.chaotic_data_file_to_load = chaotic_data_file_path

        # print(f"DEBUG [EntropyManager]: Initializing. Attempting to load chaotic data from '{self.chaotic_data_file_to_load}'...")
        self.current_chaotic_entropy = extract_entropy_from_chaotic_data(
            data_filename=self.chaotic_data_file_to_load, # Pass the determined path
            required_freshness=True,
            required_volatility=True
        )
        
        prng_seed = self.current_chaotic_entropy if self.current_chaotic_entropy else None
        if self.current_chaotic_entropy:
            # print("DEBUG [EntropyManager]: PRNG will be seeded with freshly extracted chaotic entropy.")
            pass
        else:
            # print("DEBUG [EntropyManager]: No fresh/quality chaotic entropy for PRNG seed. PRNG will use its own random seed.")
            pass
        self.prng = SecurePRNG(seed=prng_seed)
        self._chaotic_entropy_consumed = False

    def get_entropy(self, num_bytes: int) -> bytes:
        if not isinstance(num_bytes, int) or num_bytes < 0:
            raise ValueError("Number of bytes must be a non-negative integer.")
        if num_bytes == 0:
            return b""

        if self.current_chaotic_entropy and not self._chaotic_entropy_consumed:
            # print("DEBUG [EntropyManager]: Providing entropy directly from current chaotic source.")
            output = self.current_chaotic_entropy[:num_bytes]
            self._chaotic_entropy_consumed = True 
            if len(output) < num_bytes:
                print(f"Warning [EntropyManager]: Requested {num_bytes} from chaotic source, "
                      f"but only {len(output)} available (full digest). Using PRNG for remainder if needed by caller "
                      f"or caller should handle short read.")
            return output
        else:
            # print("DEBUG [EntropyManager]: Falling back to SecurePRNG.")
            return self.prng.generate_bytes(num_bytes)

if __name__ == '__main__':
    print("\n--- SecurePRNG & EntropyManager Demonstration ---")
    print("\nTesting SecurePRNG:")
    seed = os.urandom(32)
    prng1 = SecurePRNG(seed=seed)
    prng1.counter_int = 0 # Ensure starting counter
    random_data1_a = prng1.generate_bytes(16)
    prng1.counter_int = 0 # Reset for fair comparison if desired (or let it continue)
    random_data1_a_fresh_for_reseed_test = prng1.generate_bytes(16) # This is now the second block if counter not reset

    # Re-initialize with same seed should produce same sequence from its start
    prng1_reseeded = SecurePRNG(seed=seed) 
    random_data1_reseeded_a = prng1_reseeded.generate_bytes(16)
    assert random_data1_a == random_data1_reseeded_a, \
        "PRNG with same seed did not produce same initial output." # This will pass as both start from counter 0
    print(f"PRNG1 (seeded) sample 1: {random_data1_a.hex()}")
    print(f"PRNG1 (re-seeded) sample 1: {random_data1_reseeded_a.hex()} (should match)")

    # Check sequence
    random_data1_b = prng1.generate_bytes(16) # This is after random_data1_a_fresh_for_reseed_test
    print(f"PRNG1 (seeded) sample 2 (sequential): {random_data1_b.hex()}")
    assert random_data1_a != random_data1_b, "Seeded PRNG produced same output on successive calls"


    prng2 = SecurePRNG()
    random_data2 = prng2.generate_bytes(16)
    print(f"PRNG2 (unseeded) sample: {random_data2.hex()}")
    assert random_data1_a != random_data2, \
        "Seeded and unseeded PRNGs produced same output (highly unlikely)."

    print("\nTesting EntropyManager:")
    # Determine path to data file for the __main__ demo
    # Assumes solar_flares_data.json is in the same dir as entropy_extractor.py
    try:
        import epic3_entropy_anchoring.entropy_extractor as ee_module_main
        extractor_module_dir_main = os.path.dirname(os.path.abspath(ee_module_main.__file__))
        demo_chaotic_file_path = os.path.join(extractor_module_dir_main, DEFAULT_SOLAR_FLARES_FILE)
    except Exception:
        demo_chaotic_file_path = DEFAULT_SOLAR_FLARES_FILE # Fallback for __main__

    print(f"\nManager 1 (using data file: '{demo_chaotic_file_path}'):")
    manager1 = EntropyManager(chaotic_data_file_path=demo_chaotic_file_path) 
    entropy1_m1 = manager1.get_entropy(16) 
    print(f"Manager1 entropy (16B)   : {entropy1_m1.hex()}")
    entropy2_m1 = manager1.get_entropy(16) 
    print(f"Manager1 entropy again (16B): {entropy2_m1.hex()}")
    
    if entropy1_m1 != entropy2_m1 or not manager1._chaotic_entropy_consumed:
        print("Note: Outputs from Manager1 differ or PRNG was used, as expected after chaotic consumed or if not suitable.")
    
    print("\nManager 2 (simulating no chaotic data file available):")
    manager2 = EntropyManager(chaotic_data_file_path="non_existent_data_file.json")
    entropy1_m2 = manager2.get_entropy(16) 
    print(f"Manager2 entropy (16B)   : {entropy1_m2.hex()}")
    entropy2_m2 = manager2.get_entropy(16) 
    print(f"Manager2 entropy again (16B): {entropy2_m2.hex()}")
    assert entropy1_m2 != entropy2_m2, "PRNG from Manager2 should produce different outputs."

    print("\nDemonstration complete.")