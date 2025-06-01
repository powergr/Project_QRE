"""
Module for Quantum Random Number Generator (QRNG) simulation and interface.
Includes an abstract interface, a software-simulated QRNG using Python's
`secrets` module, another using `os.urandom`, and a mock QRNG for testing.
"""
import secrets
import os
from abc import ABC, abstractmethod

# --- QRNG Interface Definition (Ticket 4 in epic, but defined early) ---
class QRNGInterface(ABC):
    """
    Abstract Base Class for Quantum Random Number Generators.
    Defines the interface for acquiring random bytes.
    """
    @abstractmethod
    def get_random_bytes(self, num_bytes: int) -> bytes:
        """
        Generates and returns a specified number of random bytes.

        Args:
            num_bytes: The number of random bytes to generate.

        Returns:
            A bytes object containing the random data.

        Raises:
            ValueError: If num_bytes is negative.
            IOError: If there's an issue fetching bytes from the source.
        """
        pass

# --- Software Simulated QRNG Implementations ---
class SoftwareSimulatedQRNG(QRNGInterface):
    """
    A software-simulated QRNG that uses Python's `secrets` module
    for cryptographically strong random number generation.
    """
    def get_random_bytes(self, num_bytes: int) -> bytes:
        if not isinstance(num_bytes, int):
            raise TypeError("Number of bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("Number of bytes must be non-negative.")
        try:
            return secrets.token_bytes(num_bytes)
        except Exception as e:
            # secrets.token_bytes is generally robust, but catch unexpected issues
            raise IOError(f"Error generating random bytes using 'secrets' module: {e}")

class OsUrandomQRNG(QRNGInterface):
    """
    A software-simulated QRNG that uses Python's `os.urandom`.
    `os.urandom` is suitable for cryptographic use.
    """
    def get_random_bytes(self, num_bytes: int) -> bytes:
        if not isinstance(num_bytes, int):
            raise TypeError("Number of bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("Number of bytes must be non-negative.")
        try:
            return os.urandom(num_bytes)
        except Exception as e:
            raise IOError(f"Error generating random bytes from os.urandom: {e}")

# --- Mock QRNG Implementation (for testing) ---
class MockQRNG(QRNGInterface):
    """
    A mock QRNG for testing purposes.
    Returns predictable, non-random byte sequences based on a seed byte.
    """
    def __init__(self, seed_byte: int = 0xAA, increment: bool = True):
        """
        Initializes the MockQRNG.

        Args:
            seed_byte: The starting byte value (0-255).
            increment: If True, subsequent bytes increment from seed_byte.
                       If False, all bytes will be seed_byte.
        """
        if not (0 <= seed_byte <= 255):
            raise ValueError("seed_byte must be between 0 and 255.")
        self.seed_byte = seed_byte
        self.increment = increment

    def get_random_bytes(self, num_bytes: int) -> bytes:
        if not isinstance(num_bytes, int):
            raise TypeError("Number of bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("Number of bytes must be non-negative.")
        
        if self.increment:
            # Returns a simple incrementing byte pattern for predictability in tests
            return bytes([(self.seed_byte + i) % 256 for i in range(num_bytes)])
        else:
            # Returns a repeating seed_byte
            return bytes([self.seed_byte] * num_bytes)

# --- Conceptual Basic Randomness "Test" (as per ticket for Ticket 1) ---
def _run_basic_randomness_check():
    """
    Performs a very basic conceptual check on the output of a QRNG simulator.
    This is not a substitute for rigorous statistical testing.
    """
    print("\n--- Basic Randomness Check ---")
    qrng_to_test = SoftwareSimulatedQRNG() # Or OsUrandomQRNG()
    sample_size = 100000  # A larger sample for a slightly better visual
    
    print(f"Generating {sample_size} bytes from {qrng_to_test.__class__.__name__}...")
    try:
        random_sample = qrng_to_test.get_random_bytes(sample_size)
    except IOError as e:
        print(f"Could not generate sample: {e}")
        return

    # Basic frequency analysis (count occurrences of each byte value)
    from collections import Counter
    byte_counts = Counter(random_sample)
    
    expected_avg_count = sample_size / 256.0
    print(f"Expected average count per byte value: {expected_avg_count:.2f}")

    print("\nDistribution of first 10 byte values (0-9):")
    for i in range(10):
        print(f"Byte 0x{i:02x} ({i}): {byte_counts[i]:<5} occurrences "
              f"(Delta from avg: {byte_counts[i] - expected_avg_count:+.2f})")

    # Check for obvious bias (very rough check)
    min_observed = min(byte_counts.values()) if byte_counts else 0
    max_observed = max(byte_counts.values()) if byte_counts else 0
    print(f"\nObserved min count: {min_observed}, max count: {max_observed}")
    
    # A very loose check for "flatness" - this is not statistically sound
    # For a truly random sequence, counts should be around expected_avg_count.
    # A significant deviation might indicate an issue, but natural variance is expected.
    if byte_counts and (max_observed > expected_avg_count * 2 or min_observed < expected_avg_count / 2):
        print("WARNING: Distribution seems somewhat uneven. More rigorous tests would be needed for a real QRNG.")
    else:
        print("NOTE: Basic frequency distribution seems plausible for a CSPRNG. This is not a formal test.")
    print("--- End Basic Randomness Check ---")

if __name__ == '__main__':
    # Demonstrate usage and the basic check
    print("Demonstrating QRNG implementations:")
    
    sim_s = SoftwareSimulatedQRNG()
    print(f"\nSoftwareSimulatedQRNG (secrets): {sim_s.get_random_bytes(16).hex()}")

    sim_os = OsUrandomQRNG()
    print(f"OsUrandomQRNG (os.urandom):  {sim_os.get_random_bytes(16).hex()}")

    mock = MockQRNG(seed_byte=0x30)
    print(f"MockQRNG (seed 0x30, inc):   {mock.get_random_bytes(16).hex()}")
    
    mock_flat = MockQRNG(seed_byte=0xCC, increment=False)
    print(f"MockQRNG (seed 0xCC, flat):  {mock_flat.get_random_bytes(16).hex()}")

    _run_basic_randomness_check()