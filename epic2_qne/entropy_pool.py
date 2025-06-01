"""
Module for the Dynamic Entropy Pool.
This pool maintains a buffer of random bytes, periodically refreshed from a QRNG source.
It is designed to be thread-safe.
"""
import threading
import time
from typing import Optional, Union # Changed from Type to Union for qrng_instance type hint
from .qrng import QRNGInterface # Import the interface defined in qrng.py

DEFAULT_POOL_MAX_SIZE_BYTES = 1024
DEFAULT_REFRESH_INTERVAL_SEC = 3.0 # Use float for time.sleep/wait

class EntropyPool:
    """
    Maintains a pool of entropy that is periodically refreshed from a QRNG.
    The pool is thread-safe for access.
    """
    def __init__(self,
                 qrng_instance: QRNGInterface,
                 max_size_bytes: int = DEFAULT_POOL_MAX_SIZE_BYTES,
                 refresh_interval_sec: float = DEFAULT_REFRESH_INTERVAL_SEC):
        """
        Initializes the entropy pool.

        Args:
            qrng_instance: An object conforming to QRNGInterface to source entropy.
            max_size_bytes: The maximum size of the entropy pool in bytes.
            refresh_interval_sec: How often the pool should be refreshed.
        """
        if not isinstance(qrng_instance, QRNGInterface):
            raise TypeError("qrng_instance must be an instance of QRNGInterface.")
        if not isinstance(max_size_bytes, int) or max_size_bytes <= 0:
            raise ValueError("max_size_bytes must be a positive integer.")
        if not isinstance(refresh_interval_sec, (int, float)) or refresh_interval_sec <= 0:
            raise ValueError("refresh_interval_sec must be a positive number.")

        self.qrng = qrng_instance
        self.max_size = max_size_bytes
        self.refresh_interval = refresh_interval_sec

        self._pool = bytearray()  # Use bytearray for mutable sequence of bytes
        self._lock = threading.Lock()  # To ensure thread-safe access to the pool
        self._stop_event = threading.Event()  # To signal the refresh thread to stop
        self._is_running = False # To track if the thread has been started

        # Initial fill of the pool
        # print("DEBUG: EntropyPool performing initial entropy fill...")
        self._refresh_entropy() 
        # print(f"DEBUG: Initial pool size: {len(self._pool)}")

        self._refresh_thread = threading.Thread(target=self._maintain_pool, daemon=True)
        
    def start(self):
        """Starts the background refresh thread if not already running."""
        if not self._is_running:
            self._is_running = True
            self._stop_event.clear() # Ensure stop event is clear before starting
            if not self._refresh_thread.is_alive(): # Check if thread needs to be recreated
                 self._refresh_thread = threading.Thread(target=self._maintain_pool, daemon=True)
            self._refresh_thread.start()
            # print("DEBUG: Entropy pool refresh thread started.")

    def _refresh_entropy(self):
        """
        Fetches new entropy from the QRNG and updates the pool.
        This method replaces the entire pool content with new random bytes.
        """
        # print(f"DEBUG: Attempting to refresh entropy pool (current size: {len(self._pool)})...")
        try:
            new_entropy = self.qrng.get_random_bytes(self.max_size)
            with self._lock:
                self._pool = bytearray(new_entropy)
            # print(f"DEBUG: Entropy pool refreshed. New size: {len(self._pool)} bytes.")
        except IOError as e:
            # Log error, but allow the pool to continue trying on next interval
            print(f"ERROR [EntropyPool]: Could not refresh entropy from QRNG: {e}")
        except Exception as e:
            # Catch any other unexpected errors during QRNG interaction
            print(f"ERROR [EntropyPool]: Unexpected error during entropy refresh: {e}")

    def _maintain_pool(self):
        """Background thread's main loop to periodically refresh the entropy pool."""
        # print("DEBUG: Entropy pool maintenance thread active.")
        try:
            while not self._stop_event.wait(self.refresh_interval):
                self._refresh_entropy()
        except Exception as e: # Catch unexpected errors in the thread loop itself
            print(f"CRITICAL ERROR [EntropyPool]: Maintenance thread encountered an error: {e}")
        finally:
            # print("DEBUG: Entropy pool maintenance thread loop ending.")
            pass


    def get_entropy(self, num_bytes: int) -> Optional[bytes]:
        """
        Retrieves a chunk of entropy from the pool.

        It returns a portion of the pool. The pool itself is not depleted by this call;
        it's a snapshot. The background thread continuously refreshes the entire pool.

        Args:
            num_bytes: The desired number of bytes of entropy.

        Returns:
            A bytes object with the requested entropy, or None if the request cannot be
            satisfied (e.g., pool is temporarily empty due to QRNG errors, or requested
            bytes are zero after adjustment). Returns an empty bytes object if num_bytes is 0.
        """
        if not isinstance(num_bytes, int):
            raise TypeError("Number of bytes must be an integer.")
        if num_bytes < 0:
            raise ValueError("Number of bytes must be non-negative.")
        if num_bytes == 0:
            return b""
        
        # Requests should not exceed the pool's maximum configured size.
        # If a larger chunk is needed, the application should make multiple calls
        # or use a larger pool. This method returns up to max_size.
        actual_bytes_to_return = min(num_bytes, self.max_size)

        with self._lock:
            if len(self._pool) >= actual_bytes_to_return:
                # Return a copy of the requested part of the pool (snapshot)
                return bytes(self._pool[:actual_bytes_to_return])
            elif len(self._pool) > 0: # Not enough for request, but some is available
                # print(f"Warning [EntropyPool]: Requested {num_bytes}, have {len(self._pool)}. "
                #       f"Returning available {len(self._pool)} bytes.")
                return bytes(self._pool[:]) # Return all available
            else: # Pool is empty
                # print(f"Warning [EntropyPool]: Pool is currently empty. Cannot satisfy request for {num_bytes} bytes.")
                return None 

    def stop(self):
        """Stops the background refresh thread gracefully."""
        if self._is_running:
            # print("DEBUG: Initiating entropy pool stop...")
            self._stop_event.set() # Signal the thread to stop
            if self._refresh_thread.is_alive():
                self._refresh_thread.join(timeout=self.refresh_interval * 2) # Wait for thread
                if self._refresh_thread.is_alive():
                    print("Warning [EntropyPool]: Refresh thread did not terminate in time.")
            self._is_running = False
            # print("DEBUG: Entropy pool stopped.")

    def __enter__(self):
        """Context management: enter."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context management: exit."""
        self.stop()

if __name__ == '__main__':
    from qrng import SoftwareSimulatedQRNG, MockQRNG # For testing
    print("\n--- EntropyPool Demonstration ---")

    # Test with SoftwareSimulatedQRNG
    print("\nUsing SoftwareSimulatedQRNG:")
    sim_qrng_for_pool = SoftwareSimulatedQRNG()
    # Using 'with' statement for automatic start and stop
    with EntropyPool(qrng_instance=sim_qrng_for_pool, max_size_bytes=128, refresh_interval_sec=1.0) as pool:
        print("Pool started. Waiting for a few refreshes...")
        for i in range(3):
            time.sleep(1.1) # Sleep longer than refresh interval
            entropy_chunk = pool.get_entropy(32)
            if entropy_chunk:
                print(f"Sample {i+1} (size {len(entropy_chunk)}): {entropy_chunk.hex()}")
            else:
                print(f"Sample {i+1}: Failed to get entropy or pool empty.")
        
        # Test getting more than available (but capped at max_size)
        large_request = pool.get_entropy(200)
        if large_request:
            print(f"Large request (200B capped at {pool.max_size}B), got {len(large_request)}B: {large_request.hex()[:32]}...")
        
    print("Pool stopped (after 'with' block).")

    # Test with MockQRNG
    print("\nUsing MockQRNG:")
    mock_qrng_for_pool = MockQRNG(seed_byte=0x77)
    pool2 = EntropyPool(qrng_instance=mock_qrng_for_pool, max_size_bytes=64, refresh_interval_sec=0.5)
    pool2.start()
    print("Mock pool started. Waiting for a few refreshes...")
    for i in range(3):
        time.sleep(0.6)
        entropy_chunk = pool2.get_entropy(16)
        if entropy_chunk:
            print(f"Mock Sample {i+1} (size {len(entropy_chunk)}): {entropy_chunk.hex()}")
        else:
            print(f"Mock Sample {i+1}: Failed to get entropy or pool empty.")
    pool2.stop()
    print("Mock pool stopped.")