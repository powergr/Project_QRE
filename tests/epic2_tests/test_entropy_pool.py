import unittest
import time
from epic2_qne.qrng import MockQRNG
from epic2_qne.entropy_pool import EntropyPool, DEFAULT_POOL_MAX_SIZE_BYTES

class TestEntropyPool(unittest.TestCase):
        def test_pool_initialization_and_basic_get(self):
            mock_qrng = MockQRNG(seed_byte=0xAB)
            with EntropyPool(qrng_instance=mock_qrng, max_size_bytes=64, refresh_interval_sec=0.1) as pool:
                time.sleep(0.05) # Allow initial fill
                entropy = pool.get_entropy(16)
                self.assertIsNotNone(entropy)
                self.assertEqual(len(entropy), 16)
                self.assertTrue(all(b == 0xAB or (b >= 0xAB and b < 0xAB+16) for b in entropy)) # Based on MockQRNG

                entropy_zero = pool.get_entropy(0)
                self.assertEqual(entropy_zero, b"")

                with self.assertRaises(ValueError):
                    pool.get_entropy(-5)
                with self.assertRaises(TypeError):
                    pool.get_entropy("abc") # type: ignore

        def test_pool_refresh(self):
            mock_qrng = MockQRNG(seed_byte=0x10) # Initial seed for first fill
            refresh_interval = 0.2
            pool_size = 32
            with EntropyPool(qrng_instance=mock_qrng, max_size_bytes=pool_size, refresh_interval_sec=refresh_interval) as pool:
                time.sleep(0.05) # initial fill
                entropy1 = pool.get_entropy(pool_size)
                self.assertIsNotNone(entropy1)
                # print(f"E1: {entropy1.hex()}")

                # Change the "randomness" source for the mock QRNG
                # This simulates the QRNG providing different data over time
                # In a real scenario, the QRNG itself would change its output.
                # Here, we just change the seed of our Mock to test the refresh mechanism.
                mock_qrng.seed_byte = 0x20 
                
                time.sleep(refresh_interval * 2) # Wait for at least one refresh cycle after changing seed

                entropy2 = pool.get_entropy(pool_size)
                self.assertIsNotNone(entropy2)
                # print(f"E2: {entropy2.hex()}")
                
                self.assertNotEqual(entropy1, entropy2, "Entropy pool did not refresh with new data.")
                self.assertTrue(all(b >= 0x20 and b < 0x20+pool_size for b in entropy2))


        def test_get_entropy_capped_at_max_size(self):
            mock_qrng = MockQRNG()
            pool_max = 32
            with EntropyPool(qrng_instance=mock_qrng, max_size_bytes=pool_max, refresh_interval_sec=0.1) as pool:
                time.sleep(0.05)
                entropy = pool.get_entropy(pool_max * 2) # Request more than pool max
                self.assertIsNotNone(entropy)
                self.assertEqual(len(entropy), pool_max, "get_entropy should cap at pool's max_size.")

        def test_pool_with_failing_qrng(self):
            class FailingQRNG(MockQRNG): # Inherit from Mock to have valid methods
                def get_random_bytes(self, num_bytes: int) -> bytes:
                    raise IOError("Simulated QRNG failure")

            failing_qrng_instance = FailingQRNG()
            # Pool should handle QRNG errors gracefully (log and continue, pool might be empty)
            with EntropyPool(qrng_instance=failing_qrng_instance, max_size_bytes=32, refresh_interval_sec=0.1) as pool:
                time.sleep(0.15) # Allow a refresh attempt which should fail
                entropy = pool.get_entropy(16)
                # Depending on exact timing of failure vs get, pool might be empty from start or after 1st failed refresh
                # The key is that the EntropyPool itself doesn't crash.
                # If initial fill failed, pool would be empty. If a later refresh fails, it might have old data or be empty.
                # For this test, we expect it might return None if the initial fill or subsequent fill fails and empties it.
                # Or it returns initial data if initial fill succeeded before error.
                # The _refresh_entropy logs errors.
                if entropy is not None:
                    print(f"Pool with failing QRNG returned some entropy: {len(entropy)} bytes. This might be stale.")
                else:
                    print("Pool with failing QRNG correctly returned None or empty when entropy not available.")
                # No assertion here, just checking for no crash. More complex state check needed for strictness.

        def test_init_invalid_params(self):
            mock_qrng = MockQRNG()
            with self.assertRaises(TypeError):
                EntropyPool(qrng_instance="not_a_qrng") # type: ignore
            with self.assertRaises(ValueError):
                EntropyPool(qrng_instance=mock_qrng, max_size_bytes=0)
            with self.assertRaises(ValueError):
                EntropyPool(qrng_instance=mock_qrng, refresh_interval_sec=0)


if __name__ == '__main__':
        unittest.main()