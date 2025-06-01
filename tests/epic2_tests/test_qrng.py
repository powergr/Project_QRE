import unittest
from epic2_qne.qrng import SoftwareSimulatedQRNG, OsUrandomQRNG, MockQRNG, QRNGInterface

class TestQRNGs(unittest.TestCase):
        def test_interface_adherence(self):
            self.assertTrue(issubclass(SoftwareSimulatedQRNG, QRNGInterface))
            self.assertTrue(issubclass(OsUrandomQRNG, QRNGInterface))
            self.assertTrue(issubclass(MockQRNG, QRNGInterface))

        def _test_qrng_output(self, qrng_instance: QRNGInterface, instance_name: str):
            # Test generation of 0 bytes
            self.assertEqual(qrng_instance.get_random_bytes(0), b"", f"{instance_name} failed for 0 bytes")
            
            # Test generation of positive number of bytes
            num_bytes = 16
            random_bytes = qrng_instance.get_random_bytes(num_bytes)
            self.assertIsInstance(random_bytes, bytes, f"{instance_name} did not return bytes")
            self.assertEqual(len(random_bytes), num_bytes, f"{instance_name} returned wrong length")

            # Test generation of a different length
            num_bytes_2 = 32
            random_bytes_2 = qrng_instance.get_random_bytes(num_bytes_2)
            self.assertEqual(len(random_bytes_2), num_bytes_2, f"{instance_name} returned wrong length for 2nd call")
            if not isinstance(qrng_instance, MockQRNG): # Mock might produce same if not careful
                 self.assertNotEqual(random_bytes, random_bytes_2[:16], f"{instance_name} produced same output for different calls/lengths")


            # Test ValueError for negative num_bytes
            with self.assertRaises(ValueError, msg=f"{instance_name} did not raise ValueError for negative bytes"):
                qrng_instance.get_random_bytes(-1)
            
            # Test TypeError for non-integer num_bytes
            with self.assertRaises(TypeError, msg=f"{instance_name} did not raise TypeError for non-int bytes"):
                qrng_instance.get_random_bytes("abc") # type: ignore 

        def test_software_simulated_qrng(self):
            self._test_qrng_output(SoftwareSimulatedQRNG(), "SoftwareSimulatedQRNG")

        def test_os_urandom_qrng(self):
            self._test_qrng_output(OsUrandomQRNG(), "OsUrandomQRNG")

        def test_mock_qrng(self):
            mock_inc = MockQRNG(seed_byte=0x10, increment=True)
            self._test_qrng_output(mock_inc, "MockQRNG (incrementing)")
            self.assertEqual(mock_inc.get_random_bytes(3), b'\x10\x11\x12')

            mock_flat = MockQRNG(seed_byte=0xFF, increment=False)
            self._test_qrng_output(mock_flat, "MockQRNG (flat)")
            self.assertEqual(mock_flat.get_random_bytes(3), b'\xff\xff\xff')
            
            with self.assertRaises(ValueError): # Invalid seed
                MockQRNG(seed_byte=256)
if __name__ == '__main__':
    unittest.main()