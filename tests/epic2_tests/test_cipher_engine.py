import unittest
import os
from epic2_qne.cipher_engine import (
        generate_aes_gcm_key, 
        encrypt_with_optional_aad, 
        decrypt_with_optional_aad,
        AES_KEY_SIZE_BYTES,
        AAD_LEN_FIELD_BYTES,
        GCM_NONCE_SIZE_BYTES
    )

class TestCipherEngine(unittest.TestCase):
        def setUp(self):
            self.key = generate_aes_gcm_key()
            self.plaintext = b"This is my secret data for AES-GCM testing!"
            self.aad = b"Authenticated but not encrypted context"

        def test_key_generation(self):
            key = generate_aes_gcm_key()
            self.assertIsInstance(key, bytes)
            self.assertEqual(len(key), AES_KEY_SIZE_BYTES)

        def test_encrypt_decrypt_with_aad(self):
            encrypted = encrypt_with_optional_aad(self.key, self.plaintext, self.aad)
            self.assertIsInstance(encrypted, bytes)
            
            decrypted = decrypt_with_optional_aad(self.key, encrypted)
            self.assertEqual(decrypted, self.plaintext)

        def test_encrypt_decrypt_without_aad_passed_as_none(self):
            encrypted = encrypt_with_optional_aad(self.key, self.plaintext, None)
            decrypted = decrypt_with_optional_aad(self.key, encrypted)
            self.assertEqual(decrypted, self.plaintext)

        def test_encrypt_decrypt_without_aad_passed_as_empty_bytes(self):
            encrypted = encrypt_with_optional_aad(self.key, self.plaintext, b"")
            decrypted = decrypt_with_optional_aad(self.key, encrypted)
            self.assertEqual(decrypted, self.plaintext)
            
            # Check ciphertext structure for no AAD
            aad_len_from_ct = int.from_bytes(encrypted[:AAD_LEN_FIELD_BYTES], 'big')
            self.assertEqual(aad_len_from_ct, 0)
            # Expected: AAD_LEN_FIELD | NONCE | CIPHERTEXT_BLOB
            expected_min_len = AAD_LEN_FIELD_BYTES + GCM_NONCE_SIZE_BYTES + 16 # 16 for GCM tag
            self.assertTrue(len(encrypted) >= expected_min_len)


        def test_ciphertext_structure_with_aad(self):
            encrypted = encrypt_with_optional_aad(self.key, self.plaintext, self.aad)
            
            aad_len_from_ct = int.from_bytes(encrypted[:AAD_LEN_FIELD_BYTES], 'big')
            self.assertEqual(aad_len_from_ct, len(self.aad))
            
            extracted_aad = encrypted[AAD_LEN_FIELD_BYTES : AAD_LEN_FIELD_BYTES + aad_len_from_ct]
            self.assertEqual(extracted_aad, self.aad)
            
            nonce_offset = AAD_LEN_FIELD_BYTES + aad_len_from_ct
            # Nonce should be GCM_NONCE_SIZE_BYTES long
            # Ciphertext_blob (ct + tag) should be at least 16 bytes (tag size)
            expected_min_len = nonce_offset + GCM_NONCE_SIZE_BYTES + 16 
            self.assertTrue(len(encrypted) >= expected_min_len)


        def test_decryption_failure_wrong_key(self):
            wrong_key = generate_aes_gcm_key()
            encrypted = encrypt_with_optional_aad(self.key, self.plaintext, self.aad)
            decrypted = decrypt_with_optional_aad(wrong_key, encrypted)
            self.assertIsNone(decrypted, "Decryption should fail (return None) with wrong key.")

        def test_decryption_failure_tampered_ciphertext(self):
            encrypted = encrypt_with_optional_aad(self.key, self.plaintext, self.aad)
            tampered_list = list(encrypted)
            if len(tampered_list) > AAD_LEN_FIELD_BYTES + GCM_NONCE_SIZE_BYTES + 5: # Ensure tampering is in ct/tag
                tamper_idx = len(tampered_list) - 5 # Tamper towards the end (likely tag or ciphertext)
                tampered_list[tamper_idx] = tampered_list[tamper_idx] ^ 0x01 
                tampered_ciphertext = bytes(tampered_list)
                decrypted = decrypt_with_optional_aad(self.key, tampered_ciphertext)
                self.assertIsNone(decrypted, "Decryption should fail (return None) for tampered ciphertext.")
            else:
                self.skipTest("Ciphertext too short to reliably tamper for this test.")


        def test_decryption_failure_tampered_aad_in_payload(self):
            # Encrypt with AAD
            encrypted_with_aad = encrypt_with_optional_aad(self.key, self.plaintext, self.aad)

            # Tamper the AAD part within the payload before decryption
            aad_len_from_ct = int.from_bytes(encrypted_with_aad[:AAD_LEN_FIELD_BYTES], 'big')
            if aad_len_from_ct > 0 :
                payload_list = list(encrypted_with_aad)
                # Tamper first byte of AAD in the payload
                payload_list[AAD_LEN_FIELD_BYTES] = payload_list[AAD_LEN_FIELD_BYTES] ^ 0x01
                tampered_payload = bytes(payload_list)
                
                decrypted = decrypt_with_optional_aad(self.key, tampered_payload)
                self.assertIsNone(decrypted, "Decryption should fail if AAD in payload is tampered.")
            else:
                self.skipTest("Original AAD was empty, cannot tamper AAD in payload for this test.")
        
        def test_invalid_key_length(self):
            short_key = os.urandom(16)
            long_key = os.urandom(48)
            with self.assertRaises(ValueError):
                encrypt_with_optional_aad(short_key, self.plaintext, self.aad)
            with self.assertRaises(ValueError):
                decrypt_with_optional_aad(short_key, b"someciphertext")
            with self.assertRaises(ValueError):
                encrypt_with_optional_aad(long_key, self.plaintext, self.aad)
            with self.assertRaises(ValueError):
                decrypt_with_optional_aad(long_key, b"someciphertext")
        
        def test_malformed_payload_decryption(self):
            self.assertIsNone(decrypt_with_optional_aad(self.key, b"short")) # Too short for AAD_LEN
            self.assertIsNone(decrypt_with_optional_aad(self.key, (0).to_bytes(AAD_LEN_FIELD_BYTES,'big') + b"short")) # Too short for NONCE
            self.assertIsNone(decrypt_with_optional_aad(self.key, (10).to_bytes(AAD_LEN_FIELD_BYTES,'big') + b"shortAAD")) # Too short for actual AAD
            # AAD_LEN | NONCE (no ciphertext_blob)
            no_ct_blob = (0).to_bytes(AAD_LEN_FIELD_BYTES, 'big') + os.urandom(GCM_NONCE_SIZE_BYTES)
            self.assertIsNone(decrypt_with_optional_aad(self.key, no_ct_blob))


if __name__ == '__main__':
        unittest.main()