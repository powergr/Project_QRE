"""
Module for the core encryption and decryption engine using AES-GCM.
Supports incorporating dynamic entropy as Associated Authenticated Data (AAD).
"""
import os
from typing import Optional, Tuple # Tuple not used here, but Optional is
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag # For handling GCM tag validation failures

# AES-GCM constants
AES_KEY_SIZE_BYTES = 32    # AES-256 (key length is 256 bits / 8 = 32 bytes)
GCM_NONCE_SIZE_BYTES = 12  # Recommended nonce size for GCM (96 bits)
AAD_LEN_FIELD_BYTES = 2    # Number of bytes to store the length of the AAD

def generate_aes_gcm_key() -> bytes:
    """Generates a new AES-256 key suitable for AESGCM."""
    # AESGCM.generate_key takes bit_length
    return AESGCM.generate_key(bit_length=AES_KEY_SIZE_BYTES * 8)

def encrypt_with_optional_aad(key: bytes,
                               plaintext: bytes,
                               entropy_as_aad: Optional[bytes] = None) -> bytes:
    """
    Encrypts plaintext using AES-GCM, optionally including entropy as AAD.

    The output ciphertext payload is structured as:
    [AAD_LENGTH (2 bytes, big-endian)] 
    [AAD_DATA (variable length, present if AAD_LENGTH > 0)] 
    [NONCE (12 bytes)] 
    [GCM_CIPHERTEXT_INCL_TAG (variable length)]

    Args:
        key: The AES encryption key (must be 32 bytes for AES-256).
        plaintext: The data (bytes) to encrypt.
        entropy_as_aad: Optional entropy (bytes) to use as Associated Authenticated Data (AAD).
                        If None or empty, no AAD is effectively used beyond its length field.

    Returns:
        The combined bytestream of AAD info, nonce, and ciphertext_blob (ciphertext + GCM tag).

    Raises:
        ValueError: If the key is not the correct size.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_SIZE_BYTES} bytes long for AES-256 GCM.")
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes.")
    if entropy_as_aad is not None and not isinstance(entropy_as_aad, bytes):
        raise TypeError("entropy_as_aad must be bytes or None.")

    aesgcm = AESGCM(key)
    nonce = os.urandom(GCM_NONCE_SIZE_BYTES)  # A fresh, unique nonce for each encryption is critical for GCM

    # Prepare AAD: use b"" if entropy_as_aad is None or empty, otherwise use the provided bytes
    aad_to_encrypt_with = entropy_as_aad if entropy_as_aad else b""
    
    try:
        ciphertext_blob = aesgcm.encrypt(nonce, plaintext, aad_to_encrypt_with)
    except Exception as e: # Catch potential errors during encryption
        raise RuntimeError(f"AES-GCM encryption failed: {e}")

    # Construct the output payload
    if entropy_as_aad and len(entropy_as_aad) > 0: # AAD was provided and is not empty
        # Ensure AAD length fits within the allocated field bytes
        if len(entropy_as_aad) > (2**(AAD_LEN_FIELD_BYTES * 8) - 1):
            raise ValueError(f"AAD length ({len(entropy_as_aad)}) exceeds maximum encodable "
                             f"value for {AAD_LEN_FIELD_BYTES} bytes.")
        aad_len_bytes = len(entropy_as_aad).to_bytes(AAD_LEN_FIELD_BYTES, 'big')
        return aad_len_bytes + entropy_as_aad + nonce + ciphertext_blob
    else:  # No AAD, or empty AAD provided
        aad_len_bytes = (0).to_bytes(AAD_LEN_FIELD_BYTES, 'big')
        return aad_len_bytes + nonce + ciphertext_blob


def decrypt_with_optional_aad(key: bytes,
                               full_payload: bytes) -> Optional[bytes]:
    """
    Decrypts data encrypted by encrypt_with_optional_aad.
    It parses the full_payload to extract AAD (if present) and other components.

    Args:
        key: The AES encryption key (must be 32 bytes for AES-256).
        full_payload: The combined bytestream produced by encrypt_with_optional_aad.

    Returns:
        The decrypted plaintext (bytes), or None if decryption fails (e.g., bad key,
        tampered data leading to InvalidTag, or malformed payload).
    
    Raises:
        ValueError: If the key is not the correct size, or if payload is severely malformed
                    preventing basic parsing.
    """
    if not isinstance(key, bytes) or len(key) != AES_KEY_SIZE_BYTES:
        raise ValueError(f"AES key must be {AES_KEY_SIZE_BYTES} bytes long for AES-256 GCM.")
    if not isinstance(full_payload, bytes):
        raise TypeError("Full payload must be bytes.")

    aesgcm = AESGCM(key)
    current_offset = 0

    try:
        # 1. Extract AAD length
        if len(full_payload) < current_offset + AAD_LEN_FIELD_BYTES:
            # print("DEBUG: Payload too short for AAD length field.")
            return None # Malformed payload
        aad_len = int.from_bytes(full_payload[current_offset : current_offset + AAD_LEN_FIELD_BYTES], 'big')
        current_offset += AAD_LEN_FIELD_BYTES

        # 2. Extract AAD data
        extracted_aad_for_decryption = b"" # Default to empty bytes if aad_len is 0
        if aad_len > 0:
            if len(full_payload) < current_offset + aad_len:
                # print("DEBUG: Payload too short for specified AAD content.")
                return None # Malformed payload
            extracted_aad_for_decryption = full_payload[current_offset : current_offset + aad_len]
            current_offset += aad_len
        
        # 3. Extract Nonce
        if len(full_payload) < current_offset + GCM_NONCE_SIZE_BYTES:
            # print("DEBUG: Payload too short for nonce.")
            return None # Malformed payload
        nonce = full_payload[current_offset : current_offset + GCM_NONCE_SIZE_BYTES]
        current_offset += GCM_NONCE_SIZE_BYTES

        # 4. The rest is the ciphertext blob (actual ciphertext + GCM tag)
        ciphertext_blob = full_payload[current_offset:]
        if not ciphertext_blob: # AESGCM typically requires at least the tag (16 bytes for GCM)
            # print("DEBUG: Ciphertext blob part is empty.")
            return None # Malformed payload

        # 5. Decrypt
        # The AAD passed to decrypt *must* match the AAD used during encrypt.
        plaintext = aesgcm.decrypt(nonce, ciphertext_blob, extracted_aad_for_decryption)
        return plaintext

    except InvalidTag:
        # This is the expected error if the key is wrong, data is tampered, or AAD doesn't match.
        # print("DEBUG: Decryption failed - Invalid GCM authentication tag.")
        return None
    except ValueError as ve: # Could be from int.from_bytes if payload is too short for it
        # print(f"DEBUG: ValueError during decryption parsing: {ve}")
        return None # Malformed payload
    except Exception as e: # Catch any other unexpected issues
        # print(f"DEBUG: An unexpected error occurred during decryption: {e}")
        return None

if __name__ == '__main__':
    print("\n--- CipherEngine Demonstration ---")
    # Generate a key for this demo
    aes_key = generate_aes_gcm_key()
    print(f"AES Key: {aes_key.hex()[:16]}...")

    original_data = b"Sensitive information to be encrypted with AES-GCM!"
    print(f"Original Data: '{original_data.decode()}'")

    # Scenario 1: Encrypt WITH AAD
    print("\nScenario 1: With AAD")
    aad_content = b"Context: UserID=123, SessionID=abc"
    print(f"AAD Content: {aad_content.hex()}")
    encrypted_payload_with_aad = encrypt_with_optional_aad(aes_key, original_data, aad_content)
    print(f"Encrypted Payload (with AAD, part): {encrypted_payload_with_aad.hex()[:64]}...")

    decrypted_data_1 = decrypt_with_optional_aad(aes_key, encrypted_payload_with_aad)
    if decrypted_data_1 == original_data:
        print(f"SUCCESS: Decrypted data matches: '{decrypted_data_1.decode()}'")
    else:
        print(f"FAILURE: Decryption mismatch or failed. Got: {decrypted_data_1}")

    # Scenario 2: Encrypt WITHOUT AAD (passing None)
    print("\nScenario 2: Without AAD (AAD is None)")
    encrypted_payload_no_aad = encrypt_with_optional_aad(aes_key, original_data, None)
    print(f"Encrypted Payload (no AAD, part): {encrypted_payload_no_aad.hex()[:64]}...")

    decrypted_data_2 = decrypt_with_optional_aad(aes_key, encrypted_payload_no_aad)
    if decrypted_data_2 == original_data:
        print(f"SUCCESS: Decrypted data matches: '{decrypted_data_2.decode()}'")
    else:
        print(f"FAILURE: Decryption mismatch or failed. Got: {decrypted_data_2}")

    # Scenario 3: Encrypt WITHOUT AAD (passing empty bytes b"")
    print("\nScenario 3: Without AAD (AAD is b'')")
    encrypted_payload_empty_aad = encrypt_with_optional_aad(aes_key, original_data, b"")
    print(f"Encrypted Payload (empty AAD, part): {encrypted_payload_empty_aad.hex()[:64]}...")
    # This should be identical in structure to Scenario 2 if implemented correctly

    decrypted_data_3 = decrypt_with_optional_aad(aes_key, encrypted_payload_empty_aad)
    if decrypted_data_3 == original_data:
        print(f"SUCCESS: Decrypted data matches: '{decrypted_data_3.decode()}'")
    else:
        print(f"FAILURE: Decryption mismatch or failed. Got: {decrypted_data_3}")

    # Scenario 4: Tampering Test (Illustrative)
    print("\nScenario 4: Tampering (Authentication Failure)")
    if encrypted_payload_with_aad and len(encrypted_payload_with_aad) > AAD_LEN_FIELD_BYTES + GCM_NONCE_SIZE_BYTES + 5:
        tampered_payload_list = list(encrypted_payload_with_aad)
        # Flip a bit in the ciphertext part (after AAD_LEN, AAD, and NONCE)
        # Be careful not to flip bits in length fields or IV if you want to test specific GCM tag failure.
        # Let's flip a bit near the end, likely in the tag or ciphertext.
        tampered_payload_list[-5] = tampered_payload_list[-5] ^ 0x01 
        tampered_payload = bytes(tampered_payload_list)
        
        print(f"Attempting to decrypt tampered payload...")
        decrypted_tampered = decrypt_with_optional_aad(aes_key, tampered_payload)
        if decrypted_tampered is None:
            print("SUCCESS (expected): Decryption of tampered payload failed (InvalidTag).")
        else:
            print(f"FAILURE (unexpected): Decryption of tampered payload succeeded?! Got: {decrypted_tampered}")
    else:
        print("Skipping tampering test as payload is too short.")