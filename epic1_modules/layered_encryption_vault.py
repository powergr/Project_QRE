# layered_encryption_vault.py
# (Suggest renaming from original layered_encryption.py, 
#  or update the original if it's only meant to be the Vault version)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import oqs
import os
import uuid # For key_id generation
from key_vault_manager import store_keys, get_keys # Import from our new module

KEM_ALGORITHM_LAYERED = "ML-KEM-512" # Consistent KEM algorithm

def layered_encrypt_vault(plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-256-CBC, with the AES key encapsulated by ML-KEM.
    The ML-KEM private key is stored in Vault, and a key_id is prepended to the ciphertext.
    """
    if not isinstance(plaintext, bytes):
        raise ValueError("Plaintext must be bytes.")

    key_id = uuid.uuid4().bytes # 16-byte unique key identifier

    # --- ML-KEM Key Pair Generation ---
    # This 'kem_alice' instance will generate and hold the secret key.
    try:
        kem_alice = oqs.KeyEncapsulation(KEM_ALGORITHM_LAYERED)
    except oqs.MechanismNotSupportedError:
        raise RuntimeError(f"KEM '{KEM_ALGORITHM_LAYERED}' not supported by liboqs.")
    except Exception as e:
        raise RuntimeError(f"Failed to initialize KEM '{KEM_ALGORITHM_LAYERED}': {e}")
        
    try:
        alice_public_key = kem_alice.generate_keypair()
        # This is the private key that needs to be stored for decryption.
        alice_private_key_bytes = kem_alice.export_secret_key()
    except Exception as e:
        raise RuntimeError(f"ML-KEM keypair generation failed: {e}")

    # --- Store the ML-KEM private key in Vault ---
    keys_to_store = {'Kyber_SK': alice_private_key_bytes} # Using 'Kyber_SK' for consistency
    try:
        store_keys(key_id, keys_to_store)
    except Exception as e:
        raise RuntimeError(f"Failed to store ML-KEM private key in Vault: {e}")

    # --- KEM Encapsulation (to get the symmetric key for AES) ---
    # An encapsulator uses Alice's public key.
    encapsulator_kem = oqs.KeyEncapsulation(KEM_ALGORITHM_LAYERED)
    try:
        EK, SS = encapsulator_kem.encap_secret(alice_public_key)
    except Exception as e:
        raise RuntimeError(f"ML-KEM encapsulation failed: {e}")
    
    K_sym = SS # Use shared secret directly as AES key

    # --- AES-256-CBC Encryption ---
    iv = os.urandom(16)
    cipher_aes = Cipher(algorithms.AES(K_sym), modes.CBC(iv))
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    encryptor = cipher_aes.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # --- Construct Ciphertext: key_id | len_EK | EK | IV | encrypted_data ---
    len_EK_bytes = len(EK).to_bytes(4, "big")
    
    return (key_id + 
            len_EK_bytes + EK + 
            iv + encrypted_data)


def layered_decrypt_vault(ciphertext: bytes) -> bytes:
    """
    Decrypts layered encryption ciphertext. Retrieves the ML-KEM private key from Vault
    using the key_id prepended to the ciphertext.
    """
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16: # Must have at least key_id
        raise ValueError("Ciphertext must be bytes and include at least a 16-byte key_id.")

    # --- Extract key_id and retrieve ML-KEM private key from Vault ---
    key_id = ciphertext[:16]
    actual_ciphertext_data = ciphertext[16:]

    try:
        retrieved_keys = get_keys(key_id)
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve keys from Vault for layered decryption: {e}")

    ml_kem_private_key = retrieved_keys.get('Kyber_SK')
    if ml_kem_private_key is None:
        raise RuntimeError("ML-KEM private key ('Kyber_SK') not found in Vault for the given key_id.")

    # --- Parse the rest of the ciphertext (after key_id) ---
    current_pos = 0
    try:
        len_EK = int.from_bytes(actual_ciphertext_data[current_pos : current_pos + 4], "big")
        current_pos += 4
        if current_pos + len_EK > len(actual_ciphertext_data):
            raise ValueError("Malformed ciphertext: EK length exceeds data bounds.")
        
        EK = actual_ciphertext_data[current_pos : current_pos + len_EK]
        current_pos += len_EK
        
        iv_size = 16
        if current_pos + iv_size > len(actual_ciphertext_data):
            raise ValueError("Malformed ciphertext: IV position exceeds data bounds.")
        iv = actual_ciphertext_data[current_pos : current_pos + iv_size]
        current_pos += iv_size
        
        encrypted_data = actual_ciphertext_data[current_pos:]
        if not encrypted_data:
             raise ValueError("Malformed ciphertext: Missing encrypted AES data.")
    except IndexError:
        raise ValueError("Malformed ciphertext: Error parsing components after key_id (IndexError).")
    except Exception as e:
        raise ValueError(f"Malformed ciphertext: Error parsing components - {e}")

    # --- ML-KEM Decapsulation ---
    try:
        kem_decapsulator = oqs.KeyEncapsulation(KEM_ALGORITHM_LAYERED, ml_kem_private_key)
    except oqs.MechanismNotSupportedError:
        raise RuntimeError(f"KEM '{KEM_ALGORITHM_LAYERED}' not supported for decryption.")
    except Exception as e:
        raise RuntimeError(f"Failed to initialize KEM for decryption with SK: {e}")
    
    try:
        SS = kem_decapsulator.decap_secret(EK)
    except Exception as e:
        raise RuntimeError(f"ML-KEM decapsulation failed: {e}")
    
    K_sym = SS

    # --- AES-256-CBC Decryption ---
    cipher_aes_dec = Cipher(algorithms.AES(K_sym), modes.CBC(iv))
    decryptor = cipher_aes_dec.decryptor()
    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    except Exception as e:
        raise RuntimeError(f"AES decryption failed: {e}")

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    try:
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
    except ValueError as e:
        raise RuntimeError(f"PKCS7 unpadding failed: {e}")
        
    return plaintext

if __name__ == '__main__':
    # Basic inline test for layered_encryption_vault
    # Requires Vault dev server, env vars set, and key_vault_manager.py
    print("Running inline test for layered_encryption_vault.py...")
    try:
        import oqs
        # Check KEM algorithm availability
        supported_kems = oqs.get_enabled_kem_mechanisms()
        if KEM_ALGORITHM_LAYERED not in supported_kems:
            print(f"CRITICAL WARNING: KEM '{KEM_ALGORITHM_LAYERED}' not enabled: {supported_kems}")
            exit(1)

        sample_plaintext = b"A secret message for the layered vault encryption technique."
        print(f"Encrypting: \"{sample_plaintext.decode()}\"")
        
        vault_ciphertext = layered_encrypt_vault(sample_plaintext)
        print(f"Ciphertext length (incl. key_id): {len(vault_ciphertext)}")
        print("Encryption complete, KEM private key stored in Vault.")

        print("Decrypting...")
        decrypted_text = layered_decrypt_vault(vault_ciphertext)
        print(f"Decrypted: \"{decrypted_text.decode()}\"")

        assert sample_plaintext == decrypted_text, "Layered vault decryption FAILED!"
        print("Layered encryption/decryption with Vault PASSED!")

    except EnvironmentError as ee:
        print(f"ENVIRONMENT ERROR: {ee}")
    except ConnectionError as ce:
        print(f"VAULT CONNECTION ERROR: {ce}")
    except RuntimeError as re:
        print(f"RUNTIME ERROR: {re}")
    except ValueError as ve:
        print(f"VALUE ERROR: {ve}")
    except Exception as e:
        print(f"An UNEXPECTED ERROR occurred: {e}")
        import traceback
        traceback.print_exc()