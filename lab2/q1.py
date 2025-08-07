from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii


def des_encrypt(message: str, key: str) -> str:
    key_bytes = key.encode('utf-8')


    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long")

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    # Pad the message to make its length a multiple of the block size (8 bytes for DES)
    padded_message = pad(message.encode('utf-8'), DES.block_size)

    # Encrypt the padded message
    encrypted_bytes = cipher.encrypt(padded_message)

    # Convert the encrypted bytes to a hexadecimal string for readability
    return binascii.hexlify(encrypted_bytes).decode('utf-8')
    # .decode('utf-8') converts the hex numbers to a string for reading


def des_decrypt(encrypted_message: str, key: str) -> str:
  
    # Convert the key into bytes
    key_bytes = key.encode('utf-8')

    # Ensure that the key is exactly 8 bytes long
    if len(key_bytes) != 8:
        raise ValueError("Key must be exactly 8 bytes long")

    # Create a new DES cipher object in ECB mode
    cipher = DES.new(key_bytes, DES.MODE_ECB)

    # Convert the hexadecimal encrypted message back into bytes
    encrypted_bytes = binascii.unhexlify(encrypted_message)

    # Decrypt the encrypted bytes
    padded_message = cipher.decrypt(encrypted_bytes)

    # Unpad the decrypted message to remove any padding added during encryption
    message = unpad(padded_message, DES.block_size)

    # Convert the decrypted message back into a string and return it
    return message.decode('utf-8')


# Example usage
key = 'A1B2C3D4'  # Key must be exactly 8 bytes long
message = 'Confidential Data'  # The message to encrypt

# Encrypt the message
encrypted_message = des_encrypt(message, key)
print(f"Encrypted Message: {encrypted_message}")

# Decrypt the message back to plaintext
decrypted_message = des_decrypt(encrypted_message, key)
print(f"Decrypted Message: {decrypted_message}")