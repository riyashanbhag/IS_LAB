from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii


def aes_encrypt(message: str, key: str) -> str:
    # Use only the first 16 bytes of the key for AES-128
    key_bytes = key[:16].encode('utf-8')

    # Pad the message to AES block size (16 bytes)
    padded_message = pad(message.encode('utf-8'), AES.block_size)

    # Create AES cipher in ECB mode
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # Encrypt the message
    encrypted_bytes = cipher.encrypt(padded_message)

    # Return as hex for readability
    return binascii.hexlify(encrypted_bytes).decode('utf-8')


def aes_decrypt(encrypted_message: str, key: str) -> str:
    # Use only the first 16 bytes of the key for AES-128
    key_bytes = key[:16].encode('utf-8')

    # Convert hex to bytes
    encrypted_bytes = binascii.unhexlify(encrypted_message)

    # Create AES cipher
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # Decrypt and unpad
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_message = unpad(decrypted_padded, AES.block_size)

    return decrypted_message.decode('utf-8')


# Example usage
key = "0123456789ABCDEF0123456789ABCDEF"
message = "Sensitive Information"

encrypted = aes_encrypt(message, key)
print(f"Encrypted Message: {encrypted}")

decrypted= aes_decrypt(encrypted,key)
print(f"Decrypted message:{decrypted}")