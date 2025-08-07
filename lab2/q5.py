from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

# Convert hex string key to bytes
def get_key_from_hex(hex_key):
    return bytes.fromhex(hex_key)

# Encrypt using AES-192
def encrypt_aes192(plaintext, key_hex):
    key = get_key_from_hex(key_hex)
    cipher = AES.new(key, AES.MODE_ECB)  # ECB for simplicity (no IV)
    padded_text = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_text)
    return ciphertext

# Decrypt to verify
def decrypt_aes192(ciphertext, key_hex):
    key = get_key_from_hex(key_hex)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted.decode()

# Main execution
key_hex = "FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210"  # 48 hex chars = 24 bytes
message = "Top Secret Data"

ciphertext = encrypt_aes192(message, key_hex)
print("Ciphertext (hex):", ciphertext.hex())

decrypted = decrypt_aes192(ciphertext, key_hex)
print("Decrypted Text:", decrypted)
