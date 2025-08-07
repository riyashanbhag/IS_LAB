from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import binascii

def get_3des_key(hex_key):
    # 3DES requires 24 bytes (192 bits)
    key_bytes = binascii.unhexlify(hex_key)
    return key_bytes[:24]

def pad_data(data):
    padder = padding.PKCS7(64).padder()
    padded = padder.update(data.encode()) + padder.finalize()
    return padded

def unpad_data(padded_data):
    unpadder = padding.PKCS7(64).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()

def encrypt_3des(message, key):
    padded_message = pad_data(message)
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return ciphertext

def decrypt_3des(ciphertext, key):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad_data(decrypted_padded)

# === MAIN ===
hex_key = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
key = get_3des_key(hex_key)
message = "Classified Text"

ciphertext = encrypt_3des(message, key)
print("Encrypted (Hex):", binascii.hexlify(ciphertext).decode())

decrypted = decrypt_3des(ciphertext, key)
print("Decrypted:", decrypted)
