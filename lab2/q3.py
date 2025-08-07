from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
from time import perf_counter
import binascii

# Constants
MESSAGE = "Performance Testing of Encryption Algorithms"
DES_KEY = b"8bytekey"  # 8 bytes
AES_KEY = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes

def encrypt_des(message: str, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(message.encode(), DES.block_size)
    start = perf_counter()
    encrypted = cipher.encrypt(padded)
    enc_time = perf_counter() - start
    return encrypted, enc_time

def decrypt_des(ciphertext: bytes, key: bytes):
    cipher = DES.new(key, DES.MODE_ECB)
    start = perf_counter()
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)
    dec_time = perf_counter() - start
    return decrypted.decode(), dec_time

def encrypt_aes(message: str, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(message.encode(), AES.block_size)
    start = perf_counter()
    encrypted = cipher.encrypt(padded)
    enc_time = perf_counter() - start
    return encrypted, enc_time

def decrypt_aes(ciphertext: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_ECB)
    start = perf_counter()
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
    dec_time = perf_counter() - start
    return decrypted.decode(), dec_time

def print_results(algo_name, encrypted, decrypted, enc_time, dec_time):
    print(f"\n{algo_name} ")
    print("Encrypted (hex):", binascii.hexlify(encrypted).decode())
    print("Decrypted:", decrypted)
    print(f"Encryption Time: {enc_time:.8f} seconds")
    print(f"Decryption Time: {dec_time:.8f} seconds")

def main():
    print("Original Message:", MESSAGE)

    # DES
    des_encrypted, des_enc_time = encrypt_des(MESSAGE, DES_KEY)
    des_decrypted, des_dec_time = decrypt_des(des_encrypted, DES_KEY)
    print_results("DES", des_encrypted, des_decrypted, des_enc_time, des_dec_time)

    # AES-256
    aes_encrypted, aes_enc_time = encrypt_aes(MESSAGE, AES_KEY)
    aes_decrypted, aes_dec_time = decrypt_aes(aes_encrypted, AES_KEY)
    print_results("AES-256", aes_encrypted, aes_decrypted, aes_enc_time, aes_dec_time)

if __name__ == "__main__":
    main()
