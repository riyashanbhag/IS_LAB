import rsa

# Generate a new RSA key pair
# This can take a moment depending on the key size
(public_key, private_key) = rsa.newkeys(512)

# The message to be encrypted
message = "Asymmetric Encryption"

# Encode the message as bytes, which is required for encryption
encoded_message = message.encode('utf-8')

# Encrypt the message using the public key
# 'public_key' is the tuple (n, e)
encrypted_message = rsa.encrypt(encoded_message, public_key)
print(f"Encrypted message: {encrypted_message}");

# Decrypt the ciphertext using the private key
# 'private_key' is the tuple (n, d)
decrypted_message = rsa.decrypt(encrypted_message, private_key)

# Decode the bytes back to a string to get the original message
decoded_message = decrypted_message.decode('utf-8')
print(f"Decrypted message: {decoded_message}")

# Verify if the original and decrypted messages are the same
if message == decoded_message:
    print("Verification successful: The original message was successfully decrypted.")
else:
    print("Verification failed: The original message could not be decrypted.")