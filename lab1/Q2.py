def preprocess_text(text):
    """
    Converts text to uppercase and removes all non-alphabetic characters (including spaces).
    This ensures the cipher operations work on a continuous stream of letters.
    """
    return "".join(filter(str.isalpha, text)).upper()


def char_to_int(char):
    """Converts an uppercase letter to its 0-25 integer value (A=0, B=1, ...)."""
    return ord(char) - ord('A')


def int_to_char(integer):
    """Converts an integer (0-25) to its uppercase letter."""
    return chr(integer + ord('A'))


# --- a) Vigenere Cipher ---
def vigenere_encrypt(plaintext, key):
    """
    Encrypts a plaintext message using the Vigenere cipher.
    The key is repeated as necessary to match the plaintext length.
    """
    processed_pt = preprocess_text(plaintext)
    processed_key = preprocess_text(key)  # Vigenere key itself is a string of letters

    ciphertext_chars = []
    key_len = len(processed_key)

    for i in range(len(processed_pt)):
        p_val = char_to_int(processed_pt[i])
        k_val = char_to_int(processed_key[i % key_len])  # Repeat key if shorter

        c_val = (p_val + k_val) % 26
        ciphertext_chars.append(int_to_char(c_val))

    return "".join(ciphertext_chars)


def vigenere_decrypt(ciphertext, key):
    """
    Decrypts a ciphertext message using the Vigenere cipher.
    Assumes ciphertext is already preprocessed (uppercase, no spaces).
    """
    processed_key = preprocess_text(key)
    plaintext_chars = []
    key_len = len(processed_key)

    for i in range(len(ciphertext)):
        c_val = char_to_int(ciphertext[i])
        k_val = char_to_int(processed_key[i % key_len])  # Repeat key as used in encryption

        p_val = (c_val - k_val) % 26  # (C - K) mod 26
        plaintext_chars.append(int_to_char(p_val))

    return "".join(plaintext_chars)


# --- b) Autokey Cipher ---
def autokey_encrypt(plaintext, initial_key_value):
    """
    Encrypts a plaintext message using the Autokey cipher.
    The key stream starts with the initial key value, then continues with plaintext letters.
    """
    processed_pt = preprocess_text(plaintext)
    ciphertext_chars = []

    # The key for the first character is the initial_key_value.
    # For subsequent characters, the key is the numerical value of the *previous plaintext character*.
    # So, the key stream effectively is: (initial_key_value, P0, P1, P2, ...)

    for i in range(len(processed_pt)):
        p_val = char_to_int(processed_pt[i])

        if i == 0:
            k_val = initial_key_value  # Use the provided initial numeric key
        else:
            k_val = char_to_int(processed_pt[i - 1])  # Key is previous plaintext character

        c_val = (p_val + k_val) % 26
        ciphertext_chars.append(int_to_char(c_val))

    return "".join(ciphertext_chars)


def autokey_decrypt(ciphertext, initial_key_value):
    """
    Decrypts a ciphertext message using the Autokey cipher.
    The key stream for decryption is derived from the initial key and the *decrypted* plaintext characters.
    """
    plaintext_chars = []

    for i in range(len(ciphertext)):
        c_val = char_to_int(ciphertext[i])

        if i == 0:
            k_val = initial_key_value  # Use the provided initial numeric key for the first char
        else:
            # For decryption, the key is the *already decrypted* previous plaintext character
            k_val = char_to_int(plaintext_chars[i - 1])

        p_val = (c_val - k_val) % 26  # (C - K) mod 26
        plaintext_chars.append(int_to_char(p_val))

    return "".join(plaintext_chars)


# --- Main Execution ---
if __name__ == "__main__":
    original_message = "the house is being sold tonight"

    print(f"Original Plaintext: \"{original_message}\"")
    # Show the processed version that the ciphers will actually operate on
    processed_for_cipher = preprocess_text(original_message)
    print(f"Processed for Cipher: \"{processed_for_cipher}\"\n")

    # === a) Vigenere Cipher ===
    vigenere_key = "dollars"

    print(f"Cipher: Vigenere")
    print(f"Key   : \"{vigenere_key}\"")


    encrypted_vigenere = vigenere_encrypt(original_message, vigenere_key)
    print(f"Encrypted Message: {encrypted_vigenere}")

    decrypted_vigenere = vigenere_decrypt(encrypted_vigenere, vigenere_key)
    print(f"Decrypted Message: {decrypted_vigenere}")
    print(f"Matches Original : {decrypted_vigenere == processed_for_cipher}")
    print("\n")

    # === b) Autokey Cipher ===
    # For Autokey, 'key = 7' typically means the starting key is the numerical value 7.
    # In A=0, B=1, ..., Z=25 system, 7 corresponds to the letter 'H'.
    autokey_initial_key_val = 7

    print(f"Cipher: Autokey")
    print(
        f"Initial Key (numeric value): {autokey_initial_key_val} (Corresponds to '{int_to_char(autokey_initial_key_val)}')")


    encrypted_autokey = autokey_encrypt(original_message, autokey_initial_key_val)
    print(f"Encrypted Message: {encrypted_autokey}")

    decrypted_autokey = autokey_decrypt(encrypted_autokey, autokey_initial_key_val)
    print(f"Decrypted Message: {decrypted_autokey}")
    print(f"Matches Original : {decrypted_autokey == processed_for_cipher}")
    print("\n")