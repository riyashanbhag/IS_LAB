Plain_Text = "the house is being sold tonight"

# Vigenère Cipher Encryption
def Vignere(P, k):
    """
    Encrypts a plaintext string using the Vigenère cipher.

    Args:
        P (str): The plaintext message.
        k (str): The keyword for encryption.

    Returns:
        str: The encrypted ciphertext.
    """
    Cipher_text = ""
    index = 0
    # Extend the keyword to match the length of the plaintext
    k = k * (len(P) // len(k) + 1)
    for char in P:
        if (char.isalpha()):
            n = ord(char)
            # Calculate the shift based on the current key character
            to_add = ord(k[index].lower()) - ord('a')
            index += 1
            if (char.islower()):
                n += to_add
                if (n > ord('z')):
                    n -= 26
            else: # char is uppercase
                n += to_add
                if (n > ord('Z')):
                    n -= 26
            Cipher_text += chr(n)
        else:
            Cipher_text += char
    # Remove spaces for the final output
    Cipher_text = Cipher_text.replace(" ", "")
    return Cipher_text

# Vigenère Cipher Decryption
def vignere_decode(P, k):
    """
    Decrypts a ciphertext string using the Vigenère cipher.

    Args:
        P (str): The ciphertext to decrypt.
        k (str): The keyword used for encryption.
    """
    Cipher_text = ""
    index = 0
    # Extend the keyword to match the length of the ciphertext
    k = k * (len(P) // len(k) + 1)
    for char in P:
        if (char.isalpha()):
            n = ord(char)
            # Calculate the inverse shift based on the current key character
            to_add = ord(k[index].lower()) - ord('a')
            index += 1
            if (char.islower()):
                n -= to_add
                if (n < ord('a')):
                    n += 26
            else: # char is uppercase
                n -= to_add
                if (n < ord('A')):
                    n += 26
            Cipher_text += chr(n)
        else:
            Cipher_text += char
    print(Cipher_text)

# Autokey Cipher Encryption
def autokey(P, key):  # key is an integer representing the first character of the key
    """
    Encrypts a plaintext string using the Autokey cipher.

    Args:
        P (str): The plaintext message.
        key (int): The starting key value (0-25).

    Returns:
        str: The encrypted ciphertext.
    """
    if (P[0].islower()):
        add = 'a'
    else:
        add = 'A'
    # The autokey is formed by the initial key character followed by the plaintext itself
    k = chr(key + ord(add)) + P
    # Remove spaces from the key
    k = k.replace(" ", "")
    # Use the Vigenère encryption function with the newly generated autokey
    return (Vignere(P, k))

# Autokey Cipher Decryption
def autokey_decode(P, key):
    """
    Decrypts a ciphertext string using the Autokey cipher.

    Args:
        P (str): The ciphertext to decrypt.
        key (int): The starting key value (0-25) used for encryption.
    """
    if (P[0].islower()):
        add = 'a'
    else:
        add = 'A'
    plain_Text = ""
    # The initial key character is used to decrypt the first letter
    k = chr(key + ord(add))
    for i in range(len(P)):
        if (P[i].islower()):
            add = 'a'
        else:
            add = 'A'
        # Calculate the shift value from the current key character
        j = ord(k) - ord(add)
        # Decrypt the current character
        curr = ord(P[i]) - j
        if (add == 'a' and curr < ord('a')):
            curr += 26
        if (add == 'A' and curr < ord('A')):
            curr += 26
        # The newly decrypted character becomes the key for the next character
        k = chr(curr)
        plain_Text = plain_Text + k

    print(plain_Text)

# --- Main Execution ---
print("Plain Text:", Plain_Text)

print("\nVignere Cipher with Key=dollars:")
a = Vignere(Plain_Text, "dollars")
print("Encoded:")
print(a)
print("Decoded:")
vignere_decode(a, "dollars")

print("\nAutoKey Cipher with Key=7:")
a = autokey(Plain_Text, 7)
print("Encoded:")
print(a)
print("Decoded:")
autokey_decode(a, 7)
