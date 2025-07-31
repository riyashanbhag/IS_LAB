def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def decrypt_affine(ciphertext, a, b):
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        raise ValueError("No multiplicative inverse")

    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            y = ord(char.upper()) - ord('A')
            x = (a_inv * (y - b)) % 26
            plaintext += chr(x + ord('a'))  # lowercase output
        else:
            plaintext += char
    return plaintext

ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
a = 5
b = 6

plaintext = decrypt_affine(ciphertext, a, b)
print(plaintext)
