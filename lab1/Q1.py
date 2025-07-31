
Plain_text = "I am learning information security"

def additive_ciphers(P, k):
    shifted_text = ""
    for char in P:
        if char.isalpha():
            n = ord(char) + k
            # Wrap around if it goes beyond 'z' or 'Z'
            if char.islower() and n > ord('z'):
                n -= 26
            elif char.isupper() and n > ord('Z'):
                n -= 26
            shifted_text += chr(n)
        else:
            shifted_text += char  # Leave non-alphabetic characters unchanged
    return (shifted_text)


def additive_decode(P, k):
    shifted_text = ""
    for char in P:
        if char.isalpha():
            n = ord(char) - k
            # Wrap around if it goes beyond 'z' or 'Z'
            if char.islower() and n < ord('a'):
                n += 26
            elif char.isupper() and n < ord('A'):
                n += 26
            shifted_text += chr(n)
        else:
            shifted_text += char  # Leave non-alphabetic characters unchanged
    print(shifted_text)


def multiplicative(P, k):
    Cipher_text = ""
    for char in P:
        if char.isalpha():
            if (char.islower()):
                minus = ord('a')
                n = (ord(char) - minus) * k
                n %= 26
            else:
                minus = ord('A')
                n = (ord(char) - minus) * k
                n %= 26
            Cipher_text += chr(n + minus)
        else:
            Cipher_text += char
    return Cipher_text


def multiplicative_decode(P, key):
    try:
        k = pow(key, -1, 26)
    except ValueError: # Changed generic except to ValueError for clarity
        print("Inverse Doesn't exist so can't be decoded")
        return
    print(multiplicative(P, k))


def Affine_Cipher(P, k1, k2):
    Cipher_text = ""
    for char in P:
        if char.isalpha():
            if (char.islower()):
                minus = ord('a')
                n = (ord(char) - minus) * k1
                n += k2
                n %= 26
            else:
                minus = ord('A')
                n = (ord(char) - minus) * k1
                n += k2
                n %= 26
            Cipher_text += chr(n + minus)
        else:
            Cipher_text += char
    return Cipher_text


def Affine_decode(P, k1, k2):
    try:
        k1_inverse = pow(k1, -1, 26)  # pow(a,b,c) ie (a^b)mod c
    except ValueError: # Changed generic except to ValueError for clarity
        print("Inverse Doesn't exist so can't be decoded")
        return
    Cipher_text = ""
    for char in P:
        if char.isalpha():
            if (char.islower()):
                minus = ord('a')
                n = ord(char) - k2
                if (n < ord('a')):
                    n += 26
                n = (n - minus) * k1
                n %= 26
            else:
                minus = ord('A')
                n = ord(char) - k2
                if (n < ord('A')):
                    n += 26
                n = (n - minus) * k1
                n %= 26
            Cipher_text += chr(n + minus)
        else:
            Cipher_text += char
    print(Cipher_text)



print(f"Original PlainText: {Plain_text}\n")



print("a) Additive Cipher with Key = 20")

a_additive_encoded = additive_ciphers(Plain_text, 20)
print("Encoded Message:")
print(f"  {a_additive_encoded}")
print("\nDecoded Message:")
additive_decode(a_additive_encoded, 20)
print("\n")


# b) Multiplicative Cipher

print("b) Multiplicative Cipher with Key = 15")

a_multiplicative_encoded = multiplicative(Plain_text, 15)
print("Encoded Message:")
print(f"  {a_multiplicative_encoded}")
print("\nDecoded Message:")
multiplicative_decode(a_multiplicative_encoded, 15)
print("\n")


# c) Affine Cipher

print("c) Affine Cipher with Key = (15, 20)")

a_affine_encoded = Affine_Cipher(Plain_text, 15, 20)
print("Encoded Message:")
print(f"  {a_affine_encoded}")
print("\nDecoded Message:")
Affine_decode(a_affine_encoded, 15, 20)
print("\n")




