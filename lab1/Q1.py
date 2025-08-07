def additive_ciphers(P, k):
    shifted_text = ""
    for char in P:
        if char.isalpha():
            n = ord(char) + k
            if char.islower() and n > ord('z'):
                n -= 26
            elif char.isupper() and n > ord('Z'):
                n -= 26
            shifted_text += chr(n)
        else:
            shifted_text += char
    return shifted_text


def additive_decode(P, k):
    shifted_text = ""
    for char in P:
        if char.isalpha():
            n = ord(char) - k
            if char.islower() and n < ord('a'):
                n += 26
            elif char.isupper() and n < ord('A'):
                n += 26
            shifted_text += chr(n)
        else:
            shifted_text += char
    return shifted_text


def multiplicative(P, k):
    Cipher_text = ""
    for char in P:
        if char.isalpha():
            minus = ord('a') if char.islower() else ord('A')
            n = (ord(char) - minus) * k % 26
            Cipher_text += chr(n + minus)
        else:
            Cipher_text += char
    return Cipher_text


def multiplicative_decode(P, key):
    try:
        k = pow(key, -1, 26)
    except ValueError:
        return "Inverse doesn't exist; can't decode."
    return multiplicative(P, k)


def Affine_Cipher(P, k1, k2):
    Cipher_text = ""
    for char in P:
        if char.isalpha():
            minus = ord('a') if char.islower() else ord('A')
            n = ((ord(char) - minus) * k1 + k2) % 26
            Cipher_text += chr(n + minus)
        else:
            Cipher_text += char
    return Cipher_text


def Affine_decode(P, k1, k2):
    try:
        k1_inverse = pow(k1, -1, 26)
    except ValueError:
        return "Inverse doesn't exist; can't decode."
    Cipher_text = ""
    for char in P:
        if char.isalpha():
            minus = ord('a') if char.islower() else ord('A')
            n = (ord(char) - minus - k2) % 26
            n = (n * k1_inverse) % 26
            Cipher_text += chr(n + minus)
        else:
            Cipher_text += char
    return Cipher_text


def menu():
    while True:
        print("\n========= Cipher Menu =========")
        print("1. Additive Cipher")
        print("2. Multiplicative Cipher")
        print("3. Affine Cipher")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            text = input("Enter the message: ")
            key = int(input("Enter additive key (0-25): "))
            action = input("Encode or Decode (e/d)? ").lower()
            if action == 'e':
                result = additive_ciphers(text, key)
            else:
                result = additive_decode(text, key)
            print(f"\nResult: {result}")

        elif choice == '2':
            text = input("Enter the message: ")
            key = int(input("Enter multiplicative key (must be coprime to 26): "))
            action = input("Encode or Decode (e/d)? ").lower()
            if action == 'e':
                result = multiplicative(text, key)
            else:
                result = multiplicative_decode(text, key)
            print(f"\nResult: {result}")

        elif choice == '3':
            text = input("Enter the message: ")
            k1 = int(input("Enter key1 (multiplicative part, coprime to 26): "))
            k2 = int(input("Enter key2 (additive part): "))
            action = input("Encode or Decode (e/d)? ").lower()
            if action == 'e':
                result = Affine_Cipher(text, k1, k2)
            else:
                result = Affine_decode(text, k1, k2)
            print(f"\nResult: {result}")

        elif choice == '4':
            print("Exiting.")
            break
        else:
            print("Invalid option. Try again.")

# Run the menu
menu()
