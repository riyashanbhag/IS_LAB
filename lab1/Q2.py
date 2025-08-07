def preprocess_text(text):
    return "".join(filter(str.isalpha, text)).upper()


def char_to_int(char):
    return ord(char) - ord('A')


def int_to_char(integer):
    return chr(integer + ord('A'))


# Vigenère Cipher
def vigenere_encrypt(plaintext, key):
    pt = preprocess_text(plaintext)
    key = preprocess_text(key)
    ciphertext = ""
    for i in range(len(pt)):
        p = char_to_int(pt[i])
        k = char_to_int(key[i % len(key)])
        c = (p + k) % 26
        ciphertext += int_to_char(c)
    return ciphertext


def vigenere_decrypt(ciphertext, key):
    key = preprocess_text(key)
    plaintext = ""
    for i in range(len(ciphertext)):
        c = char_to_int(ciphertext[i])
        k = char_to_int(key[i % len(key)])
        p = (c - k) % 26
        plaintext += int_to_char(p)
    return plaintext


# Autokey Cipher
def autokey_encrypt(plaintext, initial_key_val):
    pt = preprocess_text(plaintext)
    ciphertext = ""
    for i in range(len(pt)):
        p = char_to_int(pt[i])
        if i == 0:
            k = initial_key_val
        else:
            k = char_to_int(pt[i - 1])
        c = (p + k) % 26
        ciphertext += int_to_char(c)
    return ciphertext


def autokey_decrypt(ciphertext, initial_key_val):
    plaintext = ""
    for i in range(len(ciphertext)):
        c = char_to_int(ciphertext[i])
        if i == 0:
            k = initial_key_val
        else:
            k = char_to_int(plaintext[i - 1])
        p = (c - k) % 26
        plaintext += int_to_char(p)
    return plaintext


# --- MENU ---
def menu():
    while True:
        print("\n==== Cipher Menu ====")
        print("1. Vigenère Cipher")
        print("2. Autokey Cipher")
        print("3. Exit")

        choice = input("Choose an option (1-3): ").strip()

        if choice == '1':
            print("\n--- Vigenère Cipher ---")
            text = input("Enter your message: ")
            key = input("Enter the key (letters only): ")
            operation = input("Encrypt or Decrypt? (e/d): ").strip().lower()

            if operation == 'e':
                result = vigenere_encrypt(text, key)
                print("Encrypted Message:", result)
            elif operation == 'd':
                text = preprocess_text(text)
                result = vigenere_decrypt(text, key)
                print("Decrypted Message:", result)
            else:
                print("Invalid operation.")

        elif choice == '2':
            print("\n--- Autokey Cipher ---")
            text = input("Enter your message: ")
            try:
                key_val = int(input("Enter initial key (0-25): "))
                if not (0 <= key_val <= 25):
                    raise ValueError
            except ValueError:
                print("Invalid key. Please enter a number from 0 to 25.")
                continue

            operation = input("Encrypt or Decrypt? (e/d): ").strip().lower()

            if operation == 'e':
                result = autokey_encrypt(text, key_val)
                print("Encrypted Message:", result)
            elif operation == 'd':
                text = preprocess_text(text)
                result = autokey_decrypt(text, key_val)
                print("Decrypted Message:", result)
            else:
                print("Invalid operation.")

        elif choice == '3':
            print("Exiting. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")


# Run the menu
if __name__ == "__main__":
    menu()
