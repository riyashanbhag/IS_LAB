def encrypt(plaintext, key):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():
            # Shift character by key positions
            shift = key % 26
            if char.islower():
                ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
            else:
                ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        else:
            ciphertext += char  # Non-alphabetical characters unchanged
    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            shift = key % 26
            if char.islower():
                plaintext += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                plaintext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            plaintext += char
    return plaintext

def menu():
    while True:
        print("\nMenu:")
        print("1. Encrypt plaintext")
        print("2. Decrypt ciphertext")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            plaintext = input("Enter plaintext: ")
            key = int(input("Enter key (shift value): "))
            ciphertext = encrypt(plaintext, key)
            print(f"Ciphertext: {ciphertext}")

        elif choice == '2':
            ciphertext = input("Enter ciphertext: ")
            key = int(input("Enter key (shift value): "))
            plaintext = decrypt(ciphertext, key)
            print(f"Plaintext: {plaintext}")

        elif choice == '3':
            print("Exiting program. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
