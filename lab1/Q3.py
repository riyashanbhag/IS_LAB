# Use the Playfair cipher to encipher the message "The key is hidden under the door pad". The
# secret key can be made by filling the first and part of the second row with the word
# "GUIDANCE" and filling the rest of the matrix with the rest of the alphabet

def create_playfair_matrix(key):
    """
    Creates the 5x5 Playfair cipher matrix based on the given key.
    'J' is implicitly treated as 'I' as 'J' is excluded from the alphabet.
    """
    # Remove duplicates from key while preserving order
    # sorted(set(key), key=key.index) ensures order is preserved for unique characters
    unique_key = "".join(sorted(set(key.upper()), key=key.upper().index))

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is intentionally excluded here

    matrix_letters = []

    # Add unique key characters to the matrix list
    for char in unique_key:
        if char not in matrix_letters:  # Double check in case of lower/upper mix-up if not .upper()
            matrix_letters.append(char)

    # Fill the rest with remaining alphabet characters
    for char in alphabet:
        if char not in matrix_letters:
            matrix_letters.append(char)

    # Reshape the 25 letters into a 5x5 matrix (list of lists)
    return [matrix_letters[i:i + 5] for i in range(0, 25, 5)]


def find_position(matrix, char):
    """
    Finds the (row, col) position of a character in the Playfair matrix.
    Assumes 'J' has been replaced by 'I' in the input character if necessary.
    """
    for i, row in enumerate(matrix):  # i is the row index, row is the actual list (row)
        if char in row:
            return i, row.index(char)  # Return row index and column index
    return None  # Should not happen if character is valid and matrix is complete


def playfair_encipher(pair, matrix):
    """
    Enciphers a two-character pair (digraph) using the Playfair rules.
    """
    r1, c1 = find_position(matrix, pair[0])
    r2, c2 = find_position(matrix, pair[1])

    if r1 == r2:  # Same row: shift right (wrap around)
        return matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5]
    elif c1 == c2:  # Same column: shift down (wrap around)
        return matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2]
    else:  # Different row and column (rectangle rule): swap columns
        return matrix[r1][c2] + matrix[r2][c1]


def prepare_text(text):
    """
    Prepares the plaintext message for Playfair encryption.
    1. Converts to uppercase.
    2. Replaces 'J' with 'I'.
    3. Removes spaces.
    4. Handles double letters by inserting 'X' between them.
    5. Pads with 'X' at the end if the total length is odd.
    """
    text = text.upper().replace("J", "I").replace(" ", "")
    prepared_text = ""

    i = 0
    while i < len(text):
        prepared_text += text[i]  # Add current character

        # Check for double letters or if it's the last character
        if i + 1 < len(text) and text[i] == text[i + 1]:
            prepared_text += 'X'  # Insert 'X' if consecutive identical characters
            # Do NOT advance 'i' for the second identical char, it needs to be processed again
            i += 1  # Advance 'i' to the next character in original text for the loop
        else:
            # If not a double letter, add the next character (if available)
            if i + 1 < len(text):
                prepared_text += text[i + 1]
            i += 2  # Advance 'i' by two characters (a full pair)

    # Ensure the prepared text has an even length by padding with 'X' if necessary
    if len(prepared_text) % 2 != 0:
        prepared_text += 'X'

    return prepared_text


def playfair_cipher(text, key):
    """
    Encrypts an entire message using the Playfair cipher.
    """
    matrix = create_playfair_matrix(key)
    prepared_text = prepare_text(text)
    ciphertext = ""

    # Process the prepared text in pairs
    for i in range(0, len(prepared_text), 2):
        ciphertext += playfair_encipher(prepared_text[i:i + 2], matrix)

    return ciphertext


# --- Input and Execution ---
if __name__ == "__main__":
    message = "The key is hidden under the door pad"
    secret_key = "GUIDANCE"

    # Encipher the text
    ciphertext = playfair_cipher(message, secret_key)

    # Print the output in the specified format
    print("Ciphertext:", ciphertext)