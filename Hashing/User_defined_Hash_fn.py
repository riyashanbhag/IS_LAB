"""
LAB 5 — Exercise 1
-------------------
Objective:
Implement a user-defined hash function in Python.

Description:
This program demonstrates a simple custom hash function similar to the 
"DJB2" algorithm. It starts with an initial hash value of 5381, 
multiplies the hash by 33 for each character, adds the ASCII value 
of the character, and uses bitwise operations to ensure good mixing 
and a final 32-bit hash output.
"""

# -------------------------------
# Custom Hash Function Definition
# -------------------------------

def custom_hash(message):
    """
    Custom hash function that:
    1. Starts with hash = 5381
    2. For each character:
       - Multiplies hash by 33
       - Adds ASCII value of the character
       - Applies 32-bit mask to keep hash within range
    """
    
    hash_val = 5381  # Initial hash value
    
    for ch in message:
        # Multiply by 33 and add ASCII value of the character
        hash_val = ((hash_val * 33) + ord(ch)) & 0xFFFFFFFF  
        # '& 0xFFFFFFFF' ensures the result stays within 32 bits

    return hash_val


# -------------------------------
# Main Program
# -------------------------------

if __name__ == "__main__":
    print("\n--- Custom Hash Function Demo ---\n")
    
    # Get user input
    text = input("Enter a message to hash: ")
    
    # Compute custom hash
    result = custom_hash(text)
    
    # Display results
    print("\nOriginal Message:", text)
    print("Computed Hash Value (32-bit):", result)
    print("Hash Value in Hexadecimal:", hex(result))
