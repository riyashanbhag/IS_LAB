"""
ANSWER TO:
"Try using the Elgammal, Schnor asymmetric encryption standard and verify the above steps."

This program demonstrates the **Schnorr Digital Signature Scheme** using Python.

Steps Implemented:
1. Generate keys: Select a large prime `p`, subgroup prime `q`, generator `g`, 
   and private key `x`.
2. Sign a message using Schnorr signature algorithm.
3. Verify the signature using the public key.
4. Ensures message integrity and authenticity (digital signature verification).

This code can be used in the DBS Lab (Lab 6) to demonstrate asymmetric encryption
and signature verification using the **Schnorr standard**.
"""

import hashlib
import random

# ------------------------------
# Hash Function
# ------------------------------
def hash_message(msg):
    """Return integer hash of a message using SHA-1."""
    return int(hashlib.sha1(msg.encode()).hexdigest(), 16)

# ------------------------------
# GCD Function
# ------------------------------
def gcd(a, b):
    """Greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a

# ------------------------------
# Schnorr Signature Functions
# ------------------------------
def schnorr_sign(p, q, g, x, message):
    """Generate Schnorr digital signature for a message."""
    k = random.randint(1, q - 1)
    r = pow(g, k, p)
    e = (hash_message(str(r) + message)) % q
    s = (k + x * e) % q
    return (e, s)

def schnorr_verify(p, q, g, y, message, e, s):
    """Verify Schnorr digital signature."""
    # FIXED: use modular inverse of y^e mod p
    y_e_inv = pow(pow(y, e, p), -1, p)
    r_calc = (pow(g, s, p) * y_e_inv) % p
    e_calc = (hash_message(str(r_calc) + message)) % q
    return e_calc == e

# ------------------------------
# Main Program
# ------------------------------
if __name__ == "__main__":
    print("\n--- Schnorr Digital Signature Demo ---")

    # Public parameters
    p = 467               # Large prime number
    q = 233               # Subgroup prime (divides p−1)
    g = 2                 # Generator of subgroup

    # Private and Public keys
    x = random.randint(1, q - 1)  # Private key
    y = pow(g, x, p)              # Public key

    print(f"Public key (p, q, g, y): ({p}, {q}, {g}, {y})")
    print(f"Private key (x): {x}")

    # Input message
    message = input("\nEnter message to sign: ")

    # Signing
    e, s = schnorr_sign(p, q, g, x, message)
    print(f"\nDigital Signature: (e={e}, s={s})")

    # Print hash for reference
    hash_message_result = hash_message(message)
    print(f"Hash of message: {hash_message_result}")

    # Verification
    result = schnorr_verify(p, q, g, y, message, e, s)
    print("\nVerification Result:", "Valid ✅" if result else "Invalid ❌")
