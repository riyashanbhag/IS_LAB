"""
ANSWER TO:
"Try using the Elgammal, Schnor asymmetric encryption standard and verify the above steps."

This program demonstrates the **ElGamal Digital Signature Scheme** using Python.

Steps Implemented:
1. Generate keys: Choose a large prime `p`, a primitive root `g`, and private key `x`.
2. Sign a message using ElGamal signature algorithm.
3. Verify the signature using the public key.
4. Ensures message integrity and authenticity (digital signature verification).

This code can be used in the DBS Lab (Lab 6) to demonstrate asymmetric encryption
and signature verification using the ElGamal standard.
"""
import hashlib
import random

#---------------
# hash function
#--------------------

def hash_message(msg):
    """Return integer hash of a message using SHA-1."""
    return int(hashlib.sha1(msg.encode()).hexdigest(), 16)

#-----------------------------

# ------------------------------
# GCD  Function
# ------------------------------

def gcd(a, b):
    """Greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a
# ------------------------------

# ------------------------------
# ElGamal Signature Functions
# ------------------------------

def elgamal_signature(p, g, x, message):
    """Generate ElGamal digital signature for a message."""
    h = hash_message(message)
    while True:
        k = random.randint(2, p - 2)
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = ((h - x * r) * k_inv) % (p - 1)
    return (r, s)

def verify_elgamal(p, g, y, message, r, s):
    """Verify ElGamal digital signature."""
    h = hash_message(message)
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, h, p)
    return v1 == v2
#-----------------------------

#-------------
#main program
#----------------
if __name__=="__main__":
    print("\n--- ElGamal Digital Signature Demo ---")

# Public parameters
    p = 467               # Large prime number
    g = 2                 # Primitive root modulo p
    # Private and Public keys
    x = 127  # Private key (kept secret)
    y = pow(g, x, p)  # Public key (shared)

    print(f"Public key (p, g, y): ({p}, {g}, {y})")
    print(f"Private key (x): {x}")

#   input message
message=input("\nEnter message to sign: ")

# Signing
r,s=elgamal_signature(p,g,x,message)
print(f"\nDigital Signature: (r={r}, s={s})")
hash_message_result=hash_message(message)
print(f"hash_message_result: {hash_message_result}")
# Verification
result = verify_elgamal(p, g, y, message, r, s)
print("\nVerification Result:", "Valid ✅" if result else "Invalid ❌")
