# -------------------- RSA Digital Signature --------------------
import hashlib
import random
import math
#-----------------------------------------------
# Then you can replace those three functions with the following:
#----------------------------------------------------
def rsa_keygen(bits=64):
    def egcd(a, b):
        if b == 0:
            return (1, 0, a)
        x, y, g = egcd(b, a % b)
        return (y, x - (a // b) * y, g)

    def inv_mod(a, m):
        x, y, g = egcd(a, m)
        return x % m

    # generate two primes
    def gen_prime(bits=32):
        while True:
            p = random.getrandbits(bits) | 1 | (1 << (bits-1))
            if is_probable_prime(p):
                return p

    p = gen_prime(bits//2)
    q = gen_prime(bits//2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    d = inv_mod(e, phi)
    return n, e, d

def rsa_sign(message: bytes, d, n):
    h = int(hashlib.sha256(message).hexdigest(), 16)
    return pow(h, d, n)

def rsa_verify(message: bytes, signature, e, n):
    h = int(hashlib.sha256(message).hexdigest(), 16)
    return pow(signature, e, n) == h % n


#------------------------------------------------------
# in your main section, just replace this block:
#-------------------------------------------------------

# ElGamal demo
print("\n=== RSA Digital Signature Demo ===")
n, e, d = rsa_keygen()
msg = b"Test message"
sig = rsa_sign(msg, d, n)
print("Signature valid:", rsa_verify(msg, sig, e, n))


