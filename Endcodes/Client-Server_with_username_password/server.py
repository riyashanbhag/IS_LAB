# ============================================================
# Level 2 — Applied Security
#
# Client–Server Authentication
#   Client sends username + hashed password (MD5/SHA-256).
#   Server verifies credentials using stored hash.
#   Print “Access Granted” or “Access Denied.”
#
# ElGamal Digital Signature System
#   Implement key generation, signing, and verification.
#   Demonstrate with a sample message.
#
# Homomorphic RSA Simulation
#   Encrypt two integer values.
#   Show that multiplication of ciphertexts corresponds
#   to addition of plaintexts (approximate demonstration).
# ============================================================

import socket
import hashlib
import random
import math

# -------------------- Hash Utilities --------------------
def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

# -------------------- Authentication --------------------
USER_DB = {
    "alice": sha256_hash("s3cr3t-password"),
    "bob": sha256_hash("hunter2")
}

def verify_credentials(username, hashed_password):
    if username in USER_DB and USER_DB[username] == hashed_password:
        return "Access Granted"
    return "Access Denied"

# -------------------- ElGamal Signature --------------------
def egcd(a, b):
    if b == 0:
        return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def inv_mod(a, m):
    x, y, g = egcd(a % m, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

def is_probable_prime(n, k=8):
    if n < 2: return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n-2)
        x = pow(a, d, n)
        if x == 1 or x == n-1: continue
        for __ in range(s-1):
            x = pow(x, 2, n)
            if x == n-1: break
        else:
            return False
    return True

def gen_prime(bits=64):
    while True:
        p = random.getrandbits(bits) | 1 | (1 << (bits-1))
        if is_probable_prime(p):
            return p

def find_generator(p):
    phi = p-1
    factors = set()
    n, d = phi, 2
    while d*d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1: factors.add(n)
    for g in range(2, p):
        if all(pow(g, phi//q, p) != 1 for q in factors):
            return g
    return 2

def elgamal_keygen(bits=64):
    p = gen_prime(bits)
    g = find_generator(p)
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    return p, g, x, y

def elgamal_sign(message: bytes, p, g, x):
    h = int(hashlib.sha256(message).hexdigest(), 16)
    p1 = p - 1
    while True:
        k = random.randrange(2, p1)
        if math.gcd(k, p1) == 1: break
    r = pow(g, k, p)
    k_inv = inv_mod(k, p1)
    s = (k_inv * (h - x * r)) % p1
    return r, s

def elgamal_verify(message: bytes, signature, p, g, y):
    r, s = signature
    h = int(hashlib.sha256(message).hexdigest(), 16)
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

# -------------------- RSA Homomorphic Demo --------------------
def rsa_keygen(bits=64):
    def inv_mod(a, m):
        x, y, g = egcd(a, m)
        return x % m

    p = gen_prime(bits//2)
    q = gen_prime(bits//2)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2
    d = inv_mod(e, phi)
    return n, e, d

def rsa_encrypt(m, e, n):
    return pow(m, e, n)

def rsa_decrypt(c, d, n):
    return pow(c, d, n)

# -------------------- Server Function --------------------
def start_server():
    s = socket.socket()
    s.bind(('localhost', 9999))
    s.listen(1)
    print("Server listening on port 9999...")

    conn, addr = s.accept()
    print("Connected to:", addr)
    data = conn.recv(1024).decode()
    username, hashed_pass = data.split(',')
    result = verify_credentials(username, hashed_pass)
    conn.send(result.encode())
    conn.close()
    s.close()

    print(f"Authentication result for {username}: {result}")

# -------------------- Run --------------------
if __name__ == "__main__":
    start_server()

    # ElGamal demo
    print("\n=== ElGamal Digital Signature Demo ===")
    p, g, x, y = elgamal_keygen()
    msg = b"Test message"
    sig = elgamal_sign(msg, p, g, x)
    print("Signature valid:", elgamal_verify(msg, sig, p, g, y))

    # Homomorphic RSA demo
    print("\n=== RSA Homomorphic Demo ===")
    n, e, d = rsa_keygen()
    m1, m2 = 12, 7
    c1 = rsa_encrypt(m1, e, n)
    c2 = rsa_encrypt(m2, e, n)
    c_prod = (c1 * c2) % n
    print(f"Decrypted(c1*c2) = {rsa_decrypt(c_prod, d, n)}  | Expected = {m1*m2 % n}")
