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

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()

def start_client():
    s = socket.socket()
    s.connect(('localhost', 9999))

    username = input("Enter username: ")
    password = input("Enter password: ")

    hashed_pass = sha256_hash(password)
    data = f"{username},{hashed_pass}"
    s.send(data.encode())

    response = s.recv(1024).decode()
    print("Server Response:", response)
    s.close()

if __name__ == "__main__":
    start_client()
