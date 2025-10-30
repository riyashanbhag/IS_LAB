"""
dh_users.py

Demo: Two users (A and B) create username/passwords, then perform a Diffie-Hellman
key exchange to derive a shared symmetric key. The script then encrypts a sample
message from A to B using AES-GCM and B decrypts it to verify the shared key.

NOTES:
- Password hashing here uses hashlib.sha256 for simplicity (educational).
  In real systems use a proper password hashing algorithm (bcrypt/scrypt/Argon2).
- Uses cryptography package for DH, HKDF, and AES-GCM.
"""

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def hash_password(password: str) -> str:
    """Simple SHA-256 password hash (hex). For demo only."""
    return hashlib.sha256(password.encode()).hexdigest()


def create_user(prompt_name: str):
    """Interactively create a user with username and password (hashed)."""
    username = input(f"Enter username for {prompt_name}: ").strip()
    password = input(f"Enter password for {prompt_name}: ").strip()
    pw_hash = hash_password(password)
    print(f"{prompt_name} created. Stored password hash (hex): {pw_hash}\n")
    return {"username": username, "password_hash": pw_hash}


def dh_generate_parameters():
    """Generate DH parameters once (both parties use same group)."""
    print("Generating Diffie-Hellman parameters (this may take a moment)...")
    params = dh.generate_parameters(generator=2, key_size=2048)
    print("DH parameters generated.\n")
    return params


def dh_create_keypair(parameters):
    """Create a DH private key and return (private_key, public_bytes)."""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    # Serialize public key to send to peer
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_bytes


def dh_load_public_key(public_bytes):
    """Load peer's public key from serialized bytes."""
    return serialization.load_pem_public_key(public_bytes)


def derive_shared_key(our_private_key, peer_public_key):
    """Do the DH exchange and derive a symmetric key using HKDF (SHA256)."""
    shared_secret = our_private_key.exchange(peer_public_key)
    # Derive a 32-byte key for AES-256 using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dh-shared-key-demo",
    ).derive(shared_secret)
    return derived_key


def encrypt_message(key: bytes, plaintext: bytes) -> dict:
    """Encrypt with AES-GCM. Returns dict with nonce and ciphertext."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"nonce": nonce, "ciphertext": ct}


def decrypt_message(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return pt


def main():
    print("\n=== Simple DH Key Exchange Demo between User A and User B ===\n")

    # 1) Create users A and B (username + password)
    user_a = create_user("User A")
    user_b = create_user("User B")

    # For demonstration we show stored hashes; in a real system these would be in DB
    print("Stored credentials (hashed passwords):")
    print("User A:", user_a["username"], user_a["password_hash"])
    print("User B:", user_b["username"], user_b["password_hash"])
    print()

    # 2) Generate DH parameters (group) and create keypairs for A and B
    params = dh_generate_parameters()

    a_priv, a_pub_bytes = dh_create_keypair(params)
    b_priv, b_pub_bytes = dh_create_keypair(params)

    # Show (PEM) public keys (shortened) — these would be exchanged over network
    print("User A public key (PEM, first 120 chars):")
    print(a_pub_bytes.decode()[:120].replace("\n", " ") + "...\n")
    print("User B public key (PEM, first 120 chars):")
    print(b_pub_bytes.decode()[:120].replace("\n", " ") + "...\n")

    # 3) Each party loads the other's public key and derives the shared key
    a_peer_pub = dh_load_public_key(b_pub_bytes)
    b_peer_pub = dh_load_public_key(a_pub_bytes)

    a_shared_key = derive_shared_key(a_priv, a_peer_pub)
    b_shared_key = derive_shared_key(b_priv, b_peer_pub)

    # Check both derived the same symmetric key
    print("Derived shared symmetric key (hex):")
    print("User A:", a_shared_key.hex())
    print("User B:", b_shared_key.hex())
    print()
    if a_shared_key == b_shared_key:
        print("SUCCESS: Both users derived the same shared key.\n")
    else:
        print("ERROR: Keys differ! DH exchange failed.\n")
        return

    # 4) Demonstrate secure communication using the shared key (AES-GCM)
    message = input("Enter a plaintext message that User A will send to User B: ").encode()
    enc = encrypt_message(a_shared_key, message)
    print("\nUser A encrypted ciphertext (hex, first 120 chars):")
    print(enc["ciphertext"].hex()[:240] + "...\n")

    # 5) User B decrypts
    decrypted = decrypt_message(b_shared_key, enc["nonce"], enc["ciphertext"])
    print("User B decrypted message:")
    print(decrypted.decode())
    print("\nDemo complete. Diffie-Hellman key exchange and secure message exchange succeeded.\n")


if __name__ == "__main__":
    main()
