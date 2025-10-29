"""
CLIENT PROGRAM
---------------
This program implements the **Schnorr Digital Signature Scheme** in a 
**Client-Server communication model**.

The client:
1. Generates public/private keys and a digital signature for a message.
2. Sends the message, signature, and public parameters to the server.
3. The server verifies if the signature is authentic.

This demonstrates secure message verification using asymmetric cryptography.
"""

import socket
import random
import hashlib

# --------------------------------------------------------
# Helper Function: Compute hash of message using SHA-1
# --------------------------------------------------------
def hash_message(msg):
    """Converts the given message into a numeric hash using SHA-1."""
    return int(hashlib.sha1(msg.encode()).hexdigest(), 16)

# --------------------------------------------------------
# Function to generate the Schnorr signature
# --------------------------------------------------------
def schnorr_sign(p, q, g, x, message):
    """
    Generates a Schnorr digital signature for the given message.
    - p, q, g : Public domain parameters
    - x       : Private key
    - message : The text message to sign
    Returns: tuple (e, s)
    """
    # Step 1: Choose random number k (1 ≤ k ≤ q-1)
    k = random.randint(1, q - 1)

    # Step 2: Compute r = g^k mod p
    r = pow(g, k, p)

    # Step 3: Compute hash-based challenge e = H(r || message) mod q
    e = (hash_message(str(r) + message)) % q

    # Step 4: Compute signature component s = (k + x*e) mod q
    s = (k + x * e) % q

    return (e, s)

# --------------------------------------------------------
# CLIENT CODE
# --------------------------------------------------------

# Define server address
HOST = '127.0.0.1'  # Localhost
PORT = 5000         # Must match the server port

# Public domain parameters (can be known to everyone)
p = 467  # Large prime number
q = 233  # Prime divisor of (p-1)
g = 2    # Generator value

# Step 1: Generate keys
# Private key x: random secret known only to sender
x = random.randint(1, q - 1)

# Public key y = g^x mod p
y = pow(g, x, p)

# Step 2: Take message input from user
message = input("Enter message to sign: ")

# Step 3: Generate signature (e, s)
e, s_val = schnorr_sign(p, q, g, x, message)

# Step 4: Display generated data
print(f"\n📩 Message: {message}")
print(f"🖋️ Digital Signature: (e = {e}, s = {s_val})")
print(f"🔑 Public Key (y): {y}")

# Step 5: Prepare data for transmission to server
data = f"{message}||{e}||{s_val}||{p}||{q}||{g}||{y}"

# Step 6: Create socket and connect to the server
client = socket.socket()
client.connect((HOST, PORT))

# Step 7: Send data to server
client.send(data.encode())
print("\n✅ Message and signature sent to server successfully.")

# Step 8: Close connection
client.close()
print("🔒 Connection closed.")
