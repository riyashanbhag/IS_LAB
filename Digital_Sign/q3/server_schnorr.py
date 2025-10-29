"""
ANSWER TO:
"Try the same in a client-server–based scenario and record your observation and analysis."

This program demonstrates a **Server** that verifies a digital signature 
sent by a **Client** using the **Schnorr Asymmetric Digital Signature Scheme**.

The server:
1. Listens for an incoming client connection.
2. Receives the message, signature, and public parameters.
3. Performs signature verification using the public key.
4. Displays whether the signature is VALID or INVALID.
"""

import socket
import hashlib

# --------------------------------------------------------
# Helper Function: Compute hash of the message using SHA-1
# --------------------------------------------------------
def hash_message(msg):
    """Converts a text message into a numeric hash value using SHA-1."""
    return int(hashlib.sha1(msg.encode()).hexdigest(), 16)

# --------------------------------------------------------
# Function to verify the Schnorr digital signature
# --------------------------------------------------------
def schnorr_verify(p, q, g, y, message, e, s):
    """
    Verify the Schnorr digital signature.
    - p, q, g : Public domain parameters
    - y       : Public key of the signer
    - message : Original message received
    - e, s    : Signature components
    """
    # Compute (y^e)^(-1) mod p → inverse part of verification
    y_e_inv = pow(pow(y, e, p), -1, p)

    # Compute r' = (g^s * (y^e)^-1) mod p
    r_calc = (pow(g, s, p) * y_e_inv) % p

    # Compute e' = H(r' || message) mod q
    e_calc = (hash_message(str(r_calc) + message)) % q

    # Signature is valid if computed e' == received e
    return e_calc == e

# --------------------------------------------------------
# SERVER CODE
# --------------------------------------------------------
HOST = '127.0.0.1'   # Localhost (loopback address)
PORT = 5000          # Port to listen on

# Create a socket and start listening for a connection
s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)
print("✅ Server is listening... Waiting for client connection.")

# Accept client connection
conn, addr = s.accept()
print(f"🔗 Connected with client: {addr}")

# Receive data from client
data = conn.recv(4096).decode()
parts = data.split("||")  # Split message using custom separator

# Extract data fields from received message
message = parts[0]
e = int(parts[1])
s_val = int(parts[2])
p = int(parts[3])
q = int(parts[4])
g = int(parts[5])
y = int(parts[6])

# Display received data
print("\n--- 📦 Data Received from Client ---")
print(f"Message: {message}")
print(f"Signature (e, s): ({e}, {s_val})")
print(f"Public Parameters -> p: {p}, q: {q}, g: {g}, y: {y}")

# Verify the digital signature
valid = schnorr_verify(p, q, g, y, message, e, s_val)

# Display verification result
print("\n🔍 Verification Result:", "✅ Valid Signature" if valid else "❌ Invalid Signature")

# Close connection
conn.close()
print("\n🔒 Connection closed. Server shutting down.")
