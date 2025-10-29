"""
LAB 5 — Exercise 2 (Client)
----------------------------
Objective:
Demonstrate hash-based data integrity check using sockets.

Description:
The client sends data to the server, receives the hash computed by the server,
and verifies if the received hash matches its own computed hash.
This detects any corruption or tampering during transmission.
"""

import socket
import hashlib

# -------------------------------
# Helper: Compute SHA-256 Hash
# -------------------------------
def compute_hash(data):
    """Compute SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode()).hexdigest()

# -------------------------------
# Client Setup
# -------------------------------
HOST = '127.0.0.1'   # Server address
PORT = 5000           # Port must match the server

# Create socket
client_socket = socket.socket()
client_socket.connect((HOST, PORT))

# Input message
message = input("Enter the message to send to server: ")

# Send message to server
client_socket.send(message.encode())

# Receive hash from server
server_hash = client_socket.recv(1024).decode()

# Compute hash locally
client_hash = compute_hash(message)

# Display both hashes
print("\n--- Data Integrity Verification ---")
print(f"Message sent: {message}")
print(f"Client Computed Hash: {client_hash}")
print(f"Server Returned Hash: {server_hash}")

# Compare both hashes
if client_hash == server_hash:
    print("\n✅ Data Integrity Verified! No Tampering Detected.")
else:
    print("\n❌ Data Integrity Failed! Message may have been altered.")

# Close connection
client_socket.close()
