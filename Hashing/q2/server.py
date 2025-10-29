"""
LAB 5 — Exercise 2 (Server)
----------------------------
Objective:
Use socket programming to demonstrate hash-based data integrity.

Description:
The server receives a message from the client, computes its hash,
and sends the computed hash back to the client for verification.
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
# Server Setup
# -------------------------------
HOST = '127.0.0.1'   # Localhost
PORT = 5000           # Port for communication

# Create socket
server_socket = socket.socket()
server_socket.bind((HOST, PORT))
server_socket.listen(1)
print(f"Server started on {HOST}:{PORT}, waiting for connection...")

# Wait for client connection
conn, addr = server_socket.accept()
print(f"Connected with client: {addr}")

# Receive data from client
data = conn.recv(1024).decode()
print(f"\nMessage received from client: {data}")

# Compute hash of received data
server_hash = compute_hash(data)
print(f"Computed Hash (Server side): {server_hash}")

# Send hash back to client
conn.send(server_hash.encode())
print("\nHash sent back to client for verification.")

# Close connection
conn.close()
server_socket.close()
