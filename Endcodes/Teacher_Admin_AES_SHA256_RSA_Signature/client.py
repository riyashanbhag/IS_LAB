"""
Teacher–Admin Secure Record System (Client)

→ Acts as Teacher:
   - Reads student file (name,marks).
   - AES encrypts file, encrypts AES key with Admin’s RSA (OAEP).
   - Signs file hash with Teacher’s RSA private key.
   - Builds hashed index (for search).
   - Sends all to Admin via socket.
"""

import socket, json, struct, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

HOST, PORT = "localhost", 9100
ADMIN_PUB, TEACHER_PRIV = "admin_rsa_pub.pem", "teacher_rsa_priv.pem"

def pkcs7_pad(data): pad = AES.block_size - len(data)%AES.block_size; return data + bytes([pad])*pad
def ensure_key():
    if not os.path.exists(TEACHER_PRIV):
        k = RSA.generate(2048)
        open(TEACHER_PRIV, "wb").write(k.export_key())
        open("teacher_rsa_pub.pem", "wb").write(k.publickey().export_key())

def send_file(path):
    ensure_key()
    admin_pub = RSA.import_key(open(ADMIN_PUB,"rb").read())
    teacher_priv = RSA.import_key(open(TEACHER_PRIV,"rb").read())
    oaep = PKCS1_OAEP.new(admin_pub)

    plain = open(path,"rb").read()
    aes_key, iv = get_random_bytes(32), get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    enc_file = cipher.encrypt(pkcs7_pad(plain))
    enc_key = oaep.encrypt(aes_key+iv)
    h = SHA256.new(plain)
    sig = pkcs1_15.new(teacher_priv).sign(h)

    # Build hash index (student names)
    idx = []
    for line in plain.decode().splitlines():
        if "," in line:
            name = line.split(",")[0].strip()
            if name: idx.append(SHA256.new(name.encode()).hexdigest())

    header = {
        "filename": os.path.basename(path),
        "enc_key_len": len(enc_key),
        "enc_file_len": len(enc_file),
        "sig_len": len(sig),
        "index_len": len(json.dumps(idx).encode())
    }

    with socket.socket() as s:
        s.connect((HOST, PORT))
        s.sendall(struct.pack("!I", len(json.dumps(header).encode())))
        s.sendall(json.dumps(header).encode())
        s.sendall(enc_key); s.sendall(enc_file); s.sendall(sig)
        s.sendall(json.dumps(idx).encode())

    print("[TEACHER] Sent file, key, signature, and index.")

if __name__ == "__main__":
    f = input("Enter path to student file: ")
    if os.path.exists(f): send_file(f)
    else: print("File not found.")
