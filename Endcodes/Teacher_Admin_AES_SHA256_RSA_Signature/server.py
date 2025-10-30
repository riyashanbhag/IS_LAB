"""
Teacher–Admin Secure Record System (Server)

→ Acts as Admin:
   - Receives AES-encrypted file, RSA-encrypted AES key, RSA signature & hashed index.
   - Decrypts AES key (RSA-OAEP), decrypts file (AES-CBC).
   - Verifies teacher’s RSA signature.
   - Searches student names via hash (no decryption).
   - Computes total marks after decryption.
"""

import socket, json, struct, os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

HOST, PORT = "localhost", 9100
ADMIN_PRIV, ADMIN_PUB = "admin_rsa_priv.pem", "admin_rsa_pub.pem"
TEACHER_PRIV, TEACHER_PUB = "teacher_rsa_priv.pem", "teacher_rsa_pub.pem"

def pkcs7_unpad(data): return data[:-data[-1]]

def ensure_keys():
    if not os.path.exists(ADMIN_PRIV):
        key = RSA.generate(2048)
        open(ADMIN_PRIV, "wb").write(key.export_key())
        open(ADMIN_PUB, "wb").write(key.publickey().export_key())
    if not os.path.exists(TEACHER_PRIV):
        key = RSA.generate(2048)
        open(TEACHER_PRIV, "wb").write(key.export_key())
        open(TEACHER_PUB, "wb").write(key.publickey().export_key())

def start_server():
    ensure_keys()
    admin_priv = RSA.import_key(open(ADMIN_PRIV, "rb").read())
    teacher_pub = RSA.import_key(open(TEACHER_PUB, "rb").read())
    rsa_dec = PKCS1_OAEP.new(admin_priv)

    with socket.socket() as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[ADMIN] Listening on {HOST}:{PORT}")
        conn, _ = s.accept()
        with conn:
            header_len = struct.unpack("!I", conn.recv(4))[0]
            header = json.loads(conn.recv(header_len).decode())
            enc_key = conn.recv(header["enc_key_len"])
            enc_file = conn.recv(header["enc_file_len"])
            signature = conn.recv(header["sig_len"])
            index_list = json.loads(conn.recv(header["index_len"]).decode())

            while True:
                print("\n1.Verify Signature  2.Search Name  3.Decrypt & Total  4.Exit")
                ch = input("Choice: ")

                if ch == "1":
                    try:
                        key_iv = rsa_dec.decrypt(enc_key)
                        aes_key, iv = key_iv[:32], key_iv[32:48]
                        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                        plain = pkcs7_unpad(cipher.decrypt(enc_file))
                        h = SHA256.new(plain)
                        pkcs1_15.new(teacher_pub).verify(h, signature)
                        print("✅ Signature VALID")
                    except: print("❌ Signature INVALID")

                elif ch == "2":
                    name = input("Enter name: ").strip()
                    nh = SHA256.new(name.encode()).hexdigest()
                    print("FOUND" if nh in index_list else "NOT FOUND")

                elif ch == "3":
                    key_iv = rsa_dec.decrypt(enc_key)
                    aes_key, iv = key_iv[:32], key_iv[32:48]
                    plain = pkcs7_unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(enc_file)).decode()
                    print("\nFile:\n", plain)
                    total = sum(float(x.split(",")[1]) for x in plain.splitlines() if "," in x)
                    print("Total marks =", total)

                elif ch == "4": break

if __name__ == "__main__":
    start_server()
