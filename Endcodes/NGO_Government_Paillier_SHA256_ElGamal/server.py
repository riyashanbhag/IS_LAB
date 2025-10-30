# Paillier+ElGamal Auditor (Server)
# → Loads Paillier private key (to decrypt homomorphic sum)
# → Receives payload with enc_budgets, index_map, elg_pub, signature, plaintext_hash
# → Menu: 1) Search doctor by name (via hashed index) 2) Compute homomorphic total 3) Verify ElGamal signature

import socket, pickle
from Crypto.Hash import SHA256

HOST = "localhost"
PORT = 9202

# Paillier decrypt utilities
def L(u, n):
    return (u - 1) // n

def paillier_decrypt(c, n, lam, mu):
    n_sq = n * n
    x = pow(c, lam, n_sq)
    return (L(x, n) * mu) % n

# ElGamal verify
def elgamal_verify(plain_hash_int, signature, pub):
    p, g, y = pub
    r, s = signature
    if not (0 < r < p): return False
    left = pow(g, plain_hash_int % (p-1), p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    return left == right

def start_server():
    # load paillier private key (server must have it)
    paillier_priv = pickle.load(open("paillier_priv.pkl","rb"))  # (n, lam, mu)
    n, lam, mu = paillier_priv

    print("[SERVER] Listening on", HOST, PORT)
    s = socket.socket()
    s.bind((HOST, PORT))
    s.listen(1)
    conn, addr = s.accept()
    print("[SERVER] Connected:", addr)

    data = b''
    while True:
        pkt = conn.recv(4096)
        if not pkt: break
        data += pkt
    conn.close(); s.close()

    payload = pickle.loads(data)
    enc_budgets = payload['enc_budgets']
    index_map = payload['index_map']      # dict: name_hash -> [indices]
    elg_pub = payload['elg_pub']          # (p,g,y)
    signature = payload['signature']      # (r,s)
    plaintext_hash = payload['plaintext_hash']  # int

    while True:
        print("\n=== Auditor Menu ===")
        print("1) Search doctor by name (no decryption)")
        print("2) Compute total budget (homomorphic)")
        print("3) Verify signature")
        print("4) Exit")
        ch = input("Choice: ").strip()

        if ch == "1":
            name = input("Doctor name (exact): ").strip()
            h = SHA256.new(name.encode()).hexdigest()
            if h in index_map:
                print(f"Found at indices: {index_map[h]}")
            else:
                print("Not found.")

        elif ch == "2":
            n_sq = n * n
            product = 1
            for c in enc_budgets:
                product = (product * (c % n_sq)) % n_sq
            total = paillier_decrypt(product, n, lam, mu)
            print("[SERVER] Homomorphic total budget =", total)

        elif ch == "3":
            ok = elgamal_verify(plaintext_hash, signature, elg_pub)
            print("Signature VALID ✅" if ok else "Signature INVALID ❌")

        elif ch == "4":
            print("Goodbye.")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    start_server()
