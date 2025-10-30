# Paillier+ElGamal Client (NGO/Doctor)
# → Reads CSV (branch,doctor,budget,timestamp)
# → Uses paillier_pub.pkl to encrypt budgets (additive homomorphic)
# → Signs SHA-256(plaintext) with ElGamal private key (elg_priv.pkl)
# → Sends pickled payload to server: enc_budgets, index_map, elg_pub, signature, plaintext_hash

import csv, pickle, random, socket
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, inverse

# utils
def math_gcd(a,b):
    while b:
        a,b = b, a%b
    return a

# Paillier encrypt (client uses server's public (n,g))
def paillier_encrypt(m, n, g):
    n_sq = n * n
    r = random.randrange(1, n)
    return (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq

# ElGamal sign
def elgamal_sign(plain_hash_int, priv):
    p, g, x = priv
    p1 = p - 1
    while True:
        k = random.randrange(2, p1)
        if math_gcd(k, p1) == 1:
            break
    r = pow(g, k, p)
    k_inv = inverse(k, p1)
    s = (k_inv * (plain_hash_int - x * r)) % p1
    return (r, s)

def read_csv(path):
    rows = []
    with open(path, newline='', encoding='utf-8') as f:
        rdr = csv.reader(f)
        for r in rdr:
            if len(r) >= 3:
                branch = r[0].strip()
                doctor = r[1].strip()
                try:
                    budget = int(float(r[2]))
                except:
                    budget = 0
                ts = r[3].strip() if len(r) > 3 else ""
                rows.append((branch, doctor, budget, ts))
    return rows

def main():
    # load paillier public key
    paillier_pub = pickle.load(open("paillier_pub.pkl","rb"))  # (n,g)
    n, g = paillier_pub

    # load elgamal private key for signing and elgamal public to send along
    elg_priv = pickle.load(open("elg_priv.pkl","rb"))         # (p,g,x)
    elg_pub = pickle.load(open("elg_pub.pkl","rb"))           # (p,g,y)

    path = input("CSV path (branch,doctor,budget,timestamp): ").strip()
    records = read_csv(path)
    if not records:
        print("No records found."); return

    # plaintext for signature (CSV text)
    plaintext = "\n".join([",".join(map(str,r)) for r in records]).encode()
    h_obj = SHA256.new(plaintext)
    h_int = int(h_obj.hexdigest(), 16)

    # encrypt budgets using paillier pub
    enc_budgets = [paillier_encrypt(r[2], n, g) for r in records]

    # build hashed index: doctor_name_hash -> [indices]
    index_map = {}
    for idx, r in enumerate(records):
        name = r[1]
        nh = SHA256.new(name.encode()).hexdigest()
        index_map.setdefault(nh, []).append(idx)

    # sign plaintext hash with elgamal private
    signature = elgamal_sign(h_int, elg_priv)

    payload = {
        'enc_budgets': enc_budgets,
        'index_map': index_map,
        'elg_pub': elg_pub,
        'signature': signature,
        'plaintext_hash': h_int
    }

    # send payload to server
    s = socket.socket()
    s.connect(("localhost", 9202))
    s.sendall(pickle.dumps(payload))
    s.close()
    print("[CLIENT] Payload sent to auditor.")

if __name__ == "__main__":
    main()
