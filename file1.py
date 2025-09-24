#3 people: Customer , Merchant, Auditor
#Customer-> takes input, rsa encryption + elgamal sign
#Merchant-> decrypt messages+ verify sign
#Author-> check transactoons + check signs

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes, random
from Crypto.Util import number
from Crypto.Hash import SHA256
import time

# ==========================================================
# ElGamal Signature Implementation
# ==========================================================
def elgamal_generate(bits=256):
    """Generate ElGamal keys (p,g,y,x)."""
    p = number.getPrime(bits, randfunc=get_random_bytes)
    g = random.randint(2, p - 2)
    x = random.randint(2, p - 2)   # private
    y = pow(g, x, p)               # public
    return (p, g, y, x)

def elgamal_sign(msg_hash, p, g, x):
    """Sign message hash with private key x."""
    while True:
        k = random.randint(2, p - 2)
        if number.GCD(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = pow(k, -1, p - 1)
    s = ((msg_hash - x * r) * k_inv) % (p - 1)
    return (r, s)

def elgamal_verify(msg_hash, sig, p, g, y):
    """Verify ElGamal signature (r,s)."""
    r, s = sig
    if not (0 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, msg_hash, p)
    return v1 == v2

# ==========================================================
# Key Generation
# ==========================================================
print("Generating RSA and ElGamal keys...")



#in Rsa -> encrypt-> public key of other
# decrypt-> private key



# Merchant RSA keys (for encryption/decryption)
merchant_rsa = RSA.generate(1024)
merchant_pub = merchant_rsa.publickey()

# Customer ElGamal (for signing)
customer_p, customer_g, customer_y, customer_x = elgamal_generate()

# Merchant ElGamal (for signing replies)
merchant_p, merchant_g, merchant_y, merchant_x = elgamal_generate()

print("Keys generated successfully!\n")

# ==========================================================
# Storage
# ==========================================================
TRANSACTIONS = []

# ==========================================================
# Customer
# ==========================================================
def customer():
    while True:
        print("\n=== CUSTOMER MENU ===")
        print("1) Create & send transaction")
        print("2) View my transactions")
        print("3) Back")
        ch = input("> ")

        if ch == "1":
            msg = input("Enter transaction message: ").encode()

            # Encrypt with Merchant's RSA
            cipher_int = pow(int.from_bytes(msg, "big"), merchant_pub.e, merchant_pub.n)

            # Sign with Customer's ElGamal
            h = int.from_bytes(SHA256.new(msg).digest(), "big")
            sig = elgamal_sign(h, customer_p, customer_g, customer_x)

            TRANSACTIONS.append({
                "id": len(TRANSACTIONS) + 1,
                "sender": "Alice",
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "cipher": cipher_int,
                "signature": sig,
                "plaintext": None,
                "verified": None
            })
            print("Transaction created and sent!")

        elif ch == "2":
            for t in TRANSACTIONS:
                if t["sender"] == "Alice":
                    print(f"ID {t['id']} | time {t['time']} | verified={t['verified']}")
            if not TRANSACTIONS:
                print("No transactions yet.")
        elif ch == "3":
            return

# ==========================================================
# Merchant
# ==========================================================
def merchant():
    while True:
        print("\n=== MERCHANT MENU ===")
        print("1) View encrypted transactions")
        print("2) Decrypt & verify Alice's transaction")
        print("3) Reply to Alice with signed message")
        print("4) View verified transactions")
        print("5) Back")
        ch = input("> ")

        if ch == "1":
            for t in TRANSACTIONS:
                print(f"ID {t['id']} | from={t['sender']} | cipher={str(t['cipher'])[:40]}...")
            if not TRANSACTIONS:
                print("No transactions.")

        elif ch == "2":
            tid = int(input("Enter transaction ID: "))
            t = TRANSACTIONS[tid - 1]

            if t["sender"] != "Alice":
                print("Not Alice's transaction!")
                continue

            # Decrypt RSA
            m_int = pow(t['cipher'], merchant_rsa.d, merchant_rsa.n)
            msg = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")

            # Verify Alice's ElGamal signature
            h = int.from_bytes(SHA256.new(msg).digest(), "big")
            ok = elgamal_verify(h, t['signature'], customer_p, customer_g, customer_y)

            if ok:
                print("Signature valid ✅ (Alice)")
                t['verified'] = True
            else:
                print("Signature invalid ❌")
                t['verified'] = False

            t['plaintext'] = msg
            print("Message:", msg.decode())

        elif ch == "3":
            reply = input("Enter reply to Alice: ").encode()

            # Sign with Merchant’s ElGamal
            h = int.from_bytes(SHA256.new(reply).digest(), "big")
            sig = elgamal_sign(h, merchant_p, merchant_g, merchant_x)

            TRANSACTIONS.append({
                "id": len(TRANSACTIONS) + 1,
                "sender": "Bob",
                "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "cipher": None,
                "signature": sig,
                "plaintext": reply,
                "verified": None
            })
            print("Reply created and sent!")

        elif ch == "4":
            for t in TRANSACTIONS:
                if t['plaintext']:
                    print(f"ID {t['id']} | from={t['sender']} | msg={t['plaintext'].decode()} | verified={t['verified']}")
        elif ch == "5":
            return

# ==========================================================
# Auditor
# ==========================================================
def auditor():
    while True:
        print("\n=== AUDITOR MENU ===")
        print("1) View all transactions")
        print("2) Verify all signatures")
        print("3) Back")
        ch = input("> ")

        if ch == "1":
            for t in TRANSACTIONS:
                print(f"ID {t['id']} | from={t['sender']} | time {t['time']} | decrypted={t['plaintext'] is not None}")
            if not TRANSACTIONS:
                print("No transactions.")

        elif ch == "2":
            for t in TRANSACTIONS:
                if t['plaintext']:
                    h = int.from_bytes(SHA256.new(t['plaintext']).digest(), "big")
                    if t["sender"] == "Alice":
                        ok = elgamal_verify(h, t['signature'], customer_p, customer_g, customer_y)
                    else:
                        ok = elgamal_verify(h, t['signature'], merchant_p, merchant_g, merchant_y)

                    if ok:
                        print(f"ID {t['id']} | from={t['sender']} | Signature valid ✅")
                    else:
                        print(f"ID {t['id']} | from={t['sender']} | Signature invalid ❌")
        elif ch == "3":
            return

# ==========================================================
# Main Menu
# ==========================================================
while True:
    print("\n=== MAIN MENU ===")
    print("1) Customer (Alice)")
    print("2) Merchant (Bob)")
    print("3) Auditor")
    print("4) Exit")

    choice = input("> ")
    if choice == "1":
        customer()
    elif choice == "2":
        merchant()
    elif choice == "3":
        auditor()
    elif choice == "4":
        break
