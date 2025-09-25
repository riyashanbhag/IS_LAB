# elgamal Keys sign
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
#generate keys
# Merchant ElGamal (for signing replies)
merchant_p, merchant_g, merchant_y, merchant_x = elgamal_generate()
# Customer ElGamal (for signing)
customer_p, customer_g, customer_y, customer_x = elgamal_generate()

 # Sign with Customer's ElGamal
            h = int.from_bytes(SHA256.new(msg).digest(), "big")
            sig = elgamal_sign(h, customer_p, customer_g, customer_x)

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

 # Sign with Merchant’s ElGamal
            h = int.from_bytes(SHA256.new(reply).digest(), "big")
            sig = elgamal_sign(h, merchant_p, merchant_g, merchant_x)



######   RSA Encyption and DEcryption  #######################
#generate keys
# # Merchant RSA keys (for encryption/decryption)
merchant_rsa = RSA.generate(1024)
merchant_pub = merchant_rsa.publickey()
 # Encrypt with Merchant's RSA
  cipher_int = pow(int.from_bytes(msg, "big"), merchant_pub.e, merchant_pub.n)
 # Decrypt RSA
    m_int = pow(t['cipher'], merchant_rsa.d, merchant_rsa.n)
     msg = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")

######## Rabin Encyption ####################
def rabin_generate(bits=512):
    while True:
        p = number.getPrime(bits, randfunc=get_random_bytes)
        q = number.getPrime(bits, randfunc=get_random_bytes)
        if p % 4 == 3 and q % 4 == 3:
            break
    n = p * q
    return (p, q, n)

def rabin_encrypt(msg_bytes, n):
    m = int.from_bytes(msg_bytes, "big")
    c = pow(m, 2, n)
    return c

def rabin_decrypt(c, p, q):
    # Compute square roots mod p and q
    mp = pow(c, (p + 1)//4, p)
    mq = pow(c, (q + 1)//4, q)
    # Chinese Remainder Theorem
    yp, yq = number.inverse(p, q), number.inverse(q, p)
    r1 = (mp*q*yq + mq*p*yp) % (p*q)
    r2 = (p*q - r1) % (p*q)
    r3 = (mp*q*yq - mq*p*yp) % (p*q)
    r4 = (p*q - r3) % (p*q)
    # Return all 4 roots, merchant must pick correct one
    return [r1, r2, r3, r4]

# Merchant Rabin keys (for encryption/decryption)
# generate keys 
merchant_rabin_p, merchant_rabin_q,merchant_rabin_n= rabin_generate()
  # Encrypt with Merchant's Rabin
            cipher_int = rabin_encrypt(msg,merchant_rabin_n)
 # Rabin Decryption -----------------------
            roots = rabin_decrypt(t['cipher'], merchant_rabin_p, merchant_rabin_q)
            # Pick the correct root (simplest: take the smallest)
            m_int = min(roots)
            msg = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")

################### batch 2 question ########################
"""
SecureBank - Menu-driven secure banking transaction system
Uses DES (confidentiality), RSA signatures (authenticity), MD5 (integrity).
Roles: Bank Customer, Bank Officer, Financial Auditor
"""

import time
import hashlib
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# ---------- Helpers (padding) ----------
def pad_pkcs5(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def unpad_pkcs5(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

# ---------- In-memory data stores ----------
# Transactions list: each transaction is a dict with fields described below
TRANSACTIONS = []
# Customers map: name -> RSA key pair (private_key, public_key)
CUSTOMER_KEYS = {}

# ---------- Key helpers ----------
def create_customer_account(name: str):
    """Create RSA key pair for a customer and store it."""
    key = RSA.generate(2048)
    CUSTOMER_KEYS[name] = {
        "private": key,
        "public": key.publickey()
    }
    print(f"[INFO] Customer account '{name}' created with RSA keypair.")

# ---------- Core flows ----------
def customer_menu():
    while True:
        print("\n=== BANK CUSTOMER MENU ===")
        print("1) Create & send transaction")
        print("2) View my transactions")
        print("3) Create new customer account")
        print("4) Back")
        ch = input("> ").strip()

        if ch == "1":
            name = input("Customer name: ").strip()
            if name not in CUSTOMER_KEYS:
                print("Customer not found. Create account first (option 3).")
                continue

            # Input plaintext transaction
            plaintext = input("Enter transaction detail (e.g. 'Pay 1000 to Bob'): ").strip().encode()

            # Generate DES key (8 bytes) and IV (8 bytes) for CBC
            des_key = get_random_bytes(8)
            iv = get_random_bytes(8)

            # DES encrypt (CBC + PKCS5)
            cipher = DES.new(des_key, DES.MODE_CBC, iv)
            ct = cipher.encrypt(pad_pkcs5(plaintext))

            # Sign the encrypted ciphertext with customer's RSA private key (signature over ciphertext)
            h = SHA256.new(ct)
            signature = pkcs1_15.new(CUSTOMER_KEYS[name]["private"]).sign(h)

            # Timestamp
            ts = time.strftime("%Y-%m-%d %H:%M:%S")

            # Store transaction record (Officer must be able to decrypt: we simulate customer sending DES key to officer)
            # Note: system displays DES key to customer as required (in a real system, key exchange must be secure)
            record = {
                "id": len(TRANSACTIONS) + 1,
                "customer": name,
                "timestamp": ts,
                "des_key_hex": bytes_to_hex(des_key),     # stored so Bank Officer can decrypt
                "iv_hex": bytes_to_hex(iv),
                "encrypted_hex": bytes_to_hex(ct),
                "signature_hex": signature.hex(),
                "decrypted_plaintext": None,  # to be filled by Bank Officer after decryption
                "md5_hash": None,             # to be filled by Bank Officer
                "signature_valid": None,      # to be set by Bank Officer when verification performed
                "officer": None               # officer name who processed it
            }
            TRANSACTIONS.append(record)

            # Display required to Customer
            print("\n--- Transaction Sent (Customer View) ---")
            print("Original transaction:", plaintext.decode())
            print("DES key (hex):", record["des_key_hex"])
            print("IV (hex):", record["iv_hex"])
            print("Encrypted transaction (hex):", record["encrypted_hex"])
            print("RSA signature (hex):", record["signature_hex"])
            print("Timestamp:", ts)
            print("----------------------------------------")

        elif ch == "2":
            name = input("Customer name to view history: ").strip()
            if name not in CUSTOMER_KEYS:
                print("Customer not found.")
                continue
            print(f"\n--- Transactions for {name} ---")
            found = False
            for t in TRANSACTIONS:
                if t["customer"] == name:
                    found = True
                    print(f"ID {t['id']} | time {t['timestamp']} | signature_valid={t['signature_valid']}")
                    print("  Encrypted (hex):", t["encrypted_hex"])
                    print("  DES key (hex):", t["des_key_hex"])
                    # Show decrypted if available (customers can view their own decrypted)
                    if t["decrypted_plaintext"] is not None:
                        print("  Decrypted (plaintext):", t["decrypted_plaintext"].decode())
                        print("  MD5 hash (stored by officer):", t["md5_hash"])
                    print("------------------------------------")
            if not found:
                print("No transactions found for this customer.")

        elif ch == "3":
            name = input("Enter new customer name: ").strip()
            if name in CUSTOMER_KEYS:
                print("Customer already exists.")
            else:
                create_customer_account(name)

        elif ch == "4":
            return
        else:
            print("Invalid choice. Try again.")


def officer_menu():
    while True:
        print("\n=== BANK OFFICER MENU ===")
        print("1) View received encrypted transactions")
        print("2) Process (verify signature & decrypt) a transaction")
        print("3) View processed/verified transactions (Officer view)")
        print("4) Back")
        ch = input("> ").strip()

        if ch == "1":
            if not TRANSACTIONS:
                print("No transactions received yet.")
                continue
            print("\n--- All Received (Encrypted) Transactions ---")
            for t in TRANSACTIONS:
                # Officers can see encrypted data and DES key (they received it from customer)
                print(f"ID {t['id']} | Customer={t['customer']} | time={t['timestamp']}")
                print("  Encrypted (hex):", t["encrypted_hex"])
                print("  DES key (hex):", t["des_key_hex"])
                print("  Signature (hex):", t["signature_hex"])
                print("  Signature verified:", t["signature_valid"])
                print("--------------------------------------------")
        elif ch == "2":
            try:
                tid = int(input("Enter transaction ID to process: ").strip())
                t = TRANSACTIONS[tid - 1]
            except (ValueError, IndexError):
                print("Invalid transaction ID.")
                continue

            # Verify signature using customer's RSA public key (signature on ciphertext)
            cust = t["customer"]
            if cust not in CUSTOMER_KEYS:
                print("Customer public key not found; cannot verify.")
                t["signature_valid"] = False
            else:
                ct = hex_to_bytes(t["encrypted_hex"])
                sig = bytes.fromhex(t["signature_hex"])
                h = SHA256.new(ct)
                try:
                    pkcs1_15.new(CUSTOMER_KEYS[cust]["public"]).verify(h, sig)
                    t["signature_valid"] = True
                    print("Signature verification: Valid ✅")
                except (ValueError, TypeError):
                    t["signature_valid"] = False
                    print("Signature verification: Invalid ❌")

            # Decrypt using stored DES key (Officer has access to DES key in this simulation)
            try:
                des_key = hex_to_bytes(t["des_key_hex"])
                iv = hex_to_bytes(t["iv_hex"])
                cipher = DES.new(des_key, DES.MODE_CBC, iv)
                ct = hex_to_bytes(t["encrypted_hex"])
                plaintext = unpad_pkcs5(cipher.decrypt(ct))
                t["decrypted_plaintext"] = plaintext
                # Compute MD5 on decrypted plaintext and store with timestamp
                md5 = hashlib.md5(plaintext).hexdigest()
                t["md5_hash"] = md5
                t["officer"] = "Officer"  # you can allow officer names later
                print("Decryption: Success. Decrypted plaintext shown below:")
                print(" Decrypted plaintext:", plaintext.decode())
                print(" MD5 hash (32 hex):", md5)
                print(" Stored MD5 with timestamp:", time.strftime("%Y-%m-%d %H:%M:%S"))
            except Exception as e:
                print("Decryption failed (possible tampering or wrong DES key). Error:", str(e))
                t["decrypted_plaintext"] = None
                t["md5_hash"] = None

        elif ch == "3":
            print("\n--- Processed Transactions (Officer View) ---")
            anyp = False
            for t in TRANSACTIONS:
                if t["decrypted_plaintext"] is not None:
                    anyp = True
                    print(f"ID {t['id']} | Customer={t['customer']} | time={t['timestamp']}")
                    print("  Decrypted (plaintext):", t["decrypted_plaintext"].decode())
                    print("  MD5 hash:", t["md5_hash"])
                    print("  Signature status:", "Valid" if t["signature_valid"] else "Invalid")
                    print("  Processed by:", t["officer"])
                    print("-------------------------------------------")
            if not anyp:
                print("No processed transactions yet.")

        elif ch == "4":
            return
        else:
            print("Invalid choice. Try again.")


def auditor_menu():
    while True:
        print("\n=== FINANCIAL AUDITOR MENU ===")
        print("1) View MD5 hashed transaction records (ID, timestamp, MD5 only)")
        print("2) Verify RSA signature of a transaction (without viewing plaintext)")
        print("3) Back")
        ch = input("> ").strip()

        if ch == "1":
            print("\n--- Auditor View: MD5 records ---")
            anyp = False
            for t in TRANSACTIONS:
                anyp = True
                md5 = t["md5_hash"] if t["md5_hash"] is not None else "<not computed>"
                print(f"ID {t['id']} | time={t['timestamp']} | MD5={md5}")
            if not anyp:
                print("No transactions recorded yet.")

        elif ch == "2":
            try:
                tid = int(input("Enter transaction ID to verify signature: ").strip())
                t = TRANSACTIONS[tid - 1]
            except (ValueError, IndexError):
                print("Invalid transaction ID.")
                continue

            cust = t["customer"]
            if cust not in CUSTOMER_KEYS:
                print("Customer public key not found.")
                continue

            # Verifies signature on ciphertext (auditor should not see plaintext)
            ct = hex_to_bytes(t["encrypted_hex"])
            sig = bytes.fromhex(t["signature_hex"])
            h = SHA256.new(ct)
            try:
                pkcs1_15.new(CUSTOMER_KEYS[cust]["public"]).verify(h, sig)
                print(f"Signature verification for ID {t['id']}: VALID ✅")
            except (ValueError, TypeError):
                print(f"Signature verification for ID {t['id']}: INVALID ❌")

        elif ch == "3":
            return
        else:
            print("Invalid choice. Try again.")


# ---------- Main menu ----------
def main_menu():
    print("Welcome to SecureBank - Secure Transaction System")
    print("Note: This is a simulation. In production, key exchange and key management must be secure.")
    while True:
        print("\n=== MAIN MENU ===")
        print("1) Bank Customer")
        print("2) Bank Officer")
        print("3) Financial Auditor")
        print("4) Exit")
        choice = input("> ").strip()
        if choice == "1":
            customer_menu()
        elif choice == "2":
            officer_menu()
        elif choice == "3":
            auditor_menu()
        elif choice == "4":
            print("Exiting SecureBank. Goodbye.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    # Create a sample customer account for quick testing
    create_customer_account("Alice")
    main_menu()



##################### sec A ######################################
"""
==========================================================
💻 Information Security Lab – Hospital Management System
==========================================================

Q) Develop a menu-driven **Hospital Management System** with 3 roles:
   👩‍🦱 Patient, 👨‍⚕️ Doctor, 🧑‍💼 Auditor

Requirements:

1) Patient:
   • Uploads a medical record (string or .txt file content).
   • Encrypts the record using **AES symmetric encryption**.
   • Generates a **SHA-512 hash** of the record and signs it with **RSA private key**.
   • Can view past uploaded records with timestamps.
   • Must display:
       - Original record
       - AES key used
       - Encrypted record (hex)
       - RSA signature (hex)

2) Doctor:
   • Views encrypted medical records.
   • Decrypts the record using AES key.
   • Computes SHA-512 of decrypted record.
   • Verifies patient’s RSA signature using patient’s public key.
   • Stores verification results.
   • Must display:
       - Decrypted record
       - Signature verification result (Valid / Invalid)

3) Auditor:
   • Can view metadata of records (ID, timestamp, signature in hex).
   • Cannot decrypt or view original records.
   • Can verify RSA signatures using the patient’s public key.

Access Control:
   - Patient → Encrypt, Sign, View own records.
   - Doctor → Decrypt, Verify, View verification results.
   - Auditor → View metadata only, Verify signatures.

Storage:
   - Use a list of dictionaries RECORDS[] to maintain:
     { id, ciphertext, aes_key, signature, timestamp, plaintext, verified }

Marks Distribution (example from lab exam):
   - Writeup: Patient (2), Doctor (1), Auditor (1) → 4
   - Execution: Encrypt/Decrypt (6), Hash + Sign (3), Verify (3) → 12
   - Total = 16 marks

==========================================================
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
import time, base64

# ==========================================================
# RSA Keys for Patient
# ==========================================================
patient_rsa = RSA.generate(2048)
patient_private = patient_rsa
patient_public = patient_rsa.publickey()

# AES key (shared between patient & doctor)
AES_KEY = get_random_bytes(16)

# ==========================================================
# Storage for Records
# ==========================================================
RECORDS = []   # each entry: {id, ciphertext, aes_key, signature, timestamp, plaintext, verified}

# ==========================================================
# Encryption / Decryption Helpers
# ==========================================================
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def aes_decrypt(enc_data, key):
    nonce, tag, ciphertext = enc_data[:16], enc_data[16:32], enc_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def rsa_sign(data, priv_key):
    h = SHA512.new(data)
    signature = pkcs1_15.new(priv_key).sign(h)
    return signature

def rsa_verify(data, signature, pub_key):
    h = SHA512.new(data)
    try:
        pkcs1_15.new(pub_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# ==========================================================
# 👩‍🦱 Patient Menu
# ==========================================================
def patient():
    while True:
        print("\n=== PATIENT MENU ===")
        print("1) Upload & Encrypt Medical Record")
        print("2) View My Past Records")
        print("3) Back")
        choice = input("> ")

        if choice == "1":
            record = input("Enter medical record (string or file content): ").encode()

            # Encrypt with AES
            enc = aes_encrypt(record, AES_KEY)

            # Sign SHA-512 hash using RSA
            signature = rsa_sign(record, patient_private)

            RECORDS.append({
                "id": len(RECORDS) + 1,
                "ciphertext": enc,
                "aes_key": AES_KEY,
                "signature": signature,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "plaintext": record,
                "verified": None
            })

            print("✅ Record uploaded, encrypted & signed.")
            print("Original:", record.decode())
            print("AES Key (hex):", AES_KEY.hex())
            print("Encrypted (hex):", enc.hex()[:60], "...")
            print("Signature (hex):", signature.hex()[:60], "...")

        elif choice == "2":
            for r in RECORDS:
                print(f"ID {r['id']} | time {r['timestamp']} | record={r['plaintext'].decode()}")
            if not RECORDS:
                print("No records found.")

        elif choice == "3":
            return

# ==========================================================
# 👨‍⚕️ Doctor Menu
# ==========================================================
def doctor():
    while True:
        print("\n=== DOCTOR MENU ===")
        print("1) View Encrypted Records")
        print("2) Decrypt & Verify a Record")
        print("3) Back")
        choice = input("> ")

        if choice == "1":
            for r in RECORDS:
                print(f"ID {r['id']} | Encrypted={r['ciphertext'].hex()[:60]}...")
            if not RECORDS:
                print("No records.")

        elif choice == "2":
            tid = int(input("Enter Record ID: "))
            r = RECORDS[tid - 1]

            # Decrypt AES
            try:
                plain = aes_decrypt(r["ciphertext"], r["aes_key"])
                print("Decrypted Record:", plain.decode())
            except Exception as e:
                print("❌ Decryption failed:", e)
                continue

            # Verify signature
            ok = rsa_verify(plain, r["signature"], patient_public)
            r["verified"] = ok
            print("Signature Verification:", "✅ Valid" if ok else "❌ Invalid")

        elif choice == "3":
            return

# ==========================================================
# 🧑‍💼 Auditor Menu
# ==========================================================
def auditor():
    while True:
        print("\n=== AUDITOR MENU ===")
        print("1) View Record Metadata (No Decryption)")
        print("2) Verify Signatures")
        print("3) Back")
        choice = input("> ")

        if choice == "1":
            for r in RECORDS:
                print(f"ID {r['id']} | time {r['timestamp']} | signature={r['signature'].hex()[:60]}...")
            if not RECORDS:
                print("No records.")

        elif choice == "2":
            for r in RECORDS:
                ok = rsa_verify(r["plaintext"], r["signature"], patient_public)
                print(f"ID {r['id']} | Signature:", "✅ Valid" if ok else "❌ Invalid")

        elif choice == "3":
            return

# ==========================================================
# MAIN MENU
# ==========================================================
while True:
    print("\n=== HOSPITAL MANAGEMENT SYSTEM ===")
    print("1) Patient")
    print("2) Doctor")
    print("3) Auditor")
    print("4) Exit")

    choice = input("> ")
    if choice == "1":
        patient()
    elif choice == "2":
        doctor()
    elif choice == "3":
        auditor()
    elif choice == "4":
        break
