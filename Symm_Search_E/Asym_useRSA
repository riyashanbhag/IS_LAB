"""
1. Generate RSA key pair → (public, private)
2. Create 10 documents → assign IDs
3. Hash every word (SHA-256)
4. Build inverted index (hash → docIDs)
5. Encrypt each hash and docID using RSA public key
6. Take query → hash it
7. Decrypt each encrypted token to find matching word
8. Decrypt matching doc IDs and show results

"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
#------------------------
# generate keys(rsa) and encrypt decrypt functions
#-----------------
def generate_keys(bits=2048):
    keypair = RSA.generate(bits)
    pub = keypair.publickey()
    priv = keypair
    return pub, priv

def rsa_encrypt(pubkey, data_str):
    """Encrypt string with RSA-OAEP (returns bytes). For deterministic demo we will
       encrypt the hex of the hash using PKCS1_OAEP (note OAEP still uses randomness,
       so strict equality may fail). For strict equality use raw RSA (not recommended).
       For this demo we will use OAEP but compare by decrypting all keys (works for small
       index sizes)."""
    cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA256)
    return cipher.encrypt(data_str.encode())

def rsa_decrypt(privkey, ciphertext):
    cipher = PKCS1_OAEP.new(privkey, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext).decode()
#----------------------------

#-------------------------------
#crete index list
#--------------------------
def create_encrypted_index(documents, pubkey):
    """
    Build an inverted index:
      word_hash (hex string) -> [doc_id strings]
    Then encrypt each word_hash and each doc_id with the public key.
    Returns: dict {enc_word_bytes: [enc_doc_bytes, ...]}
    """
    from collections import defaultdict
    import hashlib

    index = defaultdict(list)
    for doc_id, text in documents.items():
        for word in text.lower().split():
            h = hashlib.sha256(word.encode()).hexdigest()
            if doc_id not in index[h]:
                index[h].append(doc_id)

    encrypted_index = {}
    for word_hash, doc_list in index.items():
        # encrypt token = word_hash
        enc_token = rsa_encrypt(pubkey, word_hash)
        # encrypt doc ids
        enc_docs = [rsa_encrypt(pubkey, doc_id) for doc_id in doc_list]
        encrypted_index[enc_token] = enc_docs

    return encrypted_index
#--------------------------------

#------------------------------
#search function
#--------------------------------
def search(encrypted_index, query, pubkey, privkey):
    """
    Search flow:
      - Compute hash of query
      - Encrypt the hash with public key (to create search token)
      - Compare token to index keys — OAEP is randomized so direct byte compare may fail.
        To handle OAEP randomness in this demo we instead:
          - compute query hash
          - decrypt every index key using privkey and compare (small index OK for lab)
      - Return list of decrypted doc IDs
    Note: This approach demonstrates PKSE idea; production systems use better tokens.
    """
    import hashlib

    q_hash = hashlib.sha256(query.lower().encode()).hexdigest()

    # brute-force match: decrypt each index key to find matching token
    matched_doc_ids = []
    for enc_token, enc_doc_list in encrypted_index.items():
        try:
            token_plain = rsa_decrypt(privkey, enc_token)  # decrypt token to compare
        except Exception:
            continue
        if token_plain == q_hash:
            # decrypt doc ids
            for enc_doc in enc_doc_list:
                try:
                    doc_id = rsa_decrypt(privkey, enc_doc)
                    matched_doc_ids.append(doc_id)
                except Exception:
                    continue
            break

    return matched_doc_ids
#-----------------------------

if __name__=="__main__":

    # documents
    documents = {
    "doc1": "encryption ensures data privacy",
    "doc2": "network security uses encryption and hashing",
    "doc3": "searchable encryption enables private queries",
    "doc4": "data protection is important for security",
    "doc5": "the rsa algorithm provides public key operations",
    "doc6": "machine learning enhances data analysis",
    "doc7": "confidential information must be protected",
    "doc8": "secure systems prevent unauthorized access",
    "doc9": "encryption and decryption are key processes",
    "doc10": "cloud storage uses encryption for data safety"
}

#generate public and private keys
pubkey,privatekey= generate_keys()

# create inverted list
encypted_index=create_encrypted_index(documents,pubkey)
print("Encrypted index created (RSA-based tokens).")

# search
query=input("enter word: ").strip()
docs=search(encypted_index,query,pubkey,privatekey)
if docs:
        print("Found in documents:")
        for d in docs:
            print(f" - {d}: {documents[d]}")
else:
        print("No match found.")
