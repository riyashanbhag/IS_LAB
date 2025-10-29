"""
SSE -> AES uses 1 symmetric key.
Documents are created and given IDs.
AES key is generated for both encryption & decryption.
An inverted index is built (word → list of doc IDs).
Each word is hashed, then the entire index is encrypted.
During search:
   - The query word is hashed & encrypted.
   - The system searches the encrypted index.
   - If a match is found, corresponding encrypted doc IDs are decrypted.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

#----------------------------------------------
# encypt and decrypt fn
#----------------------------------------
def encrypt_data(key, data):
    """Encrypt data deterministically (fixed IV for demo only)."""
    iv = b'\x00' * 16   # Fixed IV (not secure in real world)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return ciphertext

def decrypt_data(key, ciphertext):
    """Decrypt data with same fixed IV."""
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()
#---------------------------------------


#create encypted index fn #######################
def create_encrypted_index(documents, key):
    index = {}

    # Build inverted index: word_hash → [doc_ids]
    for doc_id, content in documents.items():
        words = content.lower().split()
        for word in words:
            word_hash = hashlib.sha256(word.encode()).hexdigest()
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)

    # Encrypt the index
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        enc_word = encrypt_data(key, word_hash)
        enc_doc_ids = [encrypt_data(key, doc_id) for doc_id in doc_ids]
        encrypted_index[enc_word] = enc_doc_ids

    return encrypted_index

#----------------------------------
#search function
#--------------------------------

def search(encrypted_index, query, key):
    """Search the encrypted index using encrypted query."""
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()
    enc_query = encrypt_data(key, query_hash)

    # Compare encrypted query with encrypted index keys
    for enc_word, enc_doc_ids in encrypted_index.items():
        if enc_word == enc_query:
            results = []
            for enc_id in enc_doc_ids:
                doc_id = decrypt_data(key, enc_id)
                results.append(doc_id)
            return results
    return []
#-------------------------------

"""
doc make"""
if __name__ == "__main__":
    #data set
    documents={
        "doc1": "encryption ensures data privacy",
        "doc2": "network security uses encryption and hashing",
        "doc3": "searchable encryption enables private queries",
        "doc4": "data protection is important for security",
        "doc5": "the aes algorithm provides symmetric encryption",
        "doc6": "machine learning enhances data analysis",
        "doc7": "confidential information must be protected",
        "doc8": "secure systems prevent unauthorized access",
        "doc9": "encryption and decryption are key processes",
        "doc10": "cloud storage uses encryption for data safety"
    }
    #generate keys
    key=get_random_bytes(16);


    #create inverted list
    encypted_index=create_encrypted_index(documents,key);

    print("✅ Encrypted index created successfully.\n")

    #take user query
    query=input("enter word:").strip();
    #search karo in list
    results=search(encypted_index,query,key);

    if results:
        print("\n📄 Matching Documents:")
        for doc_id in results:
            print(f" - {doc_id}: {documents[doc_id]}")
    else:
        print("\n⚠️ No matching documents found for your query.")

