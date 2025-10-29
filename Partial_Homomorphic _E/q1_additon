import random
import math
#-------------------------
# Function to compute LCM
#---------------------
def lcm(x, y):
    return x * y // math.gcd(x, y)
#--------------------------------

#-------------------------
# Function to compute modinv
#---------------------
def modinv(a, m):
    # Extended Euclidean Algorithm
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m
#--------------------------------

#------------------------
#generate key fun
#----------------------
def generate_keypair(p, q):
    n = p * q
    n_sq = n * n
    g = n + 1
    lam = lcm(p - 1, q - 1)
    # µ = (L(g^λ mod n²))⁻¹ mod n
    x = pow(g, lam, n_sq)
    L = (x - 1) // n
    mu = modinv(L, n)
    pub_key = (n, g)
    priv_key = (lam, mu)
    return pub_key, priv_key
#----------------------------

#----------------------------

# Encryption
def encrypt(pub_key, m):
    n, g = pub_key
    n_sq = n * n
    r = random.randint(1, n - 1)
    c = (pow(g, m, n_sq) * pow(r, n, n_sq)) % n_sq
    return c

# Decryption
def decrypt(priv_key, pub_key, c):
    n, g = pub_key
    lam, mu = priv_key
    n_sq = n * n
    x = pow(c, lam, n_sq)
    L = (x - 1) // n
    m = (L * mu) % n
    return m
#--------------------------

#--------------------------
#homomorphic encryption
#-------------------------
def homomorphic_add(c1, c2, pub_key):
    n, g = pub_key
    n_sq = n * n
    return (c1 * c2) % n_sq
#--------------------------



#--------------------------
# main program
#-----------------
if __name__=="__main__":

#generate keys (take big prime  nos)
    p=53
q=59
pubkey,privatekey=generate_keypair(p,q)
print("Public Key (n, g):", pubkey)
print("Private Key (λ, μ):", privatekey)

 #encrypt 2 nos
m1 = 15
m2 = 25
c1=encrypt(pubkey,m1)
c2=encrypt(pubkey,m2)

# Step 3: Perform homomorphic addition
c_sum=homomorphic_add(c1,c2,pubkey)
print("\nEncrypted Sum (Ciphertext):", c_sum)

# Step 4: Decrypt to verify result
decrypted_sum = decrypt(privatekey, pubkey, c_sum)
print("Decrypted Sum:", decrypted_sum)
print("\n✅ Verified:", m1, "+", m2, "=", decrypted_sum)
