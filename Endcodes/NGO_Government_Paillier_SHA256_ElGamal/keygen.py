# Key generation for Variant3 (Paillier + ElGamal)
# → Generates Paillier keypair (server) and ElGamal keypair (client).
# → Saves files: paillier_pub.pkl, paillier_priv.pkl, elg_priv.pkl, elg_pub.pkl

#--------------------------
# run python keygen.py
# then python server.py
# then python client.py
#----------------------------------
import pickle
from Crypto.Util.number import getPrime, inverse
import random, math

def lcm(a,b): return a//math.gcd(a,b)*b

# Paillier keygen (toy/demo sizes)
def paillier_keygen(bits=256):
    p = getPrime(bits//2)
    q = getPrime(bits//2)
    n = p * q
    g = n + 1
    lam = lcm(p-1, q-1)
    # with g = n+1, mu = (L(g^lam mod n^2))^{-1} mod n simplifies to inverse(lam, n)
    mu = inverse(lam, n)
    return (n, g), (n, lam, mu)

# ElGamal keygen (simple)
def elgamal_keygen(bits=256):
    p = getPrime(bits)
    g = 2
    x = random.randrange(2, p-2)
    y = pow(g, x, p)
    return (p, g, y), (p, g, x)  # pub, priv

if __name__ == "__main__":
    paillier_pub, paillier_priv = paillier_keygen(256)
    elg_pub, elg_priv = elgamal_keygen(256)
    pickle.dump(paillier_pub, open("paillier_pub.pkl","wb"))
    pickle.dump(paillier_priv, open("paillier_priv.pkl","wb"))
    pickle.dump(elg_priv, open("elg_priv.pkl","wb"))
    pickle.dump(elg_pub, open("elg_pub.pkl","wb"))
    print("Keys saved: paillier_pub.pkl, paillier_priv.pkl, elg_priv.pkl, elg_pub.pkl")
