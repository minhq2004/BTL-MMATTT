import math
import random

def find_primitive_root(p):
    if p == 2:
        return 1
    p1, p2 = 2, (p - 1) // 2
    while True:
        alpha = random.randint(2, p - 1)
        if pow(alpha, (p - 1) // p1, p) != 1 and pow(alpha, (p - 1) // p2, p) != 1:
            return alpha

def elgamal_encrypt(p, alpha, beta, k, m):
    c1 = pow(alpha, k, p)
    c2 = (m * pow(beta, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(p, a, c1, c2):
    s = pow(c1, p-a-1, p)
    m = (c2 * s) % p
    return m

def elgamal_sign(x, p, a, alpha, k):
    gamma = pow(alpha, k, p)
    delta = ((x - a*gamma)*pow(k, -1, p-1))%(p-1)
    return (gamma, delta)

def elgamal_verify(x, p, alpha, beta, gamma, delta):
    return (pow(beta, gamma, p)*pow(gamma, delta, p)) % p == pow(alpha, x, p) 


def generate_random_number(p):
    while True:
        k = random.randint(1, p - 1)
        if math.gcd(k,p) == 1 and math.gcd(k,p-1) == 1:
            return k
