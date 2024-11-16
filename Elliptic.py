import hashlib, random, math

class MyEllipticCurve:
    def __init__(self, a, b, p, G, n):
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n

    def point_addition(self, P, Q):
        if P == (None, None):
            return Q
        if Q == (None, None):
            return P

        (x1, y1) = P
        (x2, y2) = Q

        if x1 == x2 and y1 != y2:
            return (None, None)

        if P == Q:
            m = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p)

        m = m % self.p
        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_multiplication(self, k, P):
        N = P
        Q = (None, None)
        while k:
            if k & 1:
                Q = self.point_addition(Q, N)
            N = self.point_addition(N, N)
            k >>= 1
        return Q

def generate_keypair(curve):
    private_key = random.randint(1, curve.n - 1)
    public_key = curve.scalar_multiplication(private_key, curve.G)
    return private_key, public_key

def ec_elgamal_encrypt(curve, public_key, plaintext_point):
    k = random.randint(1, curve.n - 1)
    C1 = curve.scalar_multiplication(k, curve.G)
    C2 = curve.point_addition(plaintext_point, curve.scalar_multiplication(k, public_key))
    return C1, C2

def ec_elgamal_decrypt(curve, private_key, ciphertext):
    C1, C2 = ciphertext
    S = curve.scalar_multiplication(private_key, C1)
    S_inv = (S[0], -S[1] % curve.p)
    plaintext_point = curve.point_addition(C2, S_inv)
    return plaintext_point

def elliptic_sign(curve, private_key, message):
    z = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    r = 0
    s = 0
    while r == 0 or s == 0 or math.gcd(s, curve.n) != 1:
        k = random.randint(1, curve.n - 1)
        while math.gcd(k, curve.n) != 1:
            k = random.randint(1, curve.n - 1)
        x, y = curve.scalar_multiplication(k, curve.G)
        r = x % curve.n
        s = ((z + r * private_key) * pow(k, -1, curve.n)) % curve.n
        if s == 0:
            continue
        
    return (r, s)

def elliptic_verify(curve, public_key, message, signature):
    r, s = signature
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
    z = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    w = pow(s, -1, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n
    x, y = curve.point_addition(
        curve.scalar_multiplication(u1, curve.G),
        curve.scalar_multiplication(u2, public_key)
    )
    return r == x % curve.n


def hash_message_to_point(curve, message):
    hash_int = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    x = hash_int % curve.p
    while True:
        y2 = (x**3 + curve.a * x + curve.b) % curve.p
        if pow(y2, (curve.p - 1) // 2, curve.p) == 1:  
            y = pow(y2, (curve.p + 1) // 4, curve.p)
            return (x, y)
        x = (x + 1) % curve.p
