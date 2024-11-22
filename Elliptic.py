import hashlib, random

class MyEllipticCurve:
    def __init__(self, a, b, p, G, n):
        self.a = a  
        self.b = b  
        self.p = p  
        self.G = G  
        self.n = n  

    def mod_inverse(self, k, p):
        """Tính nghịch đảo modulo của k theo p."""
        return pow(k, -1, p)  

    def point_addition(self, P, Q):
        """Phép cộng hai điểm P và Q trên đường cong elliptic."""
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2 and y1 != y2:
            # P + (-P) = O
            return None

        if x1 == x2 and y1 == y2:
            # Nhân đôi điểm
            return self.point_double(P)

        # Cộng hai điểm khác nhau
        try:
            lam = ((y2 - y1) * self.mod_inverse(x2 - x1, self.p)) % self.p
        except ZeroDivisionError:
            return None

        x3 = (lam**2 - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def point_double(self, P):
        """Phép nhân đôi điểm P."""
        if P is None:
            return None

        x1, y1 = P

        if y1 == 0:
            # Điểm nhân đôi nằm trên trục x -> điểm vô hạn
            return None

        # Nhân đôi điểm
        try:
            lam = ((3 * x1**2 + self.a) * self.mod_inverse(2 * y1, self.p)) % self.p
        except ZeroDivisionError:
            return None

        x3 = (lam**2 - 2 * x1) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p

        return (x3, y3)

    def scalar_multiplication(self, k, P):
        """Nhân một điểm P với một số nguyên k."""
        result = None  # Điểm vô hạn
        temp = P

        while k > 0:
            if k % 2 == 1:
                result = self.point_addition(result, temp)
            temp = self.point_double(temp)
            k //= 2

        return result

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
    h = int(hashlib.sha512(message.encode()).hexdigest(), 16) % curve.n
    while True:
        k = random.randint(1, curve.n-1)
        x, y = curve.scalar_multiplication(k, curve.G)
        r = x % curve.n
        
        if r == 0:
            continue
            
        k_inv = pow(k, -1, curve.n)
        s = (k_inv * (h + private_key*r)) % curve.n
        
        if s == 0:
            continue
            
        return (r, s)

def elliptic_verify(curve, public_key, message, signature):
    r, s = signature
    
    if not (1 <= r < curve.n and 1 <= s < curve.n):
        return False
        
    w = pow(s, -1, curve.n)
    h = int(hashlib.sha256(message.encode()).hexdigest(), 16) % curve.n
    u1 = (h * w) % curve.n
    u2 = (r * w) % curve.n
    x, y = curve.point_addition(
        curve.scalar_multiplication(u1, curve.G),
        curve.scalar_multiplication(u2, public_key)
    )
    v = x % curve.n
    
    return v == r


def hash_message_to_point(curve, message):
    hash_int = int(hashlib.sha512(message.encode()).hexdigest(), 16)
    x = hash_int % curve.p
    while True:
        y2 = (x**3 + curve.a * x + curve.b) % curve.p
        if pow(y2, (curve.p - 1) // 2, curve.p) == 1:  
            y = pow(y2, (curve.p + 1) // 4, curve.p)
            return (x, y)
        x = (x + 1) % curve.p
        