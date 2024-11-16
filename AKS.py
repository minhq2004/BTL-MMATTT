import math

def perfect_power(n):
    for b in range(2, int(math.log2(n)) + 1):
        a = int(n ** (1 / b))
        if a ** b == n or (a + 1) ** b == n:
            return True
    return False

def find_smallest_r(n):
    max_k = int(math.log2(n) ** 2)
    max_r = int(math.log2(n) ** 5)
    for r in range(2, max_r + 1):
        next_r = False
        for k in range(1, max_k + 1):
            if pow(n, k, r) == 0:
                next_r = True
                break
        if not next_r:
            return r
    return None

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def integer_log2(n):
    result = 0
    while n > 1:
        n //= 2
        result += 1
    return result

def integer_sqrt(n):
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x

def aks_primality_test(n):
    if n == 2 or n == 3:
        return True
    if n % 2 == 0 or n == 1:
        return False

    if perfect_power(n):
        return False

    r = find_smallest_r(n)
    if r is None:
        return False

    for a in range(2, min(r, n)):
        if gcd(a, n) > 1:
            return False

    if n <= r:
        return True

    for a in range(1, integer_sqrt(phi(r)) * integer_log2(n) + 1):
        if pow(a, n, n) != pow(a, 1, n):
            return False

    return True

def phi(n):
    result = n
    p = 2
    while p * p <= n:
        if n % p == 0:
            while n % p == 0:
                n //= p
            result -= result // p
        p += 1
    if n > 1:
        result -= result // n
    return result
