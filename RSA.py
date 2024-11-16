import random
import sys
from math import gcd

#Thuật toán mã hóa
def rsa_encrypt(message, e, n):
    return pow(message, e, n)

#Thuật toán giải mã
def rsa_decrypt(ciphertext, d, n):
    return pow(ciphertext, d, n)

#Thuật toán ký
def rsa_sign(message, d, n):
    return pow(message, d, n)

#Thuật toán kiểm thử
def rsa_verify(x, signature, e, n):
    return x % n == pow(signature, e, n)
