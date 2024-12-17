from flask import Flask, render_template, request, jsonify
import random
import re
import sys
from Elgamal import *
from RSA import *
from Elliptic import *
from EllipticCurve import *
from AKS import *

app = Flask(__name__)

# Tăng giới hạn số
sys.set_int_max_str_digits(10000)

def generate_prime_candidate(n):
    """Sinh số ngẫu nhiên n-bit"""
    return random.randrange(2**(n-1) + 1, 2**n - 1) | 1

def generate_n_bit_prime(n):
    """Sinh số nguyên tố n-bit sử dụng Miller-Rabin và xác minh bằng AKS"""
    while True:
        candidate = generate_prime_candidate(n)
        if aks_primality_test(candidate):
            return candidate

def generate_different_primes(n):
    """Sinh hai số nguyên tố khác nhau"""
    p = generate_n_bit_prime(n)
    q = generate_n_bit_prime(n)
    return p, q

def generate_single_prime(n):
    """Sinh hai số nguyên tố khác nhau"""
    p = generate_n_bit_prime(n)
    return p

def text_to_number(text):
    # Đảm bảo text là chữ hoa
    text = text.upper()
    # Thêm padding để tránh mất chữ A ở đầu
    padded_text = 'X' + text  # Thêm một ký tự prefix
    return sum((ord(char) - 65) * (26 ** i) for i, char in enumerate(padded_text[::-1]))

def number_to_text(number):
    if number == 0:
        return 'A'  # Trường hợp đặc biệt cho số 0
        
    result = []
    while number:
        number, remainder = divmod(number, 26)
        result.append(chr(remainder + 65))
    
    text = ''.join(result[::-1])
    # Bỏ ký tự padding X ở đầu nếu có
    if text.startswith('X'):
        text = text[1:]
    return text


@app.route('/')
def menu():
    return render_template('menu.html')

@app.route('/rsa')
def rsa():
    return render_template('rsa.html')  # Đổi tên từ index.html sang rsa.html

@app.route('/elgamal')
def elgamal():
    return render_template('elgamal.html')

@app.route('/ecc')
def ecc():
    return render_template('ecc.html')

@app.route('/process_rsa', methods=['POST'])
def process_rsa():
    try:
        message_text = request.json.get('message', '')
        bit_length = request.json.get('bit_length', 512)  
        
        # Thực hiện các bước RSA
        if bit_length > 8192:
            return jsonify({'error': 'Số bit không được vượt quá 8192'}), 400

        p, q = generate_different_primes(bit_length)
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = random.randint(2, phi - 1)
        while gcd(e, phi) != 1:
            e = random.randint(2, phi - 1)
        
        d = pow(e, -1, phi)
        
        message_number = text_to_number(message_text)
        encrypted_message = rsa_encrypt(message_number, e, n)
        decrypted_message_number = rsa_decrypt(encrypted_message, d, n)
        decrypted_message_text = number_to_text(decrypted_message_number)
        
        signature = rsa_sign(message_number, d, n)
        verification = rsa_verify(decrypted_message_number, signature, e, n)
        
        # Trả về kết quả dưới dạng JSON
        return jsonify({
            'bit_length': bit_length,
            'original_message': message_text,
            'p': str(p),
            'q': str(q),
            'n': str(n),
            'e': str(e),
            'd': str(d),
            'encrypted_message': number_to_text(encrypted_message),
            'decrypted_message': decrypted_message_text,
            'signature': str(signature),
            'verification': verification
        })
    except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/process_elgamal', methods=['POST'])
def process_elgamal():
    try:
        message_text = request.json.get('message', '')
        bit_length = request.json.get('bit_length', 512)

        if bit_length > 4096:
            return jsonify({'error': 'Số bit không được vượt quá 4096'}), 400

        # Sinh các tham số
        p = generate_single_prime(bit_length)
        alpha = find_primitive_root(p)
        a = generate_random_number(p)  # Khóa bí mật
        beta = pow(alpha, a, p)  # Khóa công khai
        
        # Sinh k ngẫu nhiên cho mã hóa và ký
        k1 = generate_random_number(p)  # k cho mã hóa
        k2 = generate_random_number(p)  # k cho chữ ký
        
        # Mã hóa
        message_number = text_to_number(message_text)
        c1, c2 = elgamal_encrypt(p, alpha, beta, k1, message_number)
        
        # Giải mã
        decrypted_number = elgamal_decrypt(p, a, c1, c2)
        decrypted_text = number_to_text(decrypted_number)
        
        # Ký và xác thực
        gamma, delta = elgamal_sign(message_number, p, a, alpha, k2)
        verification = elgamal_verify(decrypted_number, p, alpha, beta, gamma, delta)

        return jsonify({
            'bit_length': bit_length,
            'original_message': message_text,
            'p': str(p),
            'alpha': str(alpha),
            'a': str(a),
            'beta': str(beta),
            'k': str(k1),
            'c1': str(c1),
            'c2': str(c2),
            'decrypted_message': decrypted_text,
            'gamma': str(gamma),
            'delta': str(delta),
            'verification': verification
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/process_ecc', methods=['POST'])
def process_ecc():
    try:
        message_text = request.json.get('message', '')
        bit_length = request.json.get('bit_length', 10)

        if bit_length > 256:
            return jsonify({'error': 'Số bit không được vượt quá 256'}), 400
        
        p = generate_single_prime(bit_length)
        while True:
            while True:
                a = random.randint(1 , p - 1)
                b = random.randint(1 , p - 1)

                if (4 * a**3 + 27 * b**2) % p != 0:
                    break

            while True:
                x = random.randint(0, p - 1)
                y2 = (x**3 + a * x + b) % p
                if pow(y2, (p - 1) // 2, p) == 1:  
                    y = pow(y2, (p + 1) // 4, p)
                    g = (x, y)
                    break

            E = EllipticCurve(p, a, b)
            n = E.sea()
            if n is None:
                raise ValueError("Lỗi khi tìm cấp đường cong E")
            n = int(re.search(r'\d+', n).group())
            if (aks_primality_test(n)):
                break
            else:
                continue

        curve = MyEllipticCurve(a, b, p, g, n)

        private_key, public_key = generate_keypair(curve)

        plaintext_point = hash_message_to_point(curve, message_text)

        M1, M2 = ec_elgamal_encrypt(curve, public_key, plaintext_point)

        # Decrypt the message
        decrypted_point = ec_elgamal_decrypt(curve, private_key, (M1, M2))
        # Sign a message
        signature = elliptic_sign(curve, private_key, message_text)
        # Verify the signature
        is_valid = elliptic_verify(curve, public_key, message_text, signature)

        return jsonify({
            'bit_length': bit_length,
            'original_message': message_text,
            'original_message_point': str(plaintext_point),
            'p': str(p),
            'a': str(a),
            'b': str(b),
            'g': str(g),
            'n': str(n),
            'private_key': str(private_key),
            'public_key': str(public_key),
            'M1': str(M1),
            'M2': str(M2),
            'decrypted_point': str(decrypted_point),
            'signature': str(signature),
            'verification': is_valid
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500
