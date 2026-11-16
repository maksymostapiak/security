import sympy
import base64


# Завдання 1: Брутфорс шифру Цезаря

def decrypt_caesar(ciphertext, shift):
    """Дешифрує текст зсувом на shift символів назад."""
    result = ""
    for char in ciphertext:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - base - shift) % 26 + base)
        else:
            result += char
    return result

def task1_bruteforce_caesar(ciphertext):
    print("--- Завдання 1: Брутфорс шифру Цезаря ---")
    print(f"Шифротекст: {ciphertext}\n")
    for shift in range(26):
        decrypted = decrypt_caesar(ciphertext, shift)
        print(f"Зсув (Ключ) {shift:2}: {decrypted}")
    print()

# Завдання 2: Шифр Віженера (українська мова)

def vigenere_cipher(text, key, decrypt=False):
    alphabet = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
    text = text.lower().replace(" ", "").replace("'", "")
    key = key.lower().replace(" ", "").replace("'", "")
    
    result = ""
    key_idx = 0
    
    for char in text:
        if char in alphabet:
            p_idx = alphabet.index(char)
            k_idx = alphabet.index(key[key_idx % len(key)])
            
            if decrypt:
                c_idx = (p_idx - k_idx) % 33
            else:
                c_idx = (p_idx + k_idx) % 33
                
            result += alphabet[c_idx]
            key_idx += 1
        else:
            result += char
    return result

def task2_vigenere():
    print("--- Завдання 2: Шифр Віженера ---")
    plaintext = "криптографічніметодизахистуінформації"
    key = "остапяк"
    
    encrypted = vigenere_cipher(plaintext, key, decrypt=False)
    decrypted = vigenere_cipher(encrypted, key, decrypt=True)
    
    print(f"Відкритий текст: {plaintext}")
    print(f"Ключ: {key}")
    print(f"Зашифрований текст: {encrypted}")
    print(f"Розшифрований текст: {decrypted}\n")


# Завдання 3 та 4: Система RSA 

class RSA:
    def __init__(self, key_size=1024):

        self.p = sympy.randprime(2**(key_size//2 - 1), 2**(key_size//2))
        self.q = sympy.randprime(2**(key_size//2 - 1), 2**(key_size//2))
        

        self.n = self.p * self.q
        self.phi = (self.p - 1) * (self.q - 1)
        

        self.e = 65537
        self.d = pow(self.e, -1, self.phi)
        

    def encrypt_int(self, m):
        return pow(m, self.e, self.n)
        
    def decrypt_int(self, c):
        return pow(c, self.d, self.n)
        
 
    def encrypt_string(self, text):
        m = int.from_bytes(text.encode('utf-8'), 'big')
        
        if m >= self.n:
            raise ValueError("Текст занадто великий для поточного розміру ключа RSA.")
            
        c = self.encrypt_int(m)
        
        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')
        return base64.b64encode(c_bytes).decode('utf-8')
        
    def decrypt_string(self, b64_text):

        c_bytes = base64.b64decode(b64_text)
        c = int.from_bytes(c_bytes, 'big')
        
        m = self.decrypt_int(c)
        

        m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        return m_bytes.decode('utf-8')

def task3_and_4_rsa():

    rsa = RSA(key_size=2048)
    
    print("--- Завдання 3: RSA для чисел ---")
    M_int = 100
    C_int = rsa.encrypt_int(M_int)
    M_decrypted_int = rsa.decrypt_int(C_int)
    print(f"Початкове число M: {M_int}")
    print(f"Зашифроване число C: {C_int}")
    print(f"Розшифроване число: {M_decrypted_int}\n")
    
    print("--- Завдання 4: RSA для тексту (UTF-8 + Base64) ---")
    M_str = "Cryptography is fun and educational! Learning RSA encryption and decryption with Python helps understand public key cryptosystems."
    
    M_str += " Успішного виконання лабораторної роботи!"
    
    C_b64 = rsa.encrypt_string(M_str)
    M_decrypted_str = rsa.decrypt_string(C_b64)
    
    print(f"Відкритий текст:\n{M_str}\n")
    print(f"Зашифрований криптотекст (Base64):\n{C_b64}\n")
    print(f"Розшифрований текст:\n{M_decrypted_str}")

if __name__ == "__main__":
    task1_bruteforce_caesar("vppanlwxlyopyncjae")
    task2_vigenere()
    task3_and_4_rsa()
