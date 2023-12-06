# pip install pycryptodome

from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_key():
    return get_random_bytes(16)  # 16 bytes key for Blowfish

def encrypt(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), Blowfish.block_size))
    return ciphertext

def decrypt(ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return decrypted.decode('utf-8')

if __name__ == "__main__":
    # Example usage
    key = generate_key()
    message = "Hello, Blowfish!"

    # Encryption
    encrypted_message = encrypt(message, key)
    print("Encrypted:", encrypted_message)

    # Decryption
    decrypted_message = decrypt(encrypted_message, key)
    print("Decrypted:", decrypted_message)
