import time
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# Key setup (same as in implementations)
key_enc = os.urandom(32) # 256-bit AES key
key_mac = os.urandom(32) # 256-bit HMAC key
key_aead = ChaCha20Poly1305.generate_key()  # 256-bit AEAD key

# Implementation of Encrypt-then-MAC (same structure as your code)
def encrypt_etm(key_enc: bytes, key_mac: bytes, plaintext: bytes):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(iv + ciphertext)
    tag = h.finalize()
    return iv, ciphertext, tag

# Implementation of AEAD ChaCha20-Poly1305 (coherent naming)
def encrypt_aead(key: bytes, plaintext: bytes):
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return nonce, ciphertext

# Benchmark parameters
message_sizes = [1024, 100 * 1024, 10 * 1024 * 1024] #  1KB, 100KB, 10MB
iterations = 10  # number of runs per size

print(f"{'Size':>10} | {'AES-CBC-HMAC Encrypt (ms)':>25} | {'ChaCha20-Poly1305 Encrypt (ms)':>30}")
print("-" * 75)

for size in message_sizes:
    plaintext = os.urandom(size)

    # Benchmark AES-CBC-HMAC encryption
    start = time.perf_counter()
    for _ in range(iterations):
        iv, ciphertext, tag = encrypt_etm(key_enc, key_mac, plaintext)
    aes_time = (time.perf_counter() - start) / iterations * 1000 # average ms

    # Benchmark ChaCha20-Poly1305 AEAD encryption
    start = time.perf_counter()
    for _ in range(iterations):
        nonce, ciphertext_aead = encrypt_aead(key_aead, plaintext)
    chacha_time = (time.perf_counter() - start) / iterations * 1000 # average ms

    print(f"{size/1024:8.0f} KB | {aes_time:25.2f} | {chacha_time:30.2f}")
