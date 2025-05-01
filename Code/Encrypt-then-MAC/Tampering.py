from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Functions for Encrypt-then-MAC
def encrypt_etm(key_enc: bytes, key_mac: bytes, plaintext: bytes):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(iv + ciphertext)
    tag = h.finalize()

    return iv, ciphertext, tag

def decrypt_etm(key_enc: bytes, key_mac: bytes, iv: bytes, ciphertext: bytes, tag: bytes):
    h = hmac.HMAC(key_mac, hashes.SHA256())
    h.update(iv + ciphertext)
    h.verify(tag)  # raises InvalidSignature if tampered

    cipher_dec = Cipher(algorithms.AES(key_enc), modes.CBC(iv))
    decryptor = cipher_dec.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plain) + unpadder.finalize()

# Demo and tampering simulation
key_enc = os.urandom(32)
key_mac = os.urandom(32)
msg = b"Hello World"

# Normal operation
iv, ct, tag = encrypt_etm(key_enc, key_mac, msg)
print("Original decryption:", decrypt_etm(key_enc, key_mac, iv, ct, tag).decode())

# Tampering with ciphertext
tampered_ct = bytearray(ct)
tampered_ct[0] ^= 1  # flip a bit
tampered_ct = bytes(tampered_ct)
print("\n-- Ciphertext Tampering Simulation --")
try:
    decrypt_etm(key_enc, key_mac, iv, tampered_ct, tag)
    print("Decryption succeeded (unexpected)!")
except Exception as e:
    print("Tampering detected (ciphertext):", type(e).__name__)

# Tampering with MAC tag
tampered_tag = bytearray(tag)
tampered_tag[-1] ^= 1  # flip a bit in the tag
tampered_tag = bytes(tampered_tag)
print("\n-- MAC Tag Tampering Simulation --")
try:
    decrypt_etm(key_enc, key_mac, iv, ct, tampered_tag)
    print("Decryption succeeded (unexpected)!")
except Exception as e:
    print("Tampering detected (MAC tag):", type(e).__name__)
