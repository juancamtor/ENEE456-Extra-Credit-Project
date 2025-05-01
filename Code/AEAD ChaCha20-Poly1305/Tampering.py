from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# Functions for AEAD ChaCha20-Poly1305
def encrypt_aead(key: bytes, plaintext: bytes, aad: bytes = b""):
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12) # 96-bit nonce
    ciphertext = chacha.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext

def decrypt_aead(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b""):
    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, aad)

# Demo and tampering simulation
key = ChaCha20Poly1305.generate_key()
msg = b"Hello World"
aad = b"ENEE456" # example associated data

# Normal operation
nonce, ct = encrypt_aead(key, msg, aad)
print("Original decryption:", decrypt_aead(key, nonce, ct, aad).decode())

# Tampering with ciphertext
tampered_ct = bytearray(ct)
tampered_ct[0] ^= 1 # flip a bit
tampered_ct = bytes(tampered_ct)
print("\n-- Ciphertext Tampering Simulation --")
try:
    decrypt_aead(key, nonce, tampered_ct, aad)
    print("Decryption succeeded (unexpected)!")
except Exception as e:
    print("Tampering detected (ciphertext):", type(e).__name__)

# Tampering with authentication tag
# Tag is the last 16 bytes of the ciphertext with ChaCha20-Poly1305
tag_start = len(ct) - 16
tampered_tag_ct = bytearray(ct)
tampered_tag_ct[tag_start] ^= 1 # flip a bit in the tag
tampered_tag_ct = bytes(tampered_tag_ct)
print("\n-- Tag Tampering Simulation --")
try:
    decrypt_aead(key, nonce, tampered_tag_ct, aad)
    print("Decryption succeeded (unexpected)!")
except Exception as e:
    print("Tampering detected (tag):", type(e).__name__)
