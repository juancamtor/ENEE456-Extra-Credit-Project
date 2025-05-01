from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

# Key and plaintext setup
key = ChaCha20Poly1305.generate_key() # 256-bit random key
chacha = ChaCha20Poly1305(key)
plaintext = b"Hello World"
aad = b"ENEE456" # associated data (can be empty if not needed)

# AEAD ChaCha20-Poly1305 encryption
nonce = os.urandom(12) # 96-bit nonce
ciphertext = chacha.encrypt(nonce, plaintext, aad)
# Note: ciphertext includes the encrypted data. The 16-byte tag is appended internally.
print("Ciphertext (incl. tag):", ciphertext.hex())


# ---------------------- Transmission ----------------------


# Decryption and verification (receiver side)
received_aad = aad
received_ciphertext = ciphertext
received_nonce = nonce

# Check
try:
    decrypted_text = chacha.decrypt(received_nonce, received_ciphertext, received_aad)
    print("Decrypted message:", decrypted_text.decode())
except Exception as e:
    # If the tag or ciphertext was altered, an InvalidTag exception is raised
    print("Decryption failed:", str(e))
