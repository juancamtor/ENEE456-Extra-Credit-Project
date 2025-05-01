from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Key and plaintext setup
key_enc = os.urandom(32) # 256-bit AES key
key_mac = os.urandom(32) # 256-bit HMAC key
plaintext = b"Attack at dawn" # Example plaintext (bytes)

# Encrypt-then-MAC encryption
iv = os.urandom(16)  # 128-bit IV for AES-CBC
# Pad plaintext to 16-byte boundary (PKCS7)
padder = padding.PKCS7(128).padder()
padded_data = padder.update(plaintext) + padder.finalize()

# Encrypt using AES-CBC
cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(padded_data) + encryptor.finalize()

# Compute HMAC-SHA256 on IV || ciphertext
h = hmac.HMAC(key_mac, hashes.SHA256())
h.update(iv + ciphertext)
tag = h.finalize()


# ---------------------- Transmission ----------------------


# Decryption and verification (receiver side)
received_iv = iv
received_ciphertext = ciphertext
received_tag = tag

# Verify HMAC tag first
h2 = hmac.HMAC(key_mac, hashes.SHA256())
h2.update(received_iv + received_ciphertext)
try:
    h2.verify(received_tag) # raises InvalidSignature if tag does not match
    
    # If verification passes, proceed to decrypt
    cipher_dec = Cipher(algorithms.AES(key_enc), modes.CBC(received_iv))
    decryptor = cipher_dec.decryptor()
    padded_plain = decryptor.update(received_ciphertext) + decryptor.finalize()
    
    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext_out = unpadder.update(padded_plain) + unpadder.finalize()
    print("Decrypted message:", plaintext_out.decode())
except Exception as e:
    print("Verification failed! Ciphertext or tag tampered.")


# Ideally, if the data was uncorrupted, plaintext_out would be equal to 
the original plaintext.
