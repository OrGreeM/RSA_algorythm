"""
Simple symmetric cipher (XOR with repeating key)
"""
import os


KEY_SIZE = 32


def generate_sym_key() -> bytes:
    return os.urandom(KEY_SIZE)


def sym_encrypt(message: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(message))


def sym_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    return sym_encrypt(ciphertext, key)
