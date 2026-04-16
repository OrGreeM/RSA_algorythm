"""
implementation of RSA algorythm
"""
import random
from miller_rabin_primality_test import is_prime


def generate_prime(bits: int) -> int:
    random_range = random.SystemRandom()

    while True:
        potential_prime = random_range.getrandbits(bits)
        potential_prime |= (1 << (bits - 1)) | 1
        if is_prime(potential_prime):
            return potential_prime


def generate_keys(bits: int) -> tuple:
    while True:
        p, q = generate_prime(bits // 2), generate_prime(bits // 2)
        if p != q:
            break

    n = p * q
    e = 65537
    d = pow(e, -1, (p - 1) * (q - 1))

    return ((n, e), (n, d))


def encrypt_int(m: int, public_key: tuple) -> int:
    n, e = public_key
    if m >= n:
        raise ValueError()
    return pow(m, e, n)


def decrypt_int(c: int, private_key: tuple) -> int:
    n, d = private_key
    return pow(c, d, n)


def _block_sizes(n: int):
    key_bytes = (n.bit_length() + 7) // 8
    plain_block = key_bytes - 1
    cipher_block = key_bytes
    return plain_block, cipher_block


def encrypt_bytes(data: bytes, public_key: tuple) -> bytes:
    n, _ = public_key
    plain_block, cipher_block = _block_sizes(n)

    out = b''
    for i in range(0, len(data), plain_block):
        chunk = data[i:i + plain_block]
        m = int.from_bytes(chunk, 'big')
        c = encrypt_int(m, public_key)
        out += c.to_bytes(cipher_block, 'big')
    return out


def decrypt_bytes(data: bytes, private_key: tuple) -> bytes:
    n, _ = private_key
    plain_block, cipher_block = _block_sizes(n)

    if len(data) % cipher_block != 0:
        raise ValueError("ciphertext length is not aligned with block size")

    out = b''
    total_blocks = len(data) // cipher_block
    for i in range(total_blocks):
        chunk = data[i * cipher_block:(i + 1) * cipher_block]
        c = int.from_bytes(chunk, 'big')
        m = decrypt_int(c, private_key)

        if i == total_blocks - 1:
            size = (m.bit_length() + 7) // 8
            out += m.to_bytes(size, 'big') if size else b''
        else:
            out += m.to_bytes(plain_block, 'big')
    return out


def encrypt_string(text: str, public_key: tuple) -> bytes:
    return encrypt_bytes(text.encode('utf-8'), public_key)


def decrypt_string(data: bytes, private_key: tuple) -> str:
    return decrypt_bytes(data, private_key).decode('utf-8')
