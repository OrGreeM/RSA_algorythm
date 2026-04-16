"""
Message integrity via SHA-256
"""
import hashlib


HASH_SIZE = 32


def compute_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_hash(data: bytes, expected_hash: bytes) -> bool:
    return compute_hash(data) == expected_hash
