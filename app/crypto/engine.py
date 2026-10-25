import hashlib
import hmac
import os
import secrets
import time

from dataclasses import dataclass, field
from typing import Optional, NamedTuple, List
from app.crypto import ciphers, keys
from app.crypto.errors import CryptoError

ALGORITHMS = ("RC4", "AES", "DES")
MAC_KEY_LENGTH = 32
TAG_LENGTH = 32
_MAC_LABEL = b"cryptoapp|ciphertext"

@dataclass(frozen=True)
class EncryptedCopy:
    algorithm: str
    mode: Optional[str]
    iv: Optional[bytes] = field(repr=False)
    ciphertext: bytes = field(repr=False)
    wrapped_key: bytes = field(repr=False)
    encryption_time: float = 0.0

def _tag(mac_key, algorithm, mode, iv, body):
    header = (_MAC_LABEL + algorithm.encode() + (mode.encode() if mode else b"") + (iv if iv else b""))
    return hmac.new(mac_key, header + body, hashlib.sha256).digest()

def encrypt_one(algorithm: str, key: bytes, plaintext: bytes) -> EncryptedCopy:
    if algorithm not in ALGORITHMS:
        raise CryptoError(f"Unsupported algorithm")
    if not isinstance(plaintext, (bytes, bytearray)):
        raise CryptoError(f"Plaintext must be bytes or bytearray")
    cipher_key = keys.generate_key(algorithm)
    mac_key = secrets.token_bytes(MAC_KEY_LENGTH)
    
    start_time = time.perf_counter()
    raw_result = ciphers.encrypt(algorithm, cipher_key, plaintext)
    encryption_time = time.perf_counter() - start_time

    tag = _tag(mac_key, algorithm, raw_result.mode, raw_result.iv, raw_result.ciphertext)
    wrapped_key = keys.wrap_key(key, cipher_key + mac_key, algorithm)

    return EncryptedCopy(
        algorithm=algorithm,
        mode=raw_result.mode,
        iv=raw_result.iv,
        ciphertext=raw_result.ciphertext + tag,
        wrapped_key=wrapped_key,
        encryption_time=max(encryption_time, 0.0)
    )

def encrypt_all(plaintext: bytes, master_key: bytes) -> List[EncryptedCopy]:
    return [encrypt_one(algorithm, master_key, plaintext) for algorithm in ALGORITHMS]

def decrypt_copy(
    *,
    algorithm: str,
    mode: Optional[str],
    iv: Optional[bytes],
    wrapped_key: bytes,
    ciphertext: bytes,
    master_key: bytes
) -> bytes:
    
    if algorithm not in ALGORITHMS:
        raise CryptoError(f"Unsupported algorithm")

    secret_key = keys.unwrap_key(master_key, wrapped_key, algorithm)
    cipher_key_len = ciphers.key_len(algorithm)

    if len(secret_key) != cipher_key_len + MAC_KEY_LENGTH:
        raise CryptoError(f"Invalid secret key length")
    cipher_key, mac_key = secret_key[:cipher_key_len], secret_key[cipher_key_len:]

    if not isinstance(ciphertext, (bytes, bytearray)) or \
            len(ciphertext) < TAG_LENGTH:
        raise CryptoError(f"Ciphertext must be non-empty bytes or bytearray")
    body, tag = ciphertext[:-TAG_LENGTH], ciphertext[-TAG_LENGTH:]

    if not hmac.compare_digest(tag, _tag(mac_key, algorithm, mode, iv, body)):
        raise CryptoError(f"Invalid tag")
    return ciphers.decrypt(algorithm, cipher_key, bytes(body), mode, iv)