import secrets

from Crypto.Cipher import AES
from app.crypto.errors import CryptoError
from app.crypto.ciphers import key_len

MASTER_KEY_LENGTH = 32
WRAP_VERSION = 1
NONCE_LENGTH = 16
TAG_LENGTH = 32
_AAD_LABEL = b"cryptoapp|keywrap"

def generate_key(algorithm: str) -> bytes:
    try:
        return secrets.token_bytes(key_len(algorithm))
    except (KeyError, TypeError):
        raise CryptoError(f"Error generating key")

def _check_master_key(master_key: bytes) -> None:
    if(
        not isinstance(master_key, (bytes, bytearray))
        or len(master_key) != MASTER_KEY_LENGTH
    ):
        raise CryptoError(f"Master key must be {MASTER_KEY_LENGTH} bytes")

def _aad(algorithm: str) -> bytes:
    return _AAD_LABEL + algorithm.encode("ascii")

def wrap_key(master_key: bytes, key: bytes, algorithm: str) -> bytes:
    
    _check_master_key(master_key)
    
    aad = _aad(algorithm)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    cipher.update(aad)

    ciphertext, tag = cipher.encrypt_and_digest(key)
    return (
        WRAP_VERSION.to_bytes(1, "big")
        + nonce
        + tag
        + ciphertext
    )

def unwrap_key(master_key: bytes, wrapped_key: bytes, algorithm: str) -> bytes:
    _check_master_key(master_key)
    aad = _aad(algorithm)
    
    if( 
        not isinstance(wrapped_key, (bytes, bytearray)) 
        or len(wrapped_key) < 1 + NONCE_LENGTH + TAG_LENGTH
        or wrapped_key[:1] != WRAP_VERSION
    ):
        raise CryptoError(f"Invalid wrapped key length")

    nonce = wrapped_key[1:1 + NONCE_LENGTH]
    encrypted = wrapped_key[1 + NONCE_LENGTH:-TAG_LENGTH]
    tag = wrapped_key[-TAG_LENGTH:]

    cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
    cipher.update(aad)

    try:
        return cipher.decrypt_and_verify(encrypted, tag)
    except ValueError:
        raise CryptoError(f"Invalid wrapped key")