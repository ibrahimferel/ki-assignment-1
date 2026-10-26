import secrets
from typing import NamedTuple, Optional
from Crypto.Cipher import AES, ARC4, DES
from Crypto.Util.Padding import pad,unpad
from app.crypto.errors import CryptoError

SUPPORTED_ALGORITHMS = ("AES","DES","RC4")
BLOCK_MODE = "CBC"
RC4_DROP = 1024

"""dalam bytes"""
_KEY_LENGTH = {"AES": 32, "DES": 8,"RC4": 16} 
_BLOCK = {"AES": (AES,AES.block_size),  "DES": (DES,DES.block_size)}

class RawResult(NamedTuple):
    mode: Optional[str] = None
    iv: Optional[bytes] = None
    ciphertext: Optional[bytes] = None

def key_len(algorithm: str) -> int:
    try:
        return _KEY_LENGTH[algorithm]
    except (KeyError, TypeError):
        raise CryptoError(f"Unsupported algorithm: {algorithm}")

def _check_key(algorithm:  str, key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise CryptoError("Key must be bytes or bytearray")
    if len(key) != key_len(algorithm):
        raise CryptoError(f"Key length false")

"""for encrypting"""
def encrypt(algorithm: str, key: bytes, plaintext: bytes, mode: Optional[str] = None) -> RawResult:
    _check_key(algorithm, key)
    if algorithm == "RC4":
        cipher = ARC4.new(key, drop=RC4_DROP)
        return RawResult(None,None,cipher.encrypt(plaintext))

    module, block_size = _BLOCK[algorithm]
    iv = secrets.token_bytes(block_size)
    cipher = module.new(key, module.MODE_CBC, iv=iv)
    """modified"""
    ciphertext = cipher.encrypt(pad(plaintext, block_size))
    return RawResult(BLOCK_MODE, iv, ciphertext)

"""for decrypting"""
def decrypt(algorithm: str, key: bytes, ciphertext: bytes, mode: Optional[str] = None, iv: Optional[bytes] = None) -> bytes:
    _check_key(algorithm, key)
    if algorithm == "RC4":
        if mode is not None or iv is not None:
            raise CryptoError("RC4 does not use mode or iv")
        return ARC4.new(key, drop=RC4_DROP).decrypt(ciphertext)

    module, block_size = _BLOCK[algorithm]
    if mode != BLOCK_MODE:
        raise CryptoError(f"Invalid mode")
    if not isinstance(iv, (bytes, bytearray)) or len(iv) != block_size:
        raise CryptoError(f"Invalid iv")
    if len(ciphertext) % block_size != 0:
        raise CryptoError(f"Invalid ciphertext length")
    padded = module.new(key, module.MODE_CBC, iv=iv).decrypt(ciphertext)

    try:
        return unpad(padded, block_size)
    except ValueError:
        raise CryptoError("Invalid padding")
    