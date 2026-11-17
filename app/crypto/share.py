import base64
import re
import secrets
import string
import struct
from typing import Tuple
from app.crypto.asymmetric import RSA_BITS
from app.crypto.errors import CryptoError
from app.crypto.keys import unwrap_key, wrap_key
from Crypto.Cipher import AES

__all__ = [
    "new_share_key",
    "encrypt_shared",
    "decrypt_shared",
    "wrap_share_key",
    "unwrap_share_key",
    "encode_key_package",
    "decode_key_package",
    "share_aad",
    "oaep_label"
]

SHARE_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MAX_ID = 2**63 - 1

PACKAGE_HEADER = "MEDVAULT-KEY-V1"
PACKAGE_MAX_CHARS = 2048
PACKAGE_CIPHERTEXT_BYTES = RSA_BITS // 8
PACKAGE_LINE_LENGTH = 64

_ID_ERROR = "invalid share ID"
_ENCRYPT_ERROR = "could not encrypt the shared data"
_DECRYPT_ERROR = "could not decrypt the shared data"
_PACKAGE_ERROR = "could not decode the key package"
_REQUEST_LINE = re.compile(r"REQUEST ([1-9][0-9]{0,18})")
_DROP_WHITESPACE = str.maketrans("", "", string.whitespace)

def _is_valid_id(value) -> bool:
    """Return True if the value is a valid share ID."""
    return type(value) is int and 1 <= value <= MAX_ID

def wrap_label(request_id) -> str:
    """Return the OAEP label for a share request with the given ID."""
    return "SHARE-%d" % request_id

def share_aad(request_id, file_id) -> bytes:
    """Return the AAD for a share request with the given ID."""
    if not (_is_valid_id(request_id) and _is_valid_id(file_id)):
        raise CryptoError(_ID_ERROR)
    return struct.pack(">QQ", request_id, file_id)

def oaep_label(request_id) -> bytes:
    """Return the OAEP label for a share request with the given ID."""
    if not _is_valid_id(request_id):
        raise CryptoError(_ID_ERROR)
    return struct.pack(">Q", request_id)

def new_share_key() -> bytes:
    return secrets.token_bytes(SHARE_KEY_BYTES)

def encrypt_shared(key, plaintext, aad) -> Tuple[bytes, bytes]:
    if not (
        type(key) is bytes and len(key) == SHARE_KEY_BYTES and type(plaintext) is bytes and type(aad) is bytes
    ):
        raise CryptoError(_ENCRYPT_ERROR)
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_BYTES)
    cipher.update(aad)
    body, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, body + tag

def decrypt_shared(key, nonce, ciphertext, aad) -> bytes:
    plaintext = None
    if (
        type(key) is bytes
        and len(key) == SHARE_KEY_BYTES
        and type(nonce) is bytes
        and len(nonce) == GCM_NONCE_BYTES
        and type(ciphertext) is bytes
        and len(ciphertext) >= GCM_TAG_BYTES
        and type(aad) is bytes
    ):
        view = memoryview(ciphertext)
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_BYTES)
            cipher.update(aad)
            plaintext = cipher.decrypt_and_verify(view[:-GCM_TAG_BYTES], view[-GCM_TAG_BYTES:])
        except (ValueError, TypeError):  # raised by PyCryptodome on failure
            plaintext = None
    if plaintext is None:
        raise CryptoError(_DECRYPT_ERROR)
    return plaintext

def wrap_share_key(master_key, key, request_id) -> bytes:
    if not (
        _is_valid_id(request_id)
        and type(master_key) is bytes
        and len(master_key) == SHARE_KEY_BYTES
        and type(key) is bytes
        and len(key) == SHARE_KEY_BYTES
    ):
        raise CryptoError(_ENCRYPT_ERROR)
    return wrap_key(master_key, key, wrap_label(request_id))

def unwrap_share_key(master_key, wrapped, request_id) -> bytes:
    if not (
        _is_valid_id(request_id)
        and type(master_key) is bytes
        and len(master_key) == SHARE_KEY_BYTES
        and type(wrapped) is bytes
    ):
        raise CryptoError(_DECRYPT_ERROR)
    try:
        key = unwrap_key(master_key, wrapped, wrap_label(request_id))
    except CryptoError:
        key = None
    if key is None or len(key) != SHARE_KEY_BYTES:
        raise CryptoError(_DECRYPT_ERROR)
    return key

def encode_key_package(request_id, encrypted_key) -> str:
    if not (
        _is_valid_id(request_id)
        and type(encrypted_key) is bytes
        and len(encrypted_key) == PACKAGE_CIPHERTEXT_BYTES
    ):
        raise CryptoError(_PACKAGE_ERROR)
    b64 = base64.b64encode(encrypted_key).decode("ascii")
    lines = [b64[i : i + PACKAGE_LINE_LENGTH] for i in range(0, len(b64), PACKAGE_LINE_LENGTH)]
    return "\n".join([PACKAGE_HEADER, "REQUEST %d" % request_id] + lines)

def decode_key_package(text) -> Tuple[int, bytes]:
    request_id = None
    encrypted_share_key = None
    if type(text) is str and len(text) <= PACKAGE_MAX_CHARS and text.isascii():
        lines = [line.strip() for line in text.splitlines()]
        lines = [line for line in lines if line]
        if len(lines) >= 3 and lines[0] == PACKAGE_HEADER:
            match = _REQUEST_LINE.fullmatch(lines[1])
            if match is not None and _is_valid_id(int(match.group(1))):
                request_id = int(match.group(1))
                body = "".join(lines[2:]).translate(_DROP_WHITESPACE)
                try:
                    encrypted_share_key = base64.b64decode(body, validate=True)
                except ValueError:
                    encrypted_share_key = None
    if request_id is None or encrypted_share_key is None or len(encrypted_share_key) != PACKAGE_CIPHERTEXT_BYTES:
        raise CryptoError(_PACKAGE_ERROR)
    return request_id, encrypted_share_key