"""The key pair of one user, and RSA-OAEP with it (Assignment 2, contract 1).

This module holds three public functions. ``generate_user_keypair``
(Member 1) makes the key pair; ``encrypt_for_user`` and
``decrypt_with_password`` (Member 2) use it for RSA-OAEP. The symmetric half
of key sharing (share key, AES-GCM, key package) is in ``app.crypto.share``.

What is produced
----------------
* an RSA key pair, 3072 bits, public exponent 65537;
* the public key as a PEM ``SubjectPublicKeyInfo`` (``BEGIN PUBLIC KEY``);
* the private key as a PEM PKCS#8 ``ENCRYPTED PRIVATE KEY``, protected with
  the user's own password by PBES2 (scrypt, AES-256-CBC).

scrypt parameters (written into the PEM itself, so a reader needs no
configuration): N = 2**14, r = 8, p = 1, 16 byte random salt. N = 2**14 was
chosen because ``cryptography`` 41.0.3 (the version in requirements.txt)
refuses to open a larger N. It is far stronger than the 2048 round PBKDF2 that
version would use by default, but below what OWASP currently recommends for
scrypt (N = 2**17). Raising it later is possible only when every reader of
these keys can open the larger value.

RSA-OAEP with the key pair
--------------------------
``encrypt_for_user`` and ``decrypt_with_password`` carry the 32-byte share
key K of one access request to the requester inside the key package (see
``app.crypto.share``):

* OAEP with SHA-256 and MGF1-SHA-256. ``hashAlgo`` is always passed, because
  pycryptodome's default would be SHA-1;
* the OAEP label is the request id (``app.crypto.share.oaep_label``), so a
  ciphertext made for one request does not decrypt under the label of
  another request;
* only 3072-bit keys are accepted: the ciphertext is always 384 bytes and the
  plaintext at most 318 bytes (384 - 2 * 32 - 2);
* ``decrypt_with_password`` opens the private key with the same password
  steps that ``generate_user_keypair`` uses (see "The password" below).

Only pycryptodome is imported here. The tests check the OAEP output in both
directions against ``cryptography``.

The password
------------
The password is normalized with NFKC and encoded as UTF-8 here, the same
normalization ``app.auth.services`` applies before hashing a password, so a
password that logs in also opens this key. Whoever opens the private key
later must apply exactly the same two steps. pycryptodome would turn a
``str`` passphrase into latin-1 bytes; this module always passes bytes.

Errors
------
Every failure raises ``CryptoError`` with a fixed message, raised outside
any ``except`` block, so no library error (which may carry key material)
stays reachable through ``__context__``. Each OAEP function uses a single
message for all of its failures, so the caller can not tell which check
failed: a wrong password, a wrong label and a damaged ciphertext look the same.

This module never logs and never prints. Error messages are fixed texts that
do not contain the password or any key material.
"""

import unicodedata

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from app.crypto.errors import CryptoError

__all__ = ["generate_user_keypair","encrypt_for_user","decrypt_with_password"]

RSA_BITS = 3072
_OAEP_CIPHERTEXT_BYTES = RSA_BITS // 8
_OAEP_MAX_PLAINTEXT_BYTES = _OAEP_CIPHERTEXT_BYTES - 2 * SHA256.digest_size - 2
_OAEP_ENCRYPT_FAILED = "Could not encrypt the message for the user"
_OAEP_DECRYPT_FAILED = "Could not decrypt the message with the password"
RSA_EXPONENT = 65537

# Parameters of the protection of the private key (see the module docstring).
_PROTECTION = "scryptAndAES256-CBC"
_SCRYPT_PARAMS = {
    "iteration_count": 2**14,  # this is scrypt's N in pycryptodome
    "block_size": 8,  # r
    "parallelization": 1,  # p
    "salt_size": 16,
}
_ENCRYPTED_HEADER = b"-----BEGIN ENCRYPTED PRIVATE KEY-----"

# Same raw limit as app.auth.services (PASSWORD_MAX * 8): longer input is
# refused before it is normalized. The password policy itself is checked by
# the caller (validate_password), not here.
_PASSWORD_LIMIT = 1024

_BAD_PASSWORD = (
    "Password must be a non-empty string of at most 1024 characters"
)
_FAILED = "Could not generate the user key pair"


def _generate_rsa_key():
    """Make a new RSA key. A separate function only so tests can swap it."""
    return RSA.generate(RSA_BITS, e=RSA_EXPONENT)


def generate_user_keypair(password):
    """Return ``(public_pem, encrypted_private_pem)``, both ``bytes``.

    ``password`` is the user's password as typed; it is normalized here (see
    the module docstring). Raises ``CryptoError`` with a fixed message when
    the password is not a usable string or when the key pair can not be made.
    """
    failure = None
    passphrase = b""
    if isinstance(password, str) and len(password) <= _PASSWORD_LIMIT:
        try:
            passphrase = unicodedata.normalize("NFKC", password).encode(
                "utf-8"
            )
        except UnicodeEncodeError:  # a lone surrogate
            passphrase = b""
    if not passphrase:
        failure = _BAD_PASSWORD

    if failure is None:
        try:
            key = _generate_rsa_key()
            public_pem = bytes(key.publickey().export_key(format="PEM"))
            private_pem = bytes(
                key.export_key(
                    format="PEM",
                    passphrase=passphrase,
                    pkcs=8,
                    protection=_PROTECTION,
                    prot_params=_SCRYPT_PARAMS,
                )
            )
        except Exception:  # noqa: BLE001 - any failure becomes CryptoError
            failure = _FAILED
        else:
            # Never hand back a private key that is not encrypted.
            if private_pem.startswith(_ENCRYPTED_HEADER):
                return public_pem, private_pem
            failure = _FAILED

    # Raised outside every ``except`` block on purpose: the original error
    # may carry key material and must not stay reachable through
    # ``__context__``.
    raise CryptoError(failure)

def _password_to_bytes(password):
    """Turn a typed password into bytes exactly as ``generate_user_keypair`` does.

    NFKC, then UTF-8. Returns ``None`` for anything that is not a ``str`` of
    at most ``_PASSWORD_LIMIT`` (1024) characters, or that can not be encoded
    (a lone surrogate). An empty password gives ``b""``, which
    ``decrypt_with_password`` refuses, as ``generate_user_keypair`` does.
    """
    if isinstance(password, str) and len(password) <= _PASSWORD_LIMIT:
        try:
            return unicodedata.normalize("NFKC", password).encode("utf-8")
        except UnicodeEncodeError:  # a lone surrogate
            pass
    return None

def encrypt_for_user(public_pem, data, label) -> bytes:
    ciphertext = None
    if (
        isinstance(data, bytes)
        and isinstance(label, bytes)
        and len(data) <= _OAEP_MAX_PLAINTEXT_BYTES
    ):
        try:
            key = RSA.import_key(public_pem)
            if not key.has_private() and key.size_in_bits() == RSA_BITS:
                cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, label=label)
                ciphertext = cipher.encrypt(data)
        except Exception:  # noqa: BLE001 - any failure becomes CryptoError
            ciphertext = None
    if ciphertext is None:  # outside the except block: no __context__
        raise CryptoError(_OAEP_ENCRYPT_FAILED)
    return ciphertext


def decrypt_with_password(encrypted_private_pem, password, ciphertext, label) -> bytes:
    plaintext = None
    passphrase = _password_to_bytes(password)
    if (
        passphrase
        and isinstance(ciphertext, bytes)
        and len(ciphertext) == _OAEP_CIPHERTEXT_BYTES   # exactly 384, not <= 318
        and isinstance(label, bytes)
    ):
        try:
            key = RSA.import_key(encrypted_private_pem, passphrase=passphrase)
            if key.has_private() and key.size_in_bits() == RSA_BITS:
                cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256, label=label)
                plaintext = cipher.decrypt(ciphertext)
        except Exception:  # noqa: BLE001
            plaintext = None
    if plaintext is None:
        raise CryptoError(_OAEP_DECRYPT_FAILED)
    return plaintext
