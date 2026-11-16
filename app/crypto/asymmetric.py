"""The key pair of one user (Assignment 2, contract 1).

This module holds exactly one public function, ``generate_user_keypair``.
The other functions of the key sharing contract belong to Member 2.

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

The password
------------
The password is normalized with NFKC and encoded as UTF-8 here, the same
normalization ``app.auth.services`` applies before hashing a password, so a
password that logs in also opens this key. Whoever opens the private key
later must apply exactly the same two steps. pycryptodome would turn a
``str`` passphrase into latin-1 bytes; this module always passes bytes.

This module never logs and never prints. Error messages are fixed texts that
do not contain the password or any key material.
"""

import unicodedata

from Crypto.PublicKey import RSA

from app.crypto.errors import CryptoError

__all__ = ["generate_user_keypair"]

RSA_BITS = 3072
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
