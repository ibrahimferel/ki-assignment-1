"""Authentication services: account policy, password hashing, login checks.

Routes and templates must call these functions and must not hash or compare
passwords themselves. Every function that touches the database needs an
active application context.

Design decisions (see the CP5 plan):

* Passwords are hashed with Argon2id (argon2-cffi, library defaults).
* Usernames are ASCII only: 3 to 32 characters from ``a-z 0-9 . _ -``,
  starting and ending with a letter or digit. They are stored lower case.
* Passwords are 10 to 128 characters after NFKC normalization. There are no
  composition rules; control characters, the username itself and a short list
  of very common passwords are refused.
* ``authenticate`` returns ``None`` for every kind of failure and always
  spends one hash verification, so neither the answer nor the timing says
  whether the username exists.

This module never logs and never prints. Error messages are fixed texts that
do not contain user input.
"""

import re
import secrets
import threading
import unicodedata

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import User

__all__ = [
    "AuthError",
    "PASSWORD_MAX",
    "PASSWORD_MIN",
    "PasswordPolicyError",
    "USERNAME_MAX",
    "USERNAME_MIN",
    "UsernamePolicyError",
    "UsernameTakenError",
    "authenticate",
    "get_user",
    "hash_password",
    "normalize_username",
    "register_user",
    "validate_password",
    "verify_password",
]

USERNAME_MIN = 3
USERNAME_MAX = 32  # must equal the width of the ``user.username`` column
PASSWORD_MIN = 10
PASSWORD_MAX = 128

# NFKC can shrink a string (a base letter plus combining marks becomes one
# character) but never by anywhere near this factor. Longer raw input is
# refused before normalization so nobody can make us normalize megabytes.
_RAW_PASSWORD_LIMIT = PASSWORD_MAX * 8

_USERNAME_CHARS = re.compile(r"[a-z0-9._-]+")

# Lower-cased on purpose; compared with ``str.casefold``. Every entry is at
# least PASSWORD_MIN long, otherwise it could never be reached. This is a
# minimal safeguard, not a complete list of weak passwords.
_COMMON_PASSWORDS = frozenset(
    {
        "password123",
        "password1234",
        "passw0rd123",
        "passwordpassword",
        "1234567890",
        "12345678910",
        "123456789012",
        "0123456789",
        "9876543210",
        "1111111111",
        "0000000000",
        "qwertyuiop",
        "qwerty12345",
        "qwerty123456",
        "1q2w3e4r5t",
        "asdfghjkl123",
        "abcdefghij",
        "abc1234567",
        "iloveyou123",
        "letmein1234",
        "welcome1234",
        "administrator",
        "changeme123",
    }
)

_MESSAGES = {
    "username_too_short": "Username is too short.",
    "username_too_long": "Username is too long.",
    "username_invalid_characters": (
        "Username may only contain the letters a-z, digits, '.', '_' and '-'."
    ),
    "username_bad_edge": (
        "Username must start and end with a letter or a digit."
    ),
    "username_taken": "Username is already taken.",
    "password_too_short": "Password is too short.",
    "password_too_long": "Password is too long.",
    "password_invalid_characters": (
        "Password contains characters that are not allowed."
    ),
    "password_same_as_username": "Password must not be the username.",
    "password_too_common": "Password is too common.",
}


class AuthError(Exception):
    """Base class. ``code`` is stable; ``message`` is a fixed English text."""

    def __init__(self, code):
        message = _MESSAGES[code]
        super().__init__(message)
        self.code = code
        self.message = message


class UsernamePolicyError(AuthError):
    """The username breaks the username rules."""


class PasswordPolicyError(AuthError):
    """The password breaks the password rules."""


class UsernameTakenError(AuthError):
    """Another account already uses this username."""

    def __init__(self):
        super().__init__("username_taken")


# Created once. Constructing it does no hashing.
_HASHER = PasswordHasher()

_dummy_lock = threading.Lock()
_dummy = None  # (password, hash), built on first use


def _require_str(value, name):
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")


def normalize_username(raw):
    """Return the stored form of ``raw`` or raise ``UsernamePolicyError``."""
    _require_str(raw, "username")
    text = raw.strip()
    # Check ASCII BEFORE lower(): lower() turns some non-ASCII characters
    # (for example the Kelvin sign) into plain ASCII letters.
    if not text.isascii():
        raise UsernamePolicyError("username_invalid_characters")
    text = text.lower()
    if len(text) < USERNAME_MIN:
        raise UsernamePolicyError("username_too_short")
    if len(text) > USERNAME_MAX:
        raise UsernamePolicyError("username_too_long")
    if _USERNAME_CHARS.fullmatch(text) is None:
        raise UsernamePolicyError("username_invalid_characters")
    if not (text[0].isalnum() and text[-1].isalnum()):
        raise UsernamePolicyError("username_bad_edge")
    return text


def _check_password_shape(password):
    """NFKC-normalize ``password`` and refuse unusable input.

    Shared by hashing, verification and the policy check, so all three agree
    on what the password "is". Returns the normalized text.
    """
    _require_str(password, "password")
    if len(password) > _RAW_PASSWORD_LIMIT:
        raise PasswordPolicyError("password_too_long")
    normalized = unicodedata.normalize("NFKC", password)
    if len(normalized) > PASSWORD_MAX:
        raise PasswordPolicyError("password_too_long")
    # Cc: control characters (NUL, tab, newline). Cs: lone surrogates, which
    # can not be encoded to UTF-8.
    if any(unicodedata.category(c) in ("Cc", "Cs") for c in normalized):
        raise PasswordPolicyError("password_invalid_characters")
    return normalized


def validate_password(password, username=None):
    """Raise ``PasswordPolicyError`` unless ``password`` is acceptable.

    ``username`` is optional; when given, a password equal to it (ignoring
    case) is refused.
    """
    normalized = _check_password_shape(password)
    if len(normalized) < PASSWORD_MIN:
        raise PasswordPolicyError("password_too_short")
    if username is not None:
        _require_str(username, "username")
        if normalized.casefold() == username.strip().casefold():
            raise PasswordPolicyError("password_same_as_username")
    if normalized.casefold() in _COMMON_PASSWORDS:
        raise PasswordPolicyError("password_too_common")


def hash_password(password):
    """Return an Argon2id hash string for ``password``.

    Low level: it enforces the character and length cap but NOT the full
    policy. Use ``register_user`` to create accounts.
    """
    return _HASHER.hash(_check_password_shape(password))


def _verify(stored_hash, prepared_password):
    """Argon2 check of already normalized input; ``False`` on any mismatch
    or unreadable hash."""
    try:
        return _HASHER.verify(stored_hash, prepared_password)
    except (VerificationError, InvalidHashError):
        return False


def verify_password(stored_hash, password):
    """True only if ``password`` matches ``stored_hash``.

    Never raises because of the content of its arguments: an unusable
    password or a damaged hash is simply ``False``. Non-string arguments are
    programming errors and raise ``TypeError``.
    """
    _require_str(stored_hash, "stored_hash")
    try:
        prepared = _check_password_shape(password)
    except PasswordPolicyError:
        return False
    return _verify(stored_hash, prepared)


def _dummy_credentials():
    """A random password and its hash, made once per process.

    Verifying against it costs the same as verifying against a real account,
    which keeps the time for "unknown user" close to "wrong password".
    """
    global _dummy
    with _dummy_lock:
        if _dummy is None:
            secret = secrets.token_urlsafe(32)
            _dummy = (secret, _HASHER.hash(secret))
        return _dummy


def register_user(username, password):
    """Create, save and return a new ``User``.

    Raises ``UsernamePolicyError``, ``PasswordPolicyError`` or
    ``UsernameTakenError``. Commits the session.
    """
    name = normalize_username(username)
    validate_password(password, name)
    user = User(username=name, password_hash=hash_password(password))
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        taken = (
            db.session.execute(
                select(User.id).where(User.username == name)
            ).first()
            is not None
        )
        if not taken:
            raise  # some other integrity problem: do not mislabel it
    else:
        return user
    # Raised outside the ``except`` block on purpose: the IntegrityError
    # carries the password hash in its parameters and must not stay
    # reachable through ``__context__``.
    raise UsernameTakenError()


def authenticate(username, password):
    """Return the ``User`` for valid credentials, otherwise ``None``.

    Every failure looks the same to the caller: bad username format, unknown
    user, wrong password, unusable password, damaged stored hash. Exactly one
    hash verification is done in every case.
    """
    _require_str(username, "username")
    _require_str(password, "password")

    try:
        name = normalize_username(username)
    except UsernamePolicyError:
        name = None
    user = None
    if name is not None:
        user = db.session.execute(
            select(User).where(User.username == name)
        ).scalar_one_or_none()

    try:
        candidate = _check_password_shape(password)
    except PasswordPolicyError:
        candidate = None

    if user is not None and candidate is not None:
        verified = _verify(user.password_hash, candidate)
    else:
        # Same amount of work, and the real input is never hashed when it
        # is unusable (for example megabytes long).
        dummy_password, dummy_hash = _dummy_credentials()
        _verify(dummy_hash, dummy_password)
        verified = False

    return user if verified else None


def get_user(user_id):
    """Return the ``User`` with this id, or ``None``.

    Meant for the Flask-Login ``user_loader``. Only a real ``int`` in the
    range SQLite can store is accepted; anything else is ``None``.
    """
    if isinstance(user_id, bool) or not isinstance(user_id, int):
        return None
    if not 1 <= user_id <= 2**63 - 1:
        return None
    return db.session.get(User, user_id)
