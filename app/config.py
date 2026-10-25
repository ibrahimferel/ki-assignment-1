"""Application configuration.

All settings come from environment variables. For local development they can
be placed in a ``.env`` file (see ``.env.example``). No secret value is ever
stored in the source code.

Two configuration classes are provided:

* ``Config``        - normal runs; reads and validates the environment.
* ``TestingConfig`` - automated tests; isolated and self-contained.

Both are meant to be *instantiated*, e.g. ``app.config.from_object(Config())``.
"""

import os
import secrets
import string
import tempfile
from pathlib import Path
from typing import Mapping, Optional

from dotenv import load_dotenv

# Project root: the folder that contains ``app/`` and ``.env``.
BASE_DIR = Path(__file__).resolve().parent.parent

MIN_SECRET_KEY_LENGTH = 32
MASTER_KEY_BYTES = 32  # AES-256 key size; written as 64 hex characters.
DEFAULT_MAX_UPLOAD_MB = 50  # One upload is stored as 3 ciphertext copies.

# Where ciphertext files are kept. This matches Flask's instance/ folder for
# an app created in the ``app`` package; a test compares the two.
DEFAULT_STORAGE_DIR = BASE_DIR / "instance" / "storage"

# A relative SQLite path is placed inside the Flask instance/ folder by
# Flask-SQLAlchemy, which also creates that folder if it does not exist.
DEFAULT_DATABASE_URI = "sqlite:///app.db"

_TRUE_VALUES = {"1", "true", "yes", "on"}
_FALSE_VALUES = {"0", "false", "no", "off", ""}


class ConfigError(RuntimeError):
    """Raised when the environment does not describe a valid configuration."""


def _read_secret_key(env: Mapping[str, str]) -> str:
    value = env.get("SECRET_KEY", "").strip()
    if len(value) < MIN_SECRET_KEY_LENGTH:
        # Never put the value itself in the message: it may be a real secret.
        raise ConfigError(
            f"SECRET_KEY is missing or shorter than {MIN_SECRET_KEY_LENGTH} "
            "characters.\n"
            "Copy .env.example to .env and set SECRET_KEY to a random value:\n"
            '    python -c "import secrets; print(secrets.token_hex(32))"'
        )
    return value


def _read_master_key(env: Mapping[str, str], secret_key: str) -> bytes:
    """Return the master key as raw bytes, or raise ``ConfigError``.

    The key wraps the per-file keys stored in the database. It must be a
    different secret from SECRET_KEY, so that leaking one does not leak both.
    """
    help_text = (
        "Generate a separate value (not the one used for SECRET_KEY) and "
        "set it in .env:\n"
        '    python -c "import secrets; print(secrets.token_hex(32))"'
    )
    value = env.get("MASTER_KEY", "").strip()
    if value == "":
        raise ConfigError("MASTER_KEY is missing.\n" + help_text)
    # Checked by hand: bytes.fromhex() would also accept inner whitespace.
    if len(value) != MASTER_KEY_BYTES * 2 or any(
        char not in string.hexdigits for char in value
    ):
        raise ConfigError(
            f"MASTER_KEY must be exactly {MASTER_KEY_BYTES * 2} hexadecimal "
            f"characters ({MASTER_KEY_BYTES} bytes).\n" + help_text
        )
    if value.lower() == secret_key.lower():
        raise ConfigError("MASTER_KEY must be different from SECRET_KEY.")
    return bytes.fromhex(value)


def _read_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    value = raw.strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ConfigError(
        f"{name} must be one of: 1, 0, true, false, yes, no, on, off."
    )


def _read_max_upload_mb(env: Mapping[str, str]) -> int:
    raw = env.get("MAX_UPLOAD_MB", "").strip()
    if raw == "":
        return DEFAULT_MAX_UPLOAD_MB
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(
            "MAX_UPLOAD_MB must be a whole number of megabytes."
        ) from None
    if value <= 0:
        raise ConfigError("MAX_UPLOAD_MB must be greater than zero.")
    return value


def _read_database_uri(env: Mapping[str, str]) -> str:
    return env.get("DATABASE_URL", "").strip() or DEFAULT_DATABASE_URI


def _read_storage_dir(env: Mapping[str, str]) -> Path:
    """Return the ciphertext folder. Nothing is created on disk here."""
    raw = env.get("STORAGE_DIR", "").strip()
    if raw == "":
        return DEFAULT_STORAGE_DIR
    path = Path(raw)
    if not path.is_absolute():
        # Relative to the project folder, never to the current directory.
        path = BASE_DIR / path
    path = Path(os.path.normpath(path))
    if path.exists() and not path.is_dir():
        raise ConfigError("STORAGE_DIR points to a file, not a folder.")
    return path


class Config:
    """Settings for normal runs, read from the environment.

    ``environ`` exists so tests can pass a plain dict instead of touching the
    real environment. When it is omitted, ``.env`` is loaded first; variables
    that are already set in the real environment take priority over ``.env``.
    """

    def __init__(self, environ: Optional[Mapping[str, str]] = None) -> None:
        if environ is None:
            load_dotenv(BASE_DIR / ".env")
            environ = os.environ

        self.SECRET_KEY = _read_secret_key(environ)
        self.MASTER_KEY = _read_master_key(environ, self.SECRET_KEY)
        self.DEBUG = _read_bool(environ, "FLASK_DEBUG", default=False)
        self.SQLALCHEMY_DATABASE_URI = _read_database_uri(environ)
        self.MAX_CONTENT_LENGTH = _read_max_upload_mb(environ) * 1024 * 1024
        self.STORAGE_DIR = _read_storage_dir(environ)
        # Keep bound parameters (password hashes, wrapped keys) out of
        # database error messages and logs.
        self.SQLALCHEMY_ENGINE_OPTIONS = {"hide_parameters": True}


class TestingConfig:
    """Settings for automated tests.

    Never reads ``.env`` or ``DATABASE_URL``, so a test run can not touch the
    real database. The database lives in memory and both keys are random for
    every instance. STORAGE_DIR is a unique path in the system temp folder that
    is *not* created; the test fixture should replace it with ``tmp_path``.
    """

    # Tell pytest this is not a test class, despite the "Test" name prefix.
    __test__ = False

    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MAX_CONTENT_LENGTH = DEFAULT_MAX_UPLOAD_MB * 1024 * 1024

    def __init__(self) -> None:
        self.SECRET_KEY = secrets.token_hex(32)
        self.MASTER_KEY = secrets.token_bytes(MASTER_KEY_BYTES)
        unique_name = f"cryptoapp-test-{secrets.token_hex(8)}"
        self.STORAGE_DIR = Path(tempfile.gettempdir()) / unique_name
        self.SQLALCHEMY_ENGINE_OPTIONS = {"hide_parameters": True}
