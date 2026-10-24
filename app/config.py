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
from pathlib import Path
from typing import Mapping, Optional

from dotenv import load_dotenv

# Project root: the folder that contains ``app/`` and ``.env``.
BASE_DIR = Path(__file__).resolve().parent.parent

MIN_SECRET_KEY_LENGTH = 32
DEFAULT_MAX_UPLOAD_MB = 100

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
        self.DEBUG = _read_bool(environ, "FLASK_DEBUG", default=False)
        self.SQLALCHEMY_DATABASE_URI = _read_database_uri(environ)
        self.MAX_CONTENT_LENGTH = _read_max_upload_mb(environ) * 1024 * 1024


class TestingConfig:
    """Settings for automated tests.

    Never reads ``.env`` or ``DATABASE_URL``, so a test run can not touch the
    real database. The database lives in memory and the secret key is random
    for every instance.
    """

    # Tell pytest this is not a test class, despite the "Test" name prefix.
    __test__ = False

    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MAX_CONTENT_LENGTH = DEFAULT_MAX_UPLOAD_MB * 1024 * 1024

    def __init__(self) -> None:
        self.SECRET_KEY = secrets.token_hex(32)
