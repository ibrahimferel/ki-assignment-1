"""Shared pytest fixtures.

Every test gets its own application with an empty in-memory database, so
tests can not affect each other and nothing is written to the real
``instance/`` folder.
"""

import secrets
import threading

import pytest

from app import create_app
from app.config import TestingConfig
from app.crypto import asymmetric
from app.extensions import db
from app.models import CipherCopy, StoredFile, User

# --------------------------------------------------------------------------
# RSA keys for tests
#
# Registering a user makes an RSA-3072 key pair, which takes about a second.
# To keep the suite fast, every test gets keys from a small pool of REAL,
# DIFFERENT RSA keys. The pool is built lazily, once per pytest session.
#
# The counter starts again in every test: the first key made in a test is
# pool key 1, the second is key 2, the third is key 3, and after that it
# wraps around to key 1. So only the FIRST THREE users of one test are
# guaranteed to have different key pairs; the fourth gets the same key pair
# as the first. The private key is still encrypted for real, with each user's
# own password. Ask for the ``real_keygen`` fixture to opt out and get a
# freshly generated key every time.
# --------------------------------------------------------------------------

_KEY_POOL_SIZE = 3
_REAL_GENERATE_RSA_KEY = asymmetric._generate_rsa_key
_key_pool = []
_key_pool_lock = threading.Lock()


@pytest.fixture(autouse=True)
def _pooled_rsa_keys(request, monkeypatch):
    """Swap the slow RSA generation for the pool (see the block above)."""
    if "real_keygen" in request.fixturenames:
        return
    counter = [0]

    def next_key():
        with _key_pool_lock:
            index = counter[0] % _KEY_POOL_SIZE
            counter[0] += 1
            while len(_key_pool) <= index:
                _key_pool.append(_REAL_GENERATE_RSA_KEY())
            return _key_pool[index]

    monkeypatch.setattr(asymmetric, "_generate_rsa_key", next_key)


@pytest.fixture()
def real_keygen():
    """Ask for this fixture to get a freshly generated RSA key every time.

    It does nothing by itself: ``_pooled_rsa_keys`` looks for its name.
    """


@pytest.fixture()
def rsa_key_pool():
    """The pool of RSA keys created so far (it fills up lazily)."""
    return _key_pool


@pytest.fixture()
def app(tmp_path):
    """A fresh app with created tables and an active application context."""
    config = TestingConfig()
    # TestingConfig points at a unique temp path; use pytest's own folder so
    # it is removed together with the test. The folder is NOT created here.
    config.STORAGE_DIR = tmp_path / "storage"
    flask_app = create_app(config)
    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def client(app):
    """A test client for ``app``."""
    return app.test_client()


@pytest.fixture()
def web(tmp_path):
    """A fresh app with created tables and NO open application context.

    Use it for tests that send several requests in a row (login, logout,
    CSRF). The ``app`` fixture keeps one application context open for the
    whole test, so ``g`` would be shared by all requests and Flask-Login
    would remember the user of the first one.
    """
    config = TestingConfig()
    config.STORAGE_DIR = tmp_path / "storage"
    flask_app = create_app(config)
    with flask_app.app_context():
        db.create_all()
    yield flask_app
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


@pytest.fixture()
def web_client(web):
    """A test client for ``web``."""
    return web.test_client()


@pytest.fixture()
def make_user(app):
    """Return a function that creates and saves a user."""

    def _make_user(username="alice", password_hash="hash-" + "x" * 20):
        user = User(username=username, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        return user

    return _make_user


@pytest.fixture()
def make_file(app):
    """Return a function that saves a file with its three ciphertext copies."""

    def _make_file(owner, kind="document", filename="report.pdf"):
        stored = StoredFile(
            owner=owner,
            kind=kind,
            original_filename=filename,
            content_type="application/pdf",
            plaintext_size=123,
            plaintext_sha256="0" * 64,
        )
        for algorithm, mode, iv in (
            ("AES", "CBC", b"\x01" * 16),
            ("DES", "CBC", b"\x02" * 8),
            ("RC4", None, None),
        ):
            stored.copies.append(
                CipherCopy(
                    algorithm=algorithm,
                    mode=mode,
                    iv=iv,
                    wrapped_key=b"w" * 60,
                    storage_name=secrets.token_hex(16),
                    ciphertext_size=128,
                    encrypt_seconds=0.001,
                )
            )
        db.session.add(stored)
        db.session.commit()
        return stored

    return _make_file
