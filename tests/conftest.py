"""Shared pytest fixtures.

Every test gets its own application with an empty in-memory database, so
tests can not affect each other and nothing is written to the real
``instance/`` folder.
"""

import secrets

import pytest

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import CipherCopy, StoredFile, User


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
