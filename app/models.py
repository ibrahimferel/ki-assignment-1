"""Database models: ``user``, ``stored_file`` and ``cipher_copy``.

The layout follows docs/data-model.md. One ``User`` owns many ``StoredFile``
rows, and every ``StoredFile`` has three ``CipherCopy`` rows (AES, DES, RC4).
The database stores only metadata and wrapped keys. Plaintext and ciphertext
never go into it; ciphertext lives in files under STORAGE_DIR.

Foreign keys are enforced by ``app.db_pragmas``. Do not remove that import:
without it SQLite ignores ON DELETE CASCADE and accepts orphan rows.
"""

import re
from datetime import datetime, timezone

from sqlalchemy.orm import validates

from app import db_pragmas  # noqa: F401  (registers the foreign key listener)
from app.extensions import db

__all__ = [
    "ALGORITHMS",
    "KINDS",
    "CipherCopy",
    "StoredFile",
    "User",
]

KINDS = ("personal_data", "id_card", "document", "video")
BLOCK_ALGORITHMS = ("AES", "DES")  # need a mode and an IV
STREAM_ALGORITHMS = ("RC4",)  # no mode, no IV
ALGORITHMS = BLOCK_ALGORITHMS + STREAM_ALGORITHMS

# Random file names only: no dots and no slashes, so path tricks are
# impossible by construction.
_STORAGE_NAME = re.compile(r"[A-Za-z0-9_-]{16,64}")


def _utcnow():
    """Current UTC time as a naive datetime (SQLite keeps no time zone)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _in(column, values):
    """SQL text ``column IN ('a', 'b')``, built from trusted constants."""
    return f"{column} IN ({', '.join(repr(value) for value in values)})"


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)

    files = db.relationship(
        "StoredFile",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="StoredFile.id",
    )

    __table_args__ = (
        db.UniqueConstraint("username", name="uq_user_username"),
        db.CheckConstraint(
            "length(username) > 0 AND username = lower(username)"
            " AND username = trim(username)",
            name="ck_user_username_normalized",
        ),
    )

    @validates("username")
    def _normalize_username(self, key, value):
        if value is None:
            return value
        if not isinstance(value, str):
            raise TypeError("username must be a string")
        return value.strip().lower()

    # The interface Flask-Login needs. Written out instead of inheriting
    # ``UserMixin``, whose ``__eq__`` compares ids: two unsaved users (id
    # None) would compare equal.
    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return False

    def get_id(self):
        if self.id is None:
            raise ValueError("user has no id yet; save it before logging in")
        return str(self.id)


class StoredFile(db.Model):
    __tablename__ = "stored_file"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "user.id", ondelete="CASCADE", name="fk_stored_file_owner_id"
        ),
        nullable=False,
    )
    kind = db.Column(db.String(16), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(100), nullable=False)
    plaintext_size = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)

    owner = db.relationship("User", back_populates="files")
    copies = db.relationship(
        "CipherCopy",
        back_populates="file",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CipherCopy.id",
    )

    __table_args__ = (
        db.Index("ix_stored_file_owner_id", "owner_id"),
        db.CheckConstraint(_in("kind", KINDS), name="ck_stored_file_kind"),
        db.CheckConstraint(
            "plaintext_size >= 0", name="ck_stored_file_plaintext_size"
        ),
    )


class CipherCopy(db.Model):
    __tablename__ = "cipher_copy"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "stored_file.id",
            ondelete="CASCADE",
            name="fk_cipher_copy_file_id",
        ),
        nullable=False,
    )
    algorithm = db.Column(db.String(8), nullable=False)
    mode = db.Column(db.String(8), nullable=True)
    iv = db.Column(db.LargeBinary, nullable=True)
    wrapped_key = db.Column(db.LargeBinary, nullable=False)
    storage_name = db.Column(db.String(64), nullable=False)
    ciphertext_size = db.Column(db.Integer, nullable=False)
    encrypt_seconds = db.Column(db.Float, nullable=False)

    file = db.relationship("StoredFile", back_populates="copies")

    __table_args__ = (
        db.UniqueConstraint(
            "file_id", "algorithm", name="uq_cipher_copy_file_id_algorithm"
        ),
        db.UniqueConstraint(
            "storage_name", name="uq_cipher_copy_storage_name"
        ),
        db.Index("ix_cipher_copy_file_id", "file_id"),
        db.CheckConstraint(
            _in("algorithm", ALGORITHMS), name="ck_cipher_copy_algorithm"
        ),
        # RC4 has no mode and no IV; AES and DES need both.
        db.CheckConstraint(
            f"({_in('algorithm', STREAM_ALGORITHMS)}"
            " AND mode IS NULL AND iv IS NULL)"
            f" OR ({_in('algorithm', BLOCK_ALGORITHMS)}"
            " AND mode IS NOT NULL AND iv IS NOT NULL)",
            name="ck_cipher_copy_mode_iv",
        ),
        db.CheckConstraint(
            "ciphertext_size >= 0", name="ck_cipher_copy_ciphertext_size"
        ),
        db.CheckConstraint(
            "encrypt_seconds >= 0", name="ck_cipher_copy_encrypt_seconds"
        ),
    )

    @validates("storage_name")
    def _check_storage_name(self, key, value):
        if value is None:
            return value
        if not isinstance(value, str):
            raise TypeError("storage_name must be a string")
        if _STORAGE_NAME.fullmatch(value) is None:
            raise ValueError(
                "storage_name must be 16 to 64 letters, digits, '_' or '-'"
            )
        return value
