"""Database models: ``user``, ``stored_file``, ``cipher_copy`` and the
key sharing tables ``user_key``, ``access_request`` and ``shared_copy``.

The layout follows docs/data-model.md. One ``User`` owns many ``StoredFile``
rows, and every ``StoredFile`` has three ``CipherCopy`` rows (AES, DES, RC4).
The database stores only metadata and wrapped keys. Plaintext and ciphertext
never go into it; ciphertext lives in files under STORAGE_DIR.

Assignment 2 (key management, see docs/sharing-design.md) adds three
tables. ``user_key`` keeps a public key and a private key that is
encrypted with the user's own password. ``access_request`` keeps the share
key only wrapped with the master key. ``shared_copy`` points to a re-encrypted
ciphertext file. No raw key is ever stored.

Foreign keys are enforced by ``app.db_pragmas``. Do not remove that import:
without it SQLite ignores ON DELETE CASCADE and accepts orphan rows.
"""

import re
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.orm import validates

from app import db_pragmas  # noqa: F401  (registers the foreign key listener)
from app.extensions import db

__all__ = [
    "ALGORITHMS",
    "KINDS",
    "REQUEST_STATUSES",
    "AccessRequest",
    "CipherCopy",
    "SharedCopy",
    "StoredFile",
    "User",
    "UserKey",
]

KINDS = ("personal_data", "id_card", "document", "video")
BLOCK_ALGORITHMS = ("AES", "DES")  # need a mode and an IV
STREAM_ALGORITHMS = ("RC4",)  # no mode, no IV
ALGORITHMS = BLOCK_ALGORITHMS + STREAM_ALGORITHMS
REQUEST_STATUSES = ("pending", "approved", "rejected")

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
    key = db.relationship(
        "UserKey",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    # Requests this user made (as the requester) and received (as the owner).
    requests_made = db.relationship(
        "AccessRequest",
        foreign_keys="AccessRequest.requester_id",
        back_populates="requester",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AccessRequest.id",
    )
    requests_received = db.relationship(
        "AccessRequest",
        foreign_keys="AccessRequest.owner_id",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="AccessRequest.id",
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
    plaintext_sha256 = db.Column(db.String(64), nullable=False)

    owner = db.relationship("User", back_populates="files")
    copies = db.relationship(
        "CipherCopy",
        back_populates="file",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="CipherCopy.id",
    )
    shared_copies = db.relationship(
        "SharedCopy",
        back_populates="file",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="SharedCopy.id",
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


class UserKey(db.Model):
    """The RSA key pair of one user (one row per user).

    ``public_key_pem`` is public. ``encrypted_private_key`` is the private
    key encrypted with the user's own password, so only that password opens
    it. Both columns keep the bytes produced by the crypto layer.
    """

    __tablename__ = "user_key"

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "user.id", ondelete="CASCADE", name="fk_user_key_user_id"
        ),
        primary_key=True,
    )
    public_key_pem = db.Column(db.LargeBinary, nullable=False)
    encrypted_private_key = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)

    user = db.relationship("User", back_populates="key")


class AccessRequest(db.Model):
    """A request of ``requester`` to see data of ``owner``.

    ``wrapped_share_key`` is the share key wrapped with MASTER_KEY, and
    ``key_package`` is the same key encrypted for the requester's public
    key. Both stay empty until the owner approves.
    """

    __tablename__ = "access_request"

    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "user.id",
            ondelete="CASCADE",
            name="fk_access_request_requester_id",
        ),
        nullable=False,
    )
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "user.id", ondelete="CASCADE", name="fk_access_request_owner_id"
        ),
        nullable=False,
    )
    status = db.Column(db.String(16), nullable=False, default="pending")
    reason = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    decided_at = db.Column(db.DateTime, nullable=True)
    wrapped_share_key = db.Column(db.LargeBinary, nullable=True)
    key_package = db.Column(db.Text, nullable=True)
    unlocked_at = db.Column(db.DateTime, nullable=True)

    requester = db.relationship(
        "User", foreign_keys=[requester_id], back_populates="requests_made"
    )
    owner = db.relationship(
        "User", foreign_keys=[owner_id], back_populates="requests_received"
    )
    shared_copies = db.relationship(
        "SharedCopy",
        back_populates="request",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="SharedCopy.id",
    )

    __table_args__ = (
        db.Index("ix_access_request_requester_id", "requester_id"),
        db.Index("ix_access_request_owner_id", "owner_id"),
        db.CheckConstraint(
            _in("status", REQUEST_STATUSES), name="ck_access_request_status"
        ),
        db.CheckConstraint(
            "requester_id != owner_id",
            name="ck_access_request_distinct_users",
        ),
        # At most one pending request per (requester, owner) pair. A partial
        # unique index: it only covers the rows whose status is 'pending', so
        # an approved or rejected request does not block a new one.
        db.Index(
            "uq_access_request_pending_pair",
            "requester_id",
            "owner_id",
            unique=True,
            sqlite_where=text("status = 'pending'"),
        ),
    )


class SharedCopy(db.Model):
    """One record of the owner, re-encrypted for one access request.

    The ciphertext (with its AES-GCM tag at the end) is a file under
    STORAGE_DIR named ``storage_name``; ``ciphertext_size`` is the length of
    that whole blob.
    """

    __tablename__ = "shared_copy"

    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "access_request.id",
            ondelete="CASCADE",
            name="fk_shared_copy_request_id",
        ),
        nullable=False,
    )
    file_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "stored_file.id",
            ondelete="CASCADE",
            name="fk_shared_copy_file_id",
        ),
        nullable=False,
    )
    nonce = db.Column(db.LargeBinary, nullable=False)
    storage_name = db.Column(db.String(64), nullable=False)
    ciphertext_size = db.Column(db.Integer, nullable=False)

    request = db.relationship("AccessRequest", back_populates="shared_copies")
    file = db.relationship("StoredFile", back_populates="shared_copies")

    # The unique (request_id, file_id) pair also serves lookups by request_id,
    # so only file_id gets a separate index.
    __table_args__ = (
        db.UniqueConstraint(
            "request_id", "file_id", name="uq_shared_copy_request_id_file_id"
        ),
        db.UniqueConstraint(
            "storage_name", name="uq_shared_copy_storage_name"
        ),
        db.Index("ix_shared_copy_file_id", "file_id"),
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
