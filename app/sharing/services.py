import hmac
import threading
import time
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

from flask import abort, current_app
from flask_login import current_user
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from app.authz import (
    MAX_ID,
    get_owned_or_404,
    get_requested_or_404,
    owned_select,
    requested_select,
)
from app.crypto import (
    CryptoError,
    decode_key_package,
    decrypt_shared,
    decrypt_with_password,
    encode_key_package,
    encrypt_for_user,
    encrypt_shared,
    new_share_key,
    oaep_label,
    share_aad,
    unwrap_share_key,
    wrap_share_key,
)
from app.extensions import db
from app.models import (
    AccessRequest,
    SharedCopy,
    StoredFile,
    User,
    UserKey,
)
from app.storage.disk import read_ciphertext, write_ciphertext
from app.storage.services import cleanup_ciphertexts, decrypt_record
from app.storage.validation import ValidationError

SHARE_TTL = timedelta(days=7)
UNLOCK_TTL = timedelta(minutes=15)
UNLOCK_MAX_ATTEMPTS = 5
UNLOCK_WINDOW_SECONDS = 15 * 60
UNLOCK_MAX_ENTRIES = 10000
STATE_ERROR = "Permintaan tidak dapat diproses"
PACKAGE_ERROR = "could not decode the key package"

class UnlockThrottled(Exception):
    def __init__(self, retry_after):
        super().__init__("Too many attempts.")
        self.retry_after = max(1, int(retry_after))

def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _iso(value):
    return None if value is None else value.isoformat() + "Z"

def _expires_at(access):
    if access.decided_at is None:
        return None
    return access.decided_at + SHARE_TTL

def _is_active(access):
    expires = _expires_at(access)
    return (
        access.status == "approved"
        and access.wrapped_share_key is not None
        and expires is not None
        and _now() < expires
    )

class UnlockLimiter:
    def __init__(
        self,
        limit=UNLOCK_MAX_ATTEMPTS,
        window=UNLOCK_WINDOW_SECONDS,
        max_entries=UNLOCK_MAX_ENTRIES,
    ):
        self._limit = limit
        self._window = window
        self._max_entries = max_entries
        self._hits = OrderedDict()
        self._lock = threading.Lock()

    def _purge(self, now):
        while self._hits:
            key = next(iter(self._hits))
            if now - self._hits[key][-1] < self._window:
                break
            del self._hits[key]

    def acquire(self, user_id, request_id):
        now = time.monotonic()
        key = (user_id, request_id)
        with self._lock:
            self._purge(now)
            hits = [t for t in self._hits.get(key, ()) if now - t < self._window]
            if len(hits) >= self._limit:
                self._hits[key] = hits
                return int(self._window - (now - hits[0])) + 1
            hits.append(now)
            self._hits[key] = hits
            self._hits.move_to_end(key)
            while len(self._hits) > self._max_entries:
                self._hits.popitem(last=False)
            return None

    def reset(self, user_id, request_id):
        with self._lock:
            self._hits.pop((user_id, request_id), None)

_THROTTLE_LOCK = threading.Lock()

def _unlock_throttle():
    throttle = current_app.extensions.get("unlock_throttle")
    if throttle is None:
        with _THROTTLE_LOCK:
            throttle = current_app.extensions.setdefault(
                "unlock_throttle", UnlockLimiter()
            )
    return throttle

def create_request(*, username, reason):
    owner = db.session.scalar(select(User).where(User.username == username))
    if owner is None:
        abort(404)
    if owner.id == current_user.id:
        raise ValidationError("Tidak dapat meminta akses ke diri sendiri")

    pending = select(AccessRequest.id).where(
        AccessRequest.requester_id == current_user.id,
        AccessRequest.owner_id == owner.id,
        AccessRequest.status == "pending",
    )
    if db.session.scalar(pending) is not None:
        raise ValidationError("Permintaan yang sama masih menunggu")

    access = AccessRequest(
        requester_id=current_user.id,
        owner_id=owner.id,
        reason=reason,
        status="pending",
    )
    db.session.add(access)
    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        if db.session.scalar(pending) is not None:
            raise ValidationError("Permintaan yang sama masih menunggu") from None
        raise
    except Exception:
        db.session.rollback()
        raise
    return access

def _serialize(access, counterpart):
    status = access.status
    return {
        "id": access.id,
        "username": counterpart,
        "reason": access.reason,
        "status": status,
        "created_at": _iso(access.created_at),
        "decided_at": _iso(access.decided_at),
        "expires_at": _iso(_expires_at(access)) if status == "approved" else None,
    }

def list_requests():
    incoming = db.session.scalars(
        owned_select(AccessRequest).order_by(AccessRequest.id.desc())
    ).all()
    outgoing = db.session.scalars(
        requested_select(AccessRequest).order_by(AccessRequest.id.desc())
    ).all()
    ids = {a.requester_id for a in incoming} | {a.owner_id for a in outgoing}
    names = {}
    if ids:
        names = dict(db.session.execute(
            select(User.id, User.username).where(User.id.in_(ids))
        ).all())
    return {
        "incoming": [_serialize(a, names.get(a.requester_id)) for a in incoming],
        "outgoing": [_serialize(a, names.get(a.owner_id)) for a in outgoing],
    }

def approve_request(request_id, *, file_ids):
    access = get_owned_or_404(AccessRequest, request_id)
    if access.status != "pending":
        raise ValidationError(STATE_ERROR)

    files = db.session.scalars(
        owned_select(StoredFile).where(StoredFile.id.in_(file_ids))
        .order_by(StoredFile.id)
    ).all()
    if len(files) != len(set(file_ids)):
        abort(404)

    user_key = db.session.get(UserKey, access.requester_id)
    if user_key is None:
        raise ValidationError(STATE_ERROR)

    share_key = new_share_key()
    new_names = []
    copies = []
    try:
        for stored in files:
            plaintext = decrypt_record(stored, "AES")
            nonce, blob = encrypt_shared(
                share_key, plaintext, share_aad(request_id, stored.id),
            )
            del plaintext
            name = write_ciphertext(blob)
            new_names.append(name)
            copies.append(SharedCopy(
                request_id=request_id,
                file_id=stored.id,
                nonce=nonce,
                storage_name=name,
                ciphertext_size=len(blob),
            ))

        wrapped = wrap_share_key(
            current_app.config["MASTER_KEY"], share_key, request_id,
        )
        sealed = encrypt_for_user(
            user_key.public_key_pem, share_key, oaep_label(request_id),
        )
        package = encode_key_package(request_id, sealed)

        result = db.session.execute(
            update(AccessRequest)
            .where(AccessRequest.id == request_id,
                   AccessRequest.status == "pending")
            .values(status="approved", decided_at=_now(),
                    wrapped_share_key=wrapped, key_package=package)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise ValidationError(STATE_ERROR)
        db.session.add_all(copies)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        cleanup_ciphertexts(new_names)
        if isinstance(exc, IntegrityError):
            raise ValidationError(STATE_ERROR) from None
        raise
    finally:
        del share_key
    return package

def get_key_package(request_id):
    access = get_owned_or_404(AccessRequest, request_id)
    if not _is_active(access) or not access.key_package:
        abort(404)
    return access.key_package

def reject_request(request_id):
    access = get_owned_or_404(AccessRequest, request_id)
    if access.status != "pending":
        raise ValidationError(STATE_ERROR)
    try:
        result = db.session.execute(
            update(AccessRequest)
            .where(AccessRequest.id == access.id,
                   AccessRequest.status == "pending")
            .values(status="rejected", decided_at=_now())
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise ValidationError(STATE_ERROR)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

def revoke_request(request_id):
    access = get_owned_or_404(AccessRequest, request_id)
    if access.status != "approved" or access.wrapped_share_key is None:
        raise ValidationError(STATE_ERROR)

    try:
        names = list(db.session.scalars(
            select(SharedCopy.storage_name)
            .where(SharedCopy.request_id == access.id)
        ))
        result = db.session.execute(
            update(AccessRequest)
            .where(AccessRequest.id == access.id,
                   AccessRequest.status == "approved",
                   AccessRequest.wrapped_share_key.is_not(None))
            .values(status="revoked", wrapped_share_key=None,
                    key_package=None, unlocked_at=None)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            raise ValidationError(STATE_ERROR)
        db.session.execute(
            delete(SharedCopy).where(SharedCopy.request_id == access.id)
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    try:
        cleanup_ciphertexts(names)
    except Exception:
        current_app.logger.warning(
            "Shared ciphertext cleanup failed for request %s", request_id,
        )

def unlock_request(request_id, *, key_package, password):
    access = get_requested_or_404(AccessRequest, request_id)
    if not _is_active(access):
        abort(404)

    throttle = _unlock_throttle()
    retry_after = throttle.acquire(current_user.id, request_id)
    if retry_after:
        raise UnlockThrottled(retry_after)

    package_id, sealed = decode_key_package(key_package)
    if package_id != request_id:
        raise CryptoError(PACKAGE_ERROR)

    user_key = db.session.get(UserKey, current_user.id)
    if user_key is None:
        raise CryptoError(PACKAGE_ERROR)

    package_key = decrypt_with_password(
        user_key.encrypted_private_key, password, sealed,
        oaep_label(request_id),
    )
    stored_key = unwrap_share_key(
        current_app.config["MASTER_KEY"],
        bytes(access.wrapped_share_key), request_id,
    )
    if not hmac.compare_digest(package_key, stored_key):
        raise CryptoError(PACKAGE_ERROR)
    del package_key, stored_key

    now = _now()
    try:
        result = db.session.execute(
            update(AccessRequest)
            .where(AccessRequest.id == request_id,
                   AccessRequest.status == "approved",
                   AccessRequest.wrapped_share_key.is_not(None),
                   AccessRequest.decided_at > now - SHARE_TTL)
            .values(unlocked_at=now)
            .execution_options(synchronize_session=False)
        )
        if result.rowcount != 1:
            abort(404)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise

    reset = getattr(throttle, "reset", None)
    if reset is not None:
        reset(current_user.id, request_id)

    copies = db.session.scalars(
        select(SharedCopy).where(SharedCopy.request_id == request_id)
        .order_by(SharedCopy.file_id)
    ).all()
    return {
        "files": [
            {
                "id": c.file.id,
                "name": c.file.original_filename,
                "kind": c.file.kind,
                "content_type": c.file.content_type,
                "size": c.file.plaintext_size,
            }
            for c in copies
        ],
        "unlocked_until": _iso(now + UNLOCK_TTL),
    }

def read_shared_file(request_id, file_id):
    if type(file_id) is not int or not 1 <= file_id <= MAX_ID:
        abort(404)
    access = get_requested_or_404(AccessRequest, request_id)
    if not _is_active(access) or access.unlocked_at is None:
        abort(404)
    if _now() >= access.unlocked_at + UNLOCK_TTL:
        abort(404)

    copy = db.session.scalar(
        select(SharedCopy).where(
            SharedCopy.request_id == request_id,
            SharedCopy.file_id == file_id,
        )
    )
    if copy is None:
        abort(404)

    key = unwrap_share_key(
        current_app.config["MASTER_KEY"],
        bytes(access.wrapped_share_key), request_id,
    )
    blob = read_ciphertext(copy.storage_name)
    plaintext = decrypt_shared(
        key, copy.nonce, blob, share_aad(request_id, file_id),
    )
    del key
    return copy.file, plaintext
