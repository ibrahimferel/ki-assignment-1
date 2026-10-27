import hashlib
import hmac

from flask import current_app
from flask_login import current_user

from app.crypto import decrypt_copy, encrypt_all
from app.extensions import db
from app.models import CipherCopy, StoredFile
from app.storage.disk import read_ciphertext, remove_ciphertext, write_ciphertext
from app.storage.validation import (
    max_file_bytes,
    MAX_PERSONAL_BYTES,
    UPLOAD_FORMATS,
    UploadTooLarge,
    ValidationError,
    serialize_personal,
)

PERSONAL_KIND = "personal_data"


def cleanup_ciphertexts(names):
    """Cleanup best effort tanpa menutupi error operasi utama."""
    failed = []
    for name in names:
        try:
            remove_ciphertext(name)
        except OSError:
            failed.append(name)
    if failed:
        # Hanya nama acak yang dicatat (untuk cleanup ulang), bukan isi/kunci.
        current_app.logger.warning(
            "Cleanup ciphertext gagal untuk %d file: %s", len(failed), failed
        )
    return failed


def create_record(*, plaintext, kind, filename, content_type):
    """Return StoredFile tersimpan, dengan tiga CipherCopy."""
    if not current_user.is_authenticated:
        raise PermissionError("Login diperlukan")
    if not isinstance(kind, str) or (kind != PERSONAL_KIND and kind not in UPLOAD_FORMATS):
        raise ValidationError("Jenis data tidak valid")
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        raise ValidationError("Nama file tidak valid")
    if not isinstance(content_type, str) or not content_type or len(content_type) > 100:
        raise ValidationError("Content type tidak valid")
    if not isinstance(plaintext, bytes) or not plaintext:
        raise ValidationError("Data tidak valid")
    limit = MAX_PERSONAL_BYTES if kind == PERSONAL_KIND else max_file_bytes()
    if len(plaintext) > limit:
        raise UploadTooLarge("Ukuran data melebihi batas")

    digest = hashlib.sha256(plaintext).hexdigest()
    results = encrypt_all(plaintext, current_app.config['MASTER_KEY'])

    stored = StoredFile(
        owner_id=current_user.id,
        kind=kind,
        original_filename=filename,
        content_type=content_type,
        plaintext_size=len(plaintext),
        plaintext_sha256=digest,
    )
    written = []
    try:
        db.session.add(stored)
        for result in results:
            name = write_ciphertext(result.ciphertext)
            written.append(name)
            stored.copies.append(CipherCopy(
                algorithm=result.algorithm,
                mode=result.mode,
                iv=result.iv,
                wrapped_key=result.wrapped_key,
                storage_name=name,
                ciphertext_size=len(result.ciphertext),
                encrypt_seconds=result.encryption_time,
            ))
        if len(stored.copies) != 3:
            raise ValueError("Tiga salinan ciphertext diperlukan")
        db.session.commit()
    except Exception:
        db.session.rollback()
        cleanup_ciphertexts(written)
        raise
    return stored


def decrypt_record(stored, algorithm):
    """Return plaintext hanya jika dekripsi dan pemeriksaan hash lolos."""
    copy = next((c for c in stored.copies if c.algorithm == algorithm), None)
    if copy is None:
        raise ValueError("Salinan ciphertext tidak tersedia")

    plaintext = decrypt_copy(
        algorithm=copy.algorithm,
        mode=copy.mode,
        iv=copy.iv,
        wrapped_key=copy.wrapped_key,
        ciphertext=read_ciphertext(copy.storage_name),
        master_key=current_app.config['MASTER_KEY'],
    )
    digest = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(digest, stored.plaintext_sha256):
        raise ValueError("Hash plaintext tidak cocok")
    return plaintext


def update_personal_record(stored, payload):
    """Return objek yang diperbarui; kegagalan mempertahankan data lama."""
    if stored.kind != PERSONAL_KIND:
        raise ValidationError("Bukan data pribadi")
    plaintext = serialize_personal(payload)

    old_names = [c.storage_name for c in stored.copies]
    copies_by_algorithm = {c.algorithm: c for c in stored.copies}
    new_names = []
    try:
        results = encrypt_all(plaintext, current_app.config['MASTER_KEY'])
        fresh = {}
        for result in results:
            # Tidak boleh ada algoritma baru atau ganda: unique(file_id, algorithm).
            if result.algorithm not in copies_by_algorithm or result.algorithm in fresh:
                raise ValueError("Algoritma hasil enkripsi tidak sesuai")
            name = write_ciphertext(result.ciphertext)
            new_names.append(name)
            fresh[result.algorithm] = (result, name)
        if not fresh or set(fresh) != set(copies_by_algorithm):
            raise ValueError("Tiga salinan ciphertext diperlukan")

        for algorithm, (result, name) in fresh.items():
            copy = copies_by_algorithm[algorithm]
            copy.mode = result.mode
            copy.iv = result.iv
            copy.wrapped_key = result.wrapped_key
            copy.storage_name = name
            copy.ciphertext_size = len(result.ciphertext)
            copy.encrypt_seconds = result.encryption_time
        stored.plaintext_size = len(plaintext)
        stored.plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
        db.session.commit()
    except Exception:
        db.session.rollback()
        cleanup_ciphertexts(new_names)
        raise

    # Di luar try: kegagalan cleanup tidak membatalkan transaksi yang sudah commit.
    cleanup_ciphertexts(old_names)
    return stored


def delete_record(stored):
    """Hapus metadata, commit, kemudian cleanup ciphertext."""
    names = [c.storage_name for c in stored.copies]
    try:
        db.session.delete(stored)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise  # file tidak dihapus
    cleanup_ciphertexts(names)
