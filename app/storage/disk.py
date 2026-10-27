import os
import re
import secrets
from pathlib import Path

from flask import current_app

STORAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{16,64}")


def storage_path(storage_name):
    """Return Path di dalam STORAGE_DIR; tolak nama/path tidak valid."""
    if not isinstance(storage_name, str) or not STORAGE_NAME_PATTERN.fullmatch(storage_name):
        raise ValueError("Nama penyimpanan tidak valid")
    base = Path(current_app.config['STORAGE_DIR']).resolve()
    path = (base / storage_name).resolve()
    if not path.is_relative_to(base):
        raise ValueError("Nama penyimpanan tidak valid")
    return path


def write_ciphertext(data):
    """Return nama acak setelah seluruh penulisan sukses."""
    if not isinstance(data, bytes):
        raise ValueError("Data harus berupa bytes")
    Path(current_app.config['STORAGE_DIR']).mkdir(mode=0o700, parents=True, exist_ok=True)
    for _ in range(10):
        name = secrets.token_hex(16)
        path = storage_path(name)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue # nama bentrok

        try:
            f = os.fdopen(fd, "wb")
        except BaseException:
            os.close(fd)
            path.unlink(missing_ok=True)
            raise

        try:
            with f:
                f.write(data)
        except BaseException:
            path.unlink(missing_ok=True) # bersihkan file parsial
            raise
        return name
    raise RuntimeError("Gagal membuat nama penyimpanan unik")


def read_ciphertext(storage_name):
    """Return bytes; biarkan FileNotFoundError diteruskan ke route."""
    return storage_path(storage_name).read_bytes()


def remove_ciphertext(storage_name):
    """Hapus ciphertext; file sudah hilang dianggap selesai."""
    try:
        storage_path(storage_name).unlink()
    except FileNotFoundError:
        pass
