"""Create the database tables and the ciphertext folder.

This is an explicit, separate step: ``create_app()`` never touches the
database. ``init_db()`` is safe to run again; it never drops or alters
anything that already exists.
"""

import os
import stat
from pathlib import Path
from typing import NamedTuple, Tuple

from sqlalchemy import inspect

from app import models  # noqa: F401  (registers the tables with ``db``)
from app.config import BASE_DIR
from app.extensions import db

__all__ = ["InitDbError", "InitDbReport", "init_db"]

EXPECTED_TABLES = frozenset({"user", "stored_file", "cipher_copy"})
STORAGE_MODE = 0o700  # only the owner may read, write or list the folder


class InitDbError(Exception):
    """Initialisation can not continue. The message is safe to show."""


class InitDbReport(NamedTuple):
    tables_created: Tuple[str, ...]
    tables_existing: Tuple[str, ...]
    storage_dir: Path
    storage_created: bool
    storage_tightened: bool


def _check_storage_path(raw: Path, instance_path: Path) -> Path:
    """Return the resolved storage path, or raise if it is not acceptable.

    Paths are compared after ``resolve()`` (never as raw strings), so
    symlinks and macOS's ``/var`` -> ``/private/var`` can not fool the checks.
    """
    if raw.is_symlink():
        raise InitDbError(
            "STORAGE_DIR must not be a symbolic link; "
            "point it at the real folder."
        )
    path = raw.resolve()
    if path.is_relative_to(BASE_DIR / "app"):
        raise InitDbError(
            "STORAGE_DIR must not be inside the app/ source folder."
        )
    if BASE_DIR.is_relative_to(path):
        raise InitDbError(
            "STORAGE_DIR must not be the project folder or one of its "
            "parents."
        )
    if instance_path.resolve().is_relative_to(path):
        raise InitDbError(
            "STORAGE_DIR must not contain the instance/ folder, which "
            "holds the database."
        )
    if path.exists() and not path.is_dir():
        raise InitDbError("STORAGE_DIR points to a file, not a folder.")
    return path


def _check_existing_tables(inspector, tables) -> None:
    """Fail loudly if a table on disk has other columns than the models."""
    for name in sorted(tables):
        on_disk = {column["name"] for column in inspector.get_columns(name)}
        wanted = {column.name for column in db.metadata.tables[name].columns}
        if on_disk != wanted:
            raise InitDbError(
                f"Table '{name}' already exists with different columns. "
                "There are no migrations: delete the database file in "
                "instance/ and run this command again."
            )


def _prepare_storage(path: Path) -> Tuple[bool, bool]:
    """Create the folder (owner-only) or tighten an existing one.

    Returns ``(created, tightened)``.
    """
    existed = path.exists()
    try:
        path.mkdir(mode=STORAGE_MODE, parents=True, exist_ok=True)
        if os.name != "posix":
            return (not existed, False)
        before = stat.S_IMODE(path.stat().st_mode)
        if before != STORAGE_MODE:
            # mkdir()'s mode is reduced by the umask and ignored for an
            # existing folder, so set it explicitly.
            os.chmod(path, STORAGE_MODE)
        after = stat.S_IMODE(path.stat().st_mode)
    except OSError as error:
        raise InitDbError(
            f"Could not prepare the storage folder ({error.strerror})."
        ) from None
    if after & 0o077 or not os.access(path, os.R_OK | os.W_OK | os.X_OK):
        raise InitDbError("The storage folder is not owner-only and usable.")
    return (not existed, existed and before != STORAGE_MODE)


def init_db(flask_app) -> InitDbReport:
    """Create missing tables and the storage folder for ``flask_app``."""
    storage = _check_storage_path(
        Path(flask_app.config["STORAGE_DIR"]), Path(flask_app.instance_path)
    )

    with flask_app.app_context():
        if set(db.metadata.tables) != EXPECTED_TABLES:
            raise InitDbError("The models are not registered as expected.")
        existing = EXPECTED_TABLES & set(inspect(db.engine).get_table_names())
        _check_existing_tables(inspect(db.engine), existing)
        db.create_all()
        now = set(inspect(db.engine).get_table_names())
        if not EXPECTED_TABLES <= now:
            raise InitDbError("Some tables were not created.")

    created, tightened = _prepare_storage(storage)
    return InitDbReport(
        tables_created=tuple(sorted(EXPECTED_TABLES - existing)),
        tables_existing=tuple(sorted(existing)),
        storage_dir=storage,
        storage_created=created,
        storage_tightened=tightened,
    )
