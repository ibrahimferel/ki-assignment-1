"""Turn on SQLite foreign-key enforcement for every database connection.

SQLite does NOT enforce FOREIGN KEY constraints by default, so
``ON DELETE CASCADE`` silently does nothing and orphan rows can be inserted.
The setting must be switched on separately for each connection, and SQLite
ignores it once a transaction has started, so it is done the moment a new
connection is opened.

Importing this module registers the listener (once per process). It is
imported by ``app.models``, which ``create_app()`` imports before the first
query. The listener applies to every SQLite engine created in the process.
"""

import sqlite3

from sqlalchemy import event
from sqlalchemy.engine import Engine

__all__ = ["enable_sqlite_foreign_keys"]


@event.listens_for(Engine, "connect")
def enable_sqlite_foreign_keys(dbapi_connection, connection_record):
    """Run ``PRAGMA foreign_keys=ON`` on a newly opened SQLite connection."""
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return  # Another database: nothing to do.

    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA foreign_keys")
        row = cursor.fetchone()
    finally:
        cursor.close()

    # No row, or 0, means this SQLite build can not enforce foreign keys.
    if not row or row[0] != 1:
        dbapi_connection.close()
        raise RuntimeError(
            "SQLite foreign key enforcement could not be enabled; "
            "refusing to run without it."
        )
