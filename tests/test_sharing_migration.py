"""The revoked-status upgrade preserves existing SQLite data and constraints."""

import sqlite3

import pytest
from sqlalchemy.schema import CreateIndex, CreateTable

from app.extensions import db
from app.models import AccessRequest
from migrate_sharing_status import main, upgrade_status


@pytest.fixture()
def legacy():
    connection = sqlite3.connect(":memory:")
    connection.executescript("""
        PRAGMA foreign_keys = ON;
        CREATE TABLE user (id INTEGER PRIMARY KEY);
        INSERT INTO user VALUES (1), (2);
        CREATE TABLE access_request (
            id INTEGER PRIMARY KEY,
            requester_id INTEGER REFERENCES user(id) ON DELETE CASCADE,
            owner_id INTEGER REFERENCES user(id) ON DELETE CASCADE,
            status TEXT NOT NULL,
            wrapped_share_key BLOB,
            CONSTRAINT ck_access_request_status
                CHECK (status IN ('pending', 'approved', 'rejected')),
            CONSTRAINT ck_access_request_distinct_users CHECK (requester_id != owner_id)
        );
        CREATE UNIQUE INDEX uq_access_request_pending_pair
            ON access_request(requester_id, owner_id) WHERE status = 'pending';
        CREATE TABLE shared_copy (
            id INTEGER PRIMARY KEY,
            request_id INTEGER REFERENCES access_request(id) ON DELETE CASCADE
        );
        INSERT INTO access_request VALUES (1, 1, 2, 'approved', X'1234');
        INSERT INTO access_request VALUES (2, 1, 2, 'approved', NULL);
        INSERT INTO shared_copy VALUES (1, 1);
    """)
    yield connection
    connection.close()


def test_upgrade_preserves_data_indexes_and_child_cascades(legacy):
    assert upgrade_status(legacy)
    assert legacy.execute("SELECT * FROM shared_copy").fetchall() == [(1, 1)]
    assert legacy.execute("SELECT status, wrapped_share_key FROM access_request ORDER BY id").fetchall() == [
        ("approved", b"\x12\x34"), ("revoked", None),
    ]
    assert legacy.execute("PRAGMA foreign_keys").fetchone() == (1,)
    assert legacy.execute("PRAGMA foreign_key_check").fetchall() == []
    legacy.execute("UPDATE access_request SET status = 'revoked' WHERE id = 1")
    legacy.execute("INSERT INTO access_request VALUES (3, 1, 2, 'pending', NULL)")
    with pytest.raises(sqlite3.IntegrityError):
        legacy.execute("INSERT INTO access_request VALUES (4, 1, 2, 'pending', NULL)")
    legacy.execute("DELETE FROM access_request WHERE id = 1")
    assert legacy.execute("SELECT * FROM shared_copy").fetchall() == []
    legacy.commit()
    assert not upgrade_status(legacy)


def test_upgrade_rolls_back_on_foreign_key_violation(legacy):
    before = legacy.execute("SELECT sql FROM sqlite_master WHERE name='access_request'").fetchone()
    legacy.execute("PRAGMA foreign_keys = OFF")
    legacy.execute("INSERT INTO shared_copy VALUES (2, 999)")
    legacy.commit()
    legacy.execute("PRAGMA foreign_keys = ON")
    with pytest.raises(ValueError, match="Foreign-key"):
        upgrade_status(legacy)
    assert legacy.execute("SELECT sql FROM sqlite_master WHERE name='access_request'").fetchone() == before
    assert legacy.execute("SELECT status FROM access_request WHERE id=2").fetchone() == ("approved",)
    assert legacy.execute("PRAGMA foreign_keys").fetchone() == (1,)


def test_command_creates_restorable_backup(legacy, tmp_path):
    path = tmp_path / "app.db"
    with sqlite3.connect(path) as target:
        legacy.backup(target)
    assert main([str(path)]) == 0
    backups = list(tmp_path.glob("app.db.before-revoked-*.bak"))
    assert len(backups) == 1
    with sqlite3.connect(backups[0]) as backup:
        assert backup.execute("SELECT status FROM access_request WHERE id=2").fetchone() == ("approved",)
    with sqlite3.connect(path) as upgraded:
        assert upgraded.execute("SELECT status FROM access_request WHERE id=2").fetchone() == ("revoked",)


def test_upgrade_accepts_actual_repository_schema(app):
    table = AccessRequest.__table__
    legacy_sql = str(CreateTable(table).compile(db.engine)).replace(", 'revoked'", "")
    with db.engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE access_request")
        connection.exec_driver_sql(legacy_sql)
        for index in table.indexes:
            connection.exec_driver_sql(str(CreateIndex(index).compile(db.engine)))
    connection = db.engine.raw_connection()
    try:
        assert upgrade_status(connection.driver_connection)
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name='access_request'").fetchone()[0]
        assert "'revoked'" in schema
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()
