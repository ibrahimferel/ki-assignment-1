"""Tests for the database models (docs/data-model.md).

Database-level rules (CHECK, UNIQUE, foreign keys) are tested with raw SQL so
that the Python validators can not hide a missing database rule.
"""

import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import event, inspect, text
from sqlalchemy.exc import IntegrityError

from app import create_app
from app.config import TestingConfig
from app.extensions import db
from app.models import CipherCopy, StoredFile, User

# Every test here needs the app (and its context) from conftest.py.
pytestmark = pytest.mark.usefixtures("app")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

INSERT_USER = (
    'INSERT INTO "user" (username, password_hash, created_at) '
    "VALUES (:username, :password_hash, '2026-01-01 00:00:00')"
)
INSERT_FILE = (
    "INSERT INTO stored_file (owner_id, kind, original_filename, "
    "content_type, plaintext_size, created_at) VALUES "
    "(:owner_id, :kind, :original_filename, :content_type, "
    ":plaintext_size, '2026-01-01 00:00:00')"
)
INSERT_COPY = (
    "INSERT INTO cipher_copy (file_id, algorithm, mode, iv, wrapped_key, "
    "storage_name, ciphertext_size, encrypt_seconds) VALUES "
    "(:file_id, :algorithm, :mode, :iv, :wrapped_key, :storage_name, "
    ":ciphertext_size, :encrypt_seconds)"
)


def user_row(**changes):
    row = {"username": "raw-user", "password_hash": "hash"}
    row.update(changes)
    return row


def file_row(owner_id, **changes):
    row = {
        "owner_id": owner_id,
        "kind": "document",
        "original_filename": "a.pdf",
        "content_type": "application/pdf",
        "plaintext_size": 1,
    }
    row.update(changes)
    return row


def copy_row(file_id, **changes):
    row = {
        "file_id": file_id,
        "algorithm": "AES",
        "mode": "CBC",
        "iv": b"\x01" * 16,
        "wrapped_key": b"k" * 32,
        "storage_name": "n" * 32,
        "ciphertext_size": 1,
        "encrypt_seconds": 0.5,
    }
    row.update(changes)
    return row


def execute(sql, params):
    db.session.execute(text(sql), params)
    db.session.commit()


def assert_rejected(sql, params):
    """The database must refuse this row."""
    with pytest.raises(IntegrityError):
        execute(sql, params)
    db.session.rollback()


def count(table):
    return db.session.execute(text(f'SELECT COUNT(*) FROM "{table}"')).scalar()


def counts():
    return count("user"), count("stored_file"), count("cipher_copy")


# ----------------------------------------------------------------- creating


def test_user_file_and_copies_are_saved(make_user, make_file):
    user = make_user("alice")
    stored = make_file(user)

    assert user.id is not None and stored.id is not None
    assert counts() == (1, 1, 3)
    assert stored.kind == "document"
    assert stored.plaintext_size == 123
    assert sorted(copy.algorithm for copy in stored.copies) == [
        "AES",
        "DES",
        "RC4",
    ]


@pytest.mark.skipif(
    not hasattr(time, "tzset"), reason="time.tzset needs a POSIX system"
)
def test_created_at_is_naive_utc_whatever_the_local_time_zone(
    make_user, monkeypatch
):
    monkeypatch.setenv("TZ", "Pacific/Auckland")  # about 12 hours from UTC
    time.tzset()
    try:
        user = make_user("clock")
        stamp = user.created_at
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db.session.expire_all()
        assert stamp.tzinfo is None
        assert abs((now - stamp).total_seconds()) < 60
        assert user.created_at == stamp  # unchanged after reloading
    finally:
        monkeypatch.undo()
        time.tzset()


def test_created_at_is_naive_before_the_row_is_saved_too():
    # Before a commit the value is still the one Python produced; if it had a
    # time zone it would differ from what the database returns later.
    user = User(username="early", password_hash="h")
    db.session.add(user)
    db.session.flush()
    assert user.created_at.tzinfo is None


def test_created_at_is_set_for_each_row_separately(make_user):
    first = make_user("first")
    time.sleep(1.1)
    second = make_user("second")
    assert (second.created_at - first.created_at).total_seconds() >= 1


def test_explicit_created_at_is_kept(make_user):
    user = User(
        username="old",
        password_hash="h",
        created_at=datetime(2020, 5, 6, 7, 8, 9),
    )
    db.session.add(user)
    db.session.commit()
    db.session.expire_all()
    assert user.created_at == datetime(2020, 5, 6, 7, 8, 9)


def test_binary_and_numeric_values_round_trip(make_user, make_file):
    stored = make_file(make_user())
    aes = next(c for c in stored.copies if c.algorithm == "AES")
    rc4 = next(c for c in stored.copies if c.algorithm == "RC4")
    aes.wrapped_key = b"\x00\xff" * 50 + b"\x00"
    aes.encrypt_seconds = 1.2345678901234567
    stored.plaintext_size = 2**40
    db.session.commit()
    db.session.expire_all()

    assert aes.wrapped_key == b"\x00\xff" * 50 + b"\x00"
    assert aes.encrypt_seconds == 1.2345678901234567
    assert aes.iv == b"\x01" * 16
    assert stored.plaintext_size == 2**40
    assert rc4.mode is None and rc4.iv is None


# ------------------------------------------------------------------- schema


EXPECTED_COLUMNS = {
    "user": {
        "id": ("INTEGER", False),
        "username": ("VARCHAR(32)", False),
        "password_hash": ("VARCHAR(255)", False),
        "created_at": ("DATETIME", False),
    },
    "stored_file": {
        "id": ("INTEGER", False),
        "owner_id": ("INTEGER", False),
        "kind": ("VARCHAR(16)", False),
        "original_filename": ("VARCHAR(255)", False),
        "content_type": ("VARCHAR(100)", False),
        "plaintext_size": ("INTEGER", False),
        "created_at": ("DATETIME", False),
    },
    "cipher_copy": {
        "id": ("INTEGER", False),
        "file_id": ("INTEGER", False),
        "algorithm": ("VARCHAR(8)", False),
        "mode": ("VARCHAR(8)", True),
        "iv": ("BLOB", True),
        "wrapped_key": ("BLOB", False),
        "storage_name": ("VARCHAR(64)", False),
        "ciphertext_size": ("INTEGER", False),
        "encrypt_seconds": ("FLOAT", False),
    },
}


def test_the_tables_and_columns_match_the_data_model():
    inspector = inspect(db.engine)
    assert sorted(inspector.get_table_names()) == sorted(EXPECTED_COLUMNS)
    for table, expected in EXPECTED_COLUMNS.items():
        found = {
            column["name"]: (str(column["type"]), column["nullable"])
            for column in inspector.get_columns(table)
        }
        assert found == expected, table


def test_unique_rules_foreign_keys_and_indexes_match_the_data_model():
    inspector = inspect(db.engine)

    def uniques(table):
        return {
            frozenset(u["column_names"])
            for u in inspector.get_unique_constraints(table)
        }

    def indexes(table):
        return {
            tuple(i["column_names"])
            for i in inspector.get_indexes(table)
            if not i["name"].startswith("sqlite_")
        }

    def foreign_keys(table):
        return {
            (
                tuple(f["constrained_columns"]),
                f["referred_table"],
                tuple(f["referred_columns"]),
                f["options"].get("ondelete"),
            )
            for f in inspector.get_foreign_keys(table)
        }

    assert uniques("user") == {frozenset({"username"})}
    assert uniques("stored_file") == set()
    assert uniques("cipher_copy") == {
        frozenset({"file_id", "algorithm"}),
        frozenset({"storage_name"}),
    }
    assert foreign_keys("user") == set()
    assert foreign_keys("stored_file") == {
        (("owner_id",), "user", ("id",), "CASCADE")
    }
    assert foreign_keys("cipher_copy") == {
        (("file_id",), "stored_file", ("id",), "CASCADE")
    }
    assert indexes("stored_file") == {("owner_id",)}
    assert indexes("cipher_copy") == {("file_id",)}


# ------------------------------------------------------------- relationships


def test_relationships_can_be_followed_in_both_directions(
    make_user, make_file
):
    user = make_user("alice")
    first = make_file(user, filename="one.pdf")
    second = make_file(user, filename="two.pdf")
    db.session.expire_all()

    assert [f.original_filename for f in user.files] == ["one.pdf", "two.pdf"]
    assert first.owner is user and second.owner is user
    assert [c.algorithm for c in first.copies] == ["AES", "DES", "RC4"]
    assert all(copy.file is first for copy in first.copies)


# ------------------------------------------------------- database constraints


@pytest.mark.parametrize(
    "username",
    ["Alice", " alice", "alice ", ""],
    ids=["uppercase", "leading-space", "trailing-space", "empty"],
)
def test_database_refuses_a_username_that_is_not_normalised(username):
    assert_rejected(INSERT_USER, user_row(username=username))


def test_database_refuses_duplicate_usernames():
    execute(INSERT_USER, user_row(username="dup"))
    assert_rejected(INSERT_USER, user_row(username="dup"))


@pytest.mark.parametrize("column", ["username", "password_hash"])
def test_user_columns_are_required(column):
    assert_rejected(INSERT_USER, user_row(**{column: None}))


@pytest.mark.parametrize(
    "changes",
    [
        {"kind": "audio"},
        {"kind": "Document"},
        {"plaintext_size": -1},
        {"owner_id": None},
        {"owner_id": 9999},
        {"original_filename": None},
        {"content_type": None},
        {"plaintext_size": None},
        {"kind": None},
    ],
    ids=[
        "unknown-kind",
        "kind-case-sensitive",
        "negative-size",
        "no-owner",
        "owner-does-not-exist",
        "no-filename",
        "no-content-type",
        "no-size",
        "no-kind",
    ],
)
def test_database_refuses_invalid_files(make_user, changes):
    row = file_row(make_user().id)
    row.update(changes)
    assert_rejected(INSERT_FILE, row)


@pytest.mark.parametrize(
    "kind", ["personal_data", "id_card", "document", "video"]
)
def test_every_documented_kind_is_accepted(make_user, kind):
    owner = make_user()
    execute(INSERT_FILE, file_row(owner.id, kind=kind))
    execute(INSERT_FILE, file_row(owner.id, kind=kind, plaintext_size=0))
    assert count("stored_file") == 2


@pytest.fixture()
def saved_file(make_user):
    """A bare file row without copies, for the copy-constraint tests."""
    owner = make_user()
    execute(INSERT_FILE, file_row(owner.id))
    return db.session.execute(text("SELECT id FROM stored_file")).scalar()


@pytest.mark.parametrize(
    "changes",
    [
        {"algorithm": "BLOWFISH"},
        {"algorithm": "aes"},
        {"algorithm": "RC4", "mode": "CBC", "iv": None},
        {"algorithm": "RC4", "mode": None, "iv": b"\x01"},
        {"mode": None},
        {"iv": None},
        {"algorithm": "DES", "iv": None},
        {"ciphertext_size": -1},
        {"encrypt_seconds": -0.5},
        {"wrapped_key": None},
        {"storage_name": None},
        {"ciphertext_size": None},
        {"encrypt_seconds": None},
        {"file_id": None},
        {"file_id": 9999},
    ],
    ids=[
        "unknown-algorithm",
        "lowercase-algorithm",
        "rc4-with-mode",
        "rc4-with-iv",
        "aes-without-mode",
        "aes-without-iv",
        "des-without-iv",
        "negative-ciphertext-size",
        "negative-seconds",
        "no-wrapped-key",
        "no-storage-name",
        "no-ciphertext-size",
        "no-seconds",
        "no-file",
        "file-does-not-exist",
    ],
)
def test_database_refuses_invalid_copies(saved_file, changes):
    row = copy_row(saved_file)
    row.update(changes)
    assert_rejected(INSERT_COPY, row)


@pytest.mark.parametrize(
    "changes",
    [
        {"algorithm": "DES", "iv": b"\x02" * 8},
        {"algorithm": "RC4", "mode": None, "iv": None},
        {"mode": "CTR"},
        {"encrypt_seconds": 0.0, "ciphertext_size": 0},
    ],
    ids=["des-cbc", "rc4", "mode-is-not-restricted", "zero-values"],
)
def test_database_accepts_valid_copies(saved_file, changes):
    execute(INSERT_COPY, copy_row(saved_file, **changes))
    assert count("cipher_copy") == 1


def test_one_file_can_not_have_two_copies_with_the_same_algorithm(saved_file):
    execute(INSERT_COPY, copy_row(saved_file, storage_name="a" * 32))
    assert_rejected(INSERT_COPY, copy_row(saved_file, storage_name="b" * 32))


def test_two_copies_can_not_share_a_storage_name(saved_file):
    execute(INSERT_COPY, copy_row(saved_file))
    assert_rejected(
        INSERT_COPY,
        copy_row(saved_file, algorithm="DES", iv=b"\x02" * 8),
    )


def test_a_file_without_an_owner_can_not_be_committed(app):
    db.session.add(
        StoredFile(
            kind="video",
            original_filename="a",
            content_type="x",
            plaintext_size=1,
        )
    )
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


# ---------------------------------------------------------------- validators


@pytest.mark.parametrize(
    "given, expected",
    [
        ("Budi", "budi"),
        ("  BuDi  ", "budi"),
        ("budi_01", "budi_01"),
        ("ÄBC", "äbc"),
    ],
)
def test_username_is_stripped_and_lowercased(given, expected):
    assert User(username=given).username == expected


@pytest.mark.parametrize("given", ["\talice", "alice\n", "\r\nalice\t"])
def test_username_validator_also_strips_tabs_and_newlines(given):
    # The database CHECK only trims spaces (SQLite's trim()), so this part of
    # the rule lives in the Python validator.
    assert User(username=given).username == "alice"


def test_username_is_normalised_when_changed_later():
    user = User(username="x")
    user.username = " YY "
    assert user.username == "yy"


@pytest.mark.parametrize("bad", [123, b"abc", 1.5, ["a"]])
def test_username_must_be_text(bad):
    with pytest.raises(TypeError):
        User(username=bad)


def test_usernames_that_differ_only_by_case_collide(make_user):
    make_user("Budi")
    db.session.add(User(username=" BUDI", password_hash="h"))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


@pytest.mark.parametrize(
    "name", ["a" * 16, "Ab-9_" * 3 + "x", "z" * 64, "0123456789abcdef"]
)
def test_storage_name_accepts_random_looking_names(name):
    assert CipherCopy(storage_name=name).storage_name == name


@pytest.mark.parametrize(
    "name",
    [
        "a" * 15,
        "a" * 65,
        "a" * 15 + ".",
        "a" * 15 + "/",
        "../" + "a" * 16,
        "a" * 15 + "\\",
        "a" * 15 + " ",
        "a" * 16 + "\n",
        "a" * 15 + "\x00",
        "a" * 15 + "é",
        "",
    ],
    ids=[
        "too-short",
        "too-long",
        "dot",
        "slash",
        "parent-folder",
        "backslash",
        "space",
        "trailing-newline",
        "nul",
        "non-ascii",
        "empty",
    ],
)
def test_storage_name_rejects_anything_that_could_be_a_path(name):
    with pytest.raises(ValueError):
        CipherCopy(storage_name=name)


@pytest.mark.parametrize("bad", [b"a" * 16, 12345678901234567])
def test_storage_name_must_be_text(bad):
    with pytest.raises(TypeError):
        CipherCopy(storage_name=bad)


# --------------------------------------------------------------- the cascade


def test_deleting_a_user_deletes_their_files_and_copies(make_user, make_file):
    alice, bob = make_user("alice"), make_user("bob")
    make_file(alice)
    make_file(alice)
    make_file(bob)
    assert counts() == (2, 3, 9)

    db.session.delete(alice)
    db.session.commit()

    assert counts() == (1, 1, 3)  # only bob's data is left
    remaining = db.session.execute(text("SELECT owner_id FROM stored_file"))
    assert remaining.scalar() == bob.id


def test_the_database_itself_cascades_a_plain_sql_delete(
    make_user, make_file
):
    make_file(make_user("alice"))
    db.session.expunge_all()

    execute('DELETE FROM "user"', {})

    assert counts() == (0, 0, 0)


def test_deleting_a_file_deletes_its_copies(make_user, make_file):
    user = make_user()
    keep, drop = make_file(user), make_file(user)

    db.session.delete(drop)
    db.session.commit()

    assert counts() == (1, 1, 3)
    assert db.session.get(StoredFile, keep.id) is not None


def test_removing_a_copy_from_its_file_deletes_the_row(make_user, make_file):
    stored = make_file(make_user())
    stored.copies.remove(stored.copies[0])
    db.session.commit()
    assert count("cipher_copy") == 2


def test_removing_a_file_from_its_user_deletes_it_and_its_copies(
    make_user, make_file
):
    user = make_user()
    make_file(user)
    user.files.remove(user.files[0])
    db.session.commit()
    assert counts() == (1, 0, 0)


def test_deleting_a_user_does_not_load_or_touch_child_rows(
    make_user, make_file
):
    # passive_deletes: the database does the cascade, so the ORM sends a
    # single DELETE and never looks at the child tables.
    victim = make_user("victim")
    make_file(victim)
    victim_id = victim.id
    db.session.expunge_all()
    victim = db.session.get(User, victim_id)
    statements = []

    def record(conn, cursor, statement, parameters, context, many):
        statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        db.session.delete(victim)
        db.session.commit()
    finally:
        event.remove(db.engine, "before_cursor_execute", record)

    assert len(statements) == 1
    assert statements[0].lstrip().upper().startswith("DELETE FROM")
    assert "stored_file" not in statements[0]
    assert "cipher_copy" not in statements[0]


def test_cascade_only_works_because_foreign_keys_are_switched_on(
    make_user, make_file
):
    # The control for the tests above: with SQLite's default (foreign keys
    # OFF) the same delete leaves orphan rows behind. If app.db_pragmas stops
    # working, the cascade tests fail while this one keeps showing why.
    user = make_user()
    make_file(user)
    owner_id = user.id
    db.session.commit()
    db.session.remove()

    connection = db.engine.raw_connection()
    try:
        connection.execute("PRAGMA foreign_keys=OFF")
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        connection.execute('DELETE FROM "user" WHERE id = ?', (owner_id,))
        connection.commit()
        orphans = connection.execute(
            "SELECT COUNT(*) FROM stored_file"
        ).fetchone()[0]
    finally:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.close()

    assert orphans == 1


# ---------------------------------------------------- the foreign key pragma


def test_foreign_keys_are_on_for_the_session_connection(app):
    assert db.session.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_foreign_keys_are_on_for_every_connection_to_a_file_database(tmp_path):
    config = TestingConfig()
    config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "t.db")
    config.STORAGE_DIR = tmp_path / "storage"
    flask_app = create_app(config)
    with flask_app.app_context():
        db.create_all()
        engine = db.engine
        connections = [engine.connect() for _ in range(3)]
        try:
            values = [
                c.exec_driver_sql("PRAGMA foreign_keys").scalar()
                for c in connections
            ]
        finally:
            for connection in connections:
                connection.close()
            engine.dispose()
        with engine.connect() as fresh:  # a connection opened after dispose
            values.append(
                fresh.exec_driver_sql("PRAGMA foreign_keys").scalar()
            )
        engine.dispose()
    assert values == [1, 1, 1, 1]


def test_importing_app_models_alone_switches_foreign_keys_on():
    # A fresh interpreter, so nothing else has registered the listener.
    code = (
        f"import sys; sys.path.insert(0, {str(PROJECT_ROOT)!r})\n"
        "import app.models\n"
        "from sqlalchemy import event\n"
        "from sqlalchemy.engine import Engine\n"
        "pragmas = sys.modules.get('app.db_pragmas')\n"
        "ok = pragmas is not None and event.contains(\n"
        "    Engine, 'connect', pragmas.enable_sqlite_foreign_keys)\n"
        "print('registered' if ok else 'missing')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True
    )
    assert result.stdout.strip() == "registered", result.stderr


# --------------------------------------------------- secrets stay out of text


def test_repr_and_str_show_only_the_class_and_primary_key(
    make_user, make_file
):
    user = make_user("eve", password_hash="SENTINEL_HASH_xyz")
    stored = make_file(user, filename="SENTINEL_NAME.pdf")
    copy = stored.copies[0]
    copy.wrapped_key = b"SENTINEL_WRAPPED"
    copy.iv = b"SENTINEL_IV_12345"
    db.session.commit()

    for obj in (user, stored, copy):
        for shown in (repr(obj), str(obj), f"{obj!r}", repr([obj])):
            assert "SENTINEL" not in shown
            assert "WRAPPED" not in shown and "IV_12345" not in shown
        assert re.fullmatch(
            r"<(User|StoredFile|CipherCopy) \d+>", repr(obj)
        )


def test_database_errors_do_not_print_the_values_that_were_sent(make_user):
    make_user("eve", password_hash="SENTINEL_HASH_xyz")
    db.session.add(User(username="eve", password_hash="SENTINEL_HASH_xyz"))
    with pytest.raises(IntegrityError) as caught:
        db.session.commit()
    db.session.rollback()

    assert "UNIQUE constraint failed" in str(caught.value)  # still useful
    assert "SENTINEL_HASH_xyz" not in str(caught.value)
    assert "SENTINEL_HASH_xyz" not in repr(caught.value)


# ----------------------------------------------------------- the test set-up


def test_the_storage_folder_belongs_to_pytest_and_is_not_created(
    app, tmp_path
):
    storage = Path(app.config["STORAGE_DIR"])
    assert storage == tmp_path / "storage"
    assert not storage.exists()


def test_every_test_starts_with_empty_tables(app):
    assert counts() == (0, 0, 0)


def test_the_client_fixture_talks_to_the_app(client):
    # No routes exist yet; a 404 proves the request reached the app.
    assert client.get("/").status_code == 404
