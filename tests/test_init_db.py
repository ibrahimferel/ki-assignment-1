"""Tests for app/database.py (``init_db``) and the init_db.py command.

A throw-away "project folder" under ``tmp_path`` replaces ``BASE_DIR`` for
the path rules, so the real project folder is never touched.
"""

import os
import sqlite3
import stat

import pytest
from sqlalchemy.exc import OperationalError

import init_db as init_db_command
from app import create_app, database
from app.config import ConfigError, TestingConfig
from app.database import InitDbError, init_db
from app.extensions import db

TABLES = ["cipher_copy", "stored_file", "user"]
posix_only = pytest.mark.skipif(
    os.name != "posix", reason="owner-only folders need POSIX permissions"
)


@pytest.fixture()
def project(tmp_path, monkeypatch):
    """A fake project folder; ``database.BASE_DIR`` points at it."""
    root = (tmp_path / "project").resolve()
    (root / "app").mkdir(parents=True)
    monkeypatch.setattr(database, "BASE_DIR", root)
    return root


@pytest.fixture()
def make_app(tmp_path, project, request):
    """Return a function that builds an app with a file database."""

    def _make(storage=None):
        config = TestingConfig()
        config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(
            tmp_path / "data.db"
        )
        config.STORAGE_DIR = (
            storage if storage is not None else project / "instance" / "store"
        )
        flask_app = create_app(config)
        flask_app.instance_path = str(project / "instance")

        def close():
            with flask_app.app_context():
                db.session.remove()
                db.engine.dispose()

        request.addfinalizer(close)
        return flask_app

    return _make


def db_file(tmp_path):
    return tmp_path / "data.db"


def table_names(tmp_path):
    path = db_file(tmp_path)
    if not path.exists():
        return []
    con = sqlite3.connect(str(path))
    try:
        return sorted(
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        )
    finally:
        con.close()


def mode(path):
    return stat.S_IMODE(os.stat(str(path)).st_mode)


def run_sql(tmp_path, *statements):
    con = sqlite3.connect(str(db_file(tmp_path)))
    try:
        for statement in statements:
            con.execute(statement)
        con.commit()
    finally:
        con.close()


# ------------------------------------------------------------ the library


def test_first_run_creates_the_tables_and_the_folder(make_app, tmp_path):
    flask_app = make_app()

    report = init_db(flask_app)

    assert report.tables_created == tuple(TABLES)
    assert report.tables_existing == ()
    assert report.storage_created is True
    assert report.storage_tightened is False
    assert report.storage_dir.is_dir()
    assert table_names(tmp_path) == TABLES


@posix_only
def test_the_storage_folder_is_owner_only(make_app):
    report = init_db(make_app())
    assert mode(report.storage_dir) == 0o700


def test_running_again_changes_nothing_and_keeps_the_data(make_app, tmp_path):
    flask_app = make_app()
    init_db(flask_app)
    run_sql(
        tmp_path,
        'INSERT INTO "user" (username, password_hash, created_at) '
        "VALUES ('keepme', 'h', '2026-01-01 00:00:00')",
    )
    (init_db(flask_app).storage_dir / "blob").write_bytes(b"cipher")

    report = init_db(flask_app)

    assert report.tables_created == ()
    assert report.tables_existing == tuple(TABLES)
    assert report.storage_created is False
    assert (report.storage_dir / "blob").read_bytes() == b"cipher"
    con = sqlite3.connect(str(db_file(tmp_path)))
    try:
        rows = con.execute('SELECT username FROM "user"').fetchall()
    finally:
        con.close()
    assert rows == [("keepme",)]


def test_a_missing_table_is_recreated_and_the_rest_reported(
    make_app, tmp_path
):
    flask_app = make_app()
    init_db(flask_app)
    run_sql(tmp_path, "DROP TABLE cipher_copy")

    report = init_db(flask_app)

    assert report.tables_created == ("cipher_copy",)
    assert report.tables_existing == ("stored_file", "user")
    assert table_names(tmp_path) == TABLES


def test_an_unrelated_table_is_left_alone(make_app, tmp_path):
    flask_app = make_app()
    init_db(flask_app)
    run_sql(tmp_path, "CREATE TABLE unrelated (x INTEGER)")

    init_db(flask_app)

    assert "unrelated" in table_names(tmp_path)


@pytest.mark.parametrize(
    "damage",
    [
        'DROP TABLE "user"; CREATE TABLE "user" (id INTEGER PRIMARY KEY, '
        "name TEXT)",
        'ALTER TABLE "user" ADD COLUMN extra_col TEXT',
    ],
    ids=["different-columns", "extra-column"],
)
def test_a_table_with_other_columns_stops_the_command(
    make_app, tmp_path, damage
):
    flask_app = make_app()
    init_db(flask_app)
    con = sqlite3.connect(str(db_file(tmp_path)))
    try:
        con.executescript(damage)
    finally:
        con.close()
    before = db_file(tmp_path).read_bytes()

    with pytest.raises(InitDbError, match="'user'.*delete"):
        init_db(flask_app)

    assert db_file(tmp_path).read_bytes() == before  # nothing was changed


def test_the_error_for_a_changed_table_leaves_no_folder_behind(
    make_app, tmp_path, project
):
    run_sql(tmp_path, 'CREATE TABLE "user" (id INTEGER PRIMARY KEY)')
    with pytest.raises(InitDbError):
        init_db(make_app())
    assert not (project / "instance" / "store").exists()


def test_the_command_also_works_with_the_in_memory_test_database(
    tmp_path, project
):
    config = TestingConfig()
    config.STORAGE_DIR = tmp_path / "mem-store"
    flask_app = create_app(config)
    flask_app.instance_path = str(project / "instance")

    report = init_db(flask_app)

    assert report.tables_created == tuple(TABLES)
    assert report.storage_dir.is_dir()


def test_the_report_path_is_the_resolved_real_path(make_app, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "via"
    link.symlink_to(real, target_is_directory=True)

    report = init_db(make_app(storage=link / "vault"))

    assert report.storage_dir == real.resolve() / "vault"
    assert (real / "vault").is_dir()


def test_a_missing_expected_table_list_is_refused(make_app, monkeypatch):
    monkeypatch.setattr(database, "EXPECTED_TABLES", frozenset({"user"}))
    with pytest.raises(InitDbError, match="not registered as expected"):
        init_db(make_app())


def test_tables_that_were_not_created_are_detected(make_app, monkeypatch):
    monkeypatch.setattr(db, "create_all", lambda *a, **k: None)
    with pytest.raises(InitDbError, match="not created"):
        init_db(make_app())


# ------------------------------------------------ STORAGE_DIR is refused


def refuse_storage(make_app, tmp_path, storage, message):
    flask_app = make_app(storage=storage)
    with pytest.raises(InitDbError, match=message):
        init_db(flask_app)
    assert table_names(tmp_path) == []  # refused before any table
    assert not db_file(tmp_path).exists()


def test_a_folder_inside_app_is_refused(make_app, tmp_path, project):
    refuse_storage(make_app, tmp_path, project / "app" / "vault", "app/")


def test_the_app_folder_itself_is_refused(make_app, tmp_path, project):
    refuse_storage(make_app, tmp_path, project / "app", "app/")


def test_a_path_reaching_app_through_dotdot_is_refused(
    make_app, tmp_path, project
):
    sneaky = project / "instance" / ".." / "app" / "vault"
    refuse_storage(make_app, tmp_path, sneaky, "app/")


def test_a_symlink_pointing_into_app_is_refused(make_app, tmp_path, project):
    (project / "link").symlink_to(project / "app", target_is_directory=True)
    refuse_storage(make_app, tmp_path, project / "link" / "vault", "app/")


def test_the_project_folder_and_its_parents_are_refused(
    make_app, tmp_path, project
):
    refuse_storage(make_app, tmp_path, project, "project folder")
    refuse_storage(make_app, tmp_path, project.parent, "project folder")
    refuse_storage(make_app, tmp_path, project.anchor, "project folder")


def test_the_instance_folder_is_refused(make_app, tmp_path, project):
    refuse_storage(make_app, tmp_path, project / "instance", "instance")


def test_a_symlink_to_instance_is_refused_even_if_instance_is_named_oddly(
    make_app, tmp_path, project
):
    # flask_app.instance_path is reached through a symlink; the comparison
    # must still recognise that it is the same folder.
    link = tmp_path / "lk"
    link.symlink_to(project, target_is_directory=True)
    flask_app = make_app(storage=project / "instance")
    flask_app.instance_path = str(link / "instance")
    with pytest.raises(InitDbError, match="instance"):
        init_db(flask_app)


def test_a_file_is_refused(make_app, tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("x")
    refuse_storage(make_app, tmp_path, target, "file, not a folder")


def test_a_symbolic_link_as_the_folder_itself_is_refused(make_app, tmp_path):
    (tmp_path / "real").mkdir()
    (tmp_path / "ln").symlink_to(tmp_path / "real", target_is_directory=True)
    refuse_storage(make_app, tmp_path, tmp_path / "ln", "symbolic link")


def test_a_sibling_named_like_app_is_not_mistaken_for_it(
    make_app, project
):
    report = init_db(make_app(storage=project / "app2"))
    assert report.storage_dir == project / "app2"
    assert report.storage_created is True


# ------------------------------------------------------------ permissions


@posix_only
@pytest.mark.parametrize("umask", [0o000, 0o022, 0o077])
def test_a_new_folder_is_owner_only_whatever_the_umask(make_app, umask):
    old = os.umask(umask)
    try:
        report = init_db(make_app())
    finally:
        os.umask(old)
    assert mode(report.storage_dir) == 0o700


@posix_only
@pytest.mark.parametrize("loose", [0o755, 0o777, 0o500, 0o750])
def test_a_looser_existing_folder_is_tightened_and_reported(
    make_app, project, loose
):
    folder = project / "instance" / "store"
    folder.mkdir(parents=True)
    folder.chmod(loose)

    report = init_db(make_app())

    assert report.storage_created is False
    assert report.storage_tightened is True
    assert mode(folder) == 0o700


@posix_only
def test_an_owner_only_folder_is_left_as_it_is(make_app, project):
    folder = project / "instance" / "store"
    folder.mkdir(parents=True)
    folder.chmod(0o700)

    report = init_db(make_app())

    assert report.storage_tightened is False
    assert report.storage_created is False


@posix_only
@pytest.mark.parametrize("loose", [0o750, 0o755])
def test_a_chmod_that_has_no_effect_is_detected(
    make_app, project, monkeypatch, loose
):
    folder = project / "instance" / "store"
    folder.mkdir(parents=True)
    folder.chmod(loose)
    monkeypatch.setattr(database.os, "chmod", lambda *a, **k: None)
    with pytest.raises(InitDbError, match="owner-only"):
        init_db(make_app())


@posix_only
def test_a_folder_that_can_not_be_used_is_refused(make_app, monkeypatch):
    monkeypatch.setattr(database.os, "access", lambda *a, **k: False)
    with pytest.raises(InitDbError, match="owner-only"):
        init_db(make_app())


# --------------------------------------------------------- the command


def run_command(monkeypatch, flask_app, args=()):
    monkeypatch.setattr(init_db_command, "create_app", lambda: flask_app)
    return init_db_command.main(list(args))


def test_the_command_reports_what_it_did(make_app, monkeypatch, capsys):
    flask_app = make_app()

    assert run_command(monkeypatch, flask_app) == 0
    first = capsys.readouterr()
    assert run_command(monkeypatch, flask_app) == 0
    second = capsys.readouterr()

    assert first.err == "" and second.err == ""
    assert "Tables created: cipher_copy, stored_file, user" in first.out
    assert "Storage folder (created):" in first.out
    assert "Tables created" not in second.out
    assert (
        "Tables already present: cipher_copy, stored_file, user" in second.out
    )
    assert "Storage folder (already present):" in second.out


@posix_only
def test_the_command_says_when_it_tightened_a_folder(
    make_app, project, monkeypatch, capsys
):
    folder = project / "instance" / "store"
    folder.mkdir(parents=True)
    folder.chmod(0o755)

    assert run_command(monkeypatch, make_app()) == 0

    assert "permissions tightened to owner-only" in capsys.readouterr().out


def test_the_command_never_prints_the_database_url_or_keys(
    make_app, monkeypatch, capsys
):
    flask_app = make_app()
    run_command(monkeypatch, flask_app)
    run_command(monkeypatch, flask_app)
    shown = capsys.readouterr()
    text = shown.out + shown.err

    assert "sqlite:" not in text and "data.db" not in text
    assert flask_app.config["SECRET_KEY"] not in text
    assert flask_app.config["MASTER_KEY"].hex() not in text


def test_a_refused_folder_gives_one_short_message_and_exit_code_1(
    make_app, project, monkeypatch, capsys
):
    flask_app = make_app(storage=project / "app" / "vault")

    assert run_command(monkeypatch, flask_app) == 1

    shown = capsys.readouterr()
    assert shown.out == ""
    assert shown.err.startswith("Cannot initialise: STORAGE_DIR")
    assert "Traceback" not in shown.err


def test_an_invalid_configuration_exits_with_1_and_no_traceback(
    monkeypatch, capsys
):
    def broken():
        raise ConfigError("SECRET_KEY is missing.")

    monkeypatch.setattr(init_db_command, "create_app", broken)

    assert init_db_command.main([]) == 1

    shown = capsys.readouterr()
    assert shown.out == ""
    assert "invalid configuration" in shown.err
    assert "SECRET_KEY is missing." in shown.err
    assert "Traceback" not in shown.err


def test_a_file_system_error_exits_with_1_and_names_only_the_reason(
    monkeypatch, capsys
):
    def broken():
        raise PermissionError(13, "Permission denied", "/secret/path/x")

    monkeypatch.setattr(init_db_command, "create_app", broken)

    assert init_db_command.main([]) == 1

    shown = capsys.readouterr()
    assert shown.err == (
        "Cannot initialise: file system error (Permission denied).\n"
    )


def test_a_database_error_is_one_line_without_the_url(monkeypatch, capsys):
    def broken():
        raise OperationalError(
            "SELECT 1 FROM sqlite:///SENTINEL.db",
            {"password": "SENTINEL_SECRET"},
            sqlite3.OperationalError("unable to open database file"),
        )

    monkeypatch.setattr(init_db_command, "create_app", broken)

    assert init_db_command.main([]) == 1

    shown = capsys.readouterr()
    assert shown.err == (
        "Cannot initialise: database error "
        "(OperationalError: unable to open database file).\n"
    )
    assert "SENTINEL" not in shown.err + shown.out


def test_a_database_error_from_another_driver_names_only_the_class(
    monkeypatch, capsys
):
    def broken():
        raise OperationalError(
            "x", {}, RuntimeError("host=db password=hunter2")
        )

    monkeypatch.setattr(init_db_command, "create_app", broken)

    assert init_db_command.main([]) == 1

    shown = capsys.readouterr()
    assert shown.err == (
        "Cannot initialise: database error (OperationalError).\n"
    )


@pytest.mark.parametrize("args", [["--reset"], ["extra"], ["--port", "1"]])
def test_unknown_arguments_are_refused_before_anything_happens(
    make_app, tmp_path, monkeypatch, capsys, args
):
    flask_app = make_app()
    with pytest.raises(SystemExit) as caught:
        run_command(monkeypatch, flask_app, args)
    assert caught.value.code == 2
    assert not db_file(tmp_path).exists()
    assert "usage" in capsys.readouterr().err.lower()


def test_help_exits_cleanly_and_changes_nothing(
    make_app, tmp_path, monkeypatch, capsys
):
    with pytest.raises(SystemExit) as caught:
        run_command(monkeypatch, make_app(), ["--help"])
    assert caught.value.code == 0
    assert "usage" in capsys.readouterr().out.lower()
    assert not db_file(tmp_path).exists()
