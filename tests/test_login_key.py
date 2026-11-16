"""Tests for ``ensure_user_key`` and the key pair made at login (M1-CP5).

An "old account" is one made before key pairs existed: a ``user`` row with a
password hash and no ``user_key`` row. The tests build them directly.

Most tests use the pool of real RSA keys from conftest.py; the private key is
still encrypted for real with each account's own password. The race tests
use a SQLite FILE (two connections can not share an in-memory database) and
real threads.
"""

import base64
import inspect
import logging
import re
import threading
import traceback
import unicodedata

import pytest
from argon2 import PasswordHasher
from flask_login import login_required
from cryptography.hazmat.primitives import serialization
from sqlalchemy import event, func, select
from sqlalchemy.exc import IntegrityError, OperationalError

from app import create_app
from app.auth import services
from app.auth.routes import LOGIN_FAILED
from app.auth.services import (
    KEY_CHECK_FAILED,
    KEY_CREATED,
    KEY_KEYGEN_FAILED,
    KEY_PRESENT,
    KEY_SAVE_FAILED,
    authenticate,
    ensure_user_key,
    register_user,
)
from app.auth.throttle import Decision
from app.config import TestingConfig
from app.crypto import CryptoError, asymmetric
from app.extensions import db
from app.models import User, UserKey

GOOD = "correct horse battery"
OTHER = "another long password"
TYPED = "Ｐässwörd-密碼-①"  # decomposed, full width, circled
NORMALIZED = "Pässwörd-密碼-1"  # its NFKC form
FULL_WIDTH = "ｆｕｌｌ－ｗｉｄｔｈ" \
    "－ｐａｓｓ１２"  # NFKC: full-width-pass12
LONG_DECOMPOSED = "ä" * 100  # 200 characters typed, 100 after NFKC
TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
VALUE_PATTERN = re.compile(r'value="[^"]*"')
PLAIN_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)
LOG_START = "Could not create the key pair of user"


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    """Fast Argon2 for the whole module; a fresh dummy hash every test."""
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


def old_account(name="oldie", password=GOOD):
    """Save a user with a password hash and NO key pair."""
    user = User(username=name, password_hash=services.hash_password(password))
    db.session.add(user)
    db.session.commit()
    return user


def count(model):
    statement = select(func.count()).select_from(model)
    return db.session.execute(statement).scalar_one()


def nfkc_bytes(password):
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def open_private(private_pem, password):
    return serialization.load_pem_private_key(
        private_pem, nfkc_bytes(password)
    )


def variants(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return {
        value,
        value.hex().encode(),
        value.hex().upper().encode(),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value),
    }


def trace_text(error):
    return "".join(
        traceback.format_exception(type(error), error, error.__traceback__)
    )


class CountingKeygen:
    """Wraps the real ``generate_user_keypair`` and counts the calls."""

    def __init__(self, monkeypatch):
        self.calls = 0
        self.real = services.generate_user_keypair
        monkeypatch.setattr(services, "generate_user_keypair", self)

    def __call__(self, password):
        self.calls += 1
        return self.real(password)


def failing_keygen(error=None):
    def fail(password):
        raise error if error is not None else CryptoError("SECRET-DETAIL")

    return fail


def locked(statement="INSERT"):
    return OperationalError(statement, {}, Exception("database is locked"))


# ------------------------------------------------ the happy paths (service)


def test_an_old_account_gets_a_key_pair_that_its_password_opens(app):
    user = old_account()
    assert count(UserKey) == 0
    assert ensure_user_key(user, GOOD) == KEY_CREATED
    assert count(UserKey) == 1
    row = db.session.get(UserKey, user.id)
    private = open_private(row.encrypted_private_key, GOOD)
    public = serialization.load_pem_public_key(row.public_key_pem)
    assert private.public_key().public_numbers() == public.public_numbers()
    assert type(row.public_key_pem) is bytes
    assert row.encrypted_private_key.startswith(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
    )
    with pytest.raises(ValueError):
        open_private(row.encrypted_private_key, OTHER)


def test_a_second_call_changes_nothing(app, monkeypatch):
    user = old_account()
    assert ensure_user_key(user, GOOD) == KEY_CREATED
    row = db.session.get(UserKey, user.id)
    before = (row.public_key_pem, row.encrypted_private_key, row.created_at)
    keygen = CountingKeygen(monkeypatch)
    assert ensure_user_key(user, GOOD) == KEY_PRESENT
    assert keygen.calls == 0
    db.session.expire_all()
    row = db.session.get(UserKey, user.id)
    assert (row.public_key_pem, row.encrypted_private_key, row.created_at) \
        == before
    assert count(UserKey) == 1


def test_an_account_from_register_user_is_left_alone(app, monkeypatch):
    user = register_user("alice", GOOD)
    before = (user.key.public_key_pem, user.key.encrypted_private_key)
    keygen = CountingKeygen(monkeypatch)
    assert ensure_user_key(user, GOOD) == KEY_PRESENT
    assert keygen.calls == 0
    db.session.expire_all()
    row = db.session.get(UserKey, user.id)
    assert (row.public_key_pem, row.encrypted_private_key) == before


def test_the_password_is_not_checked_again_when_the_key_exists(
    app, monkeypatch
):
    user = register_user("alice", GOOD)
    checks = []
    real = services.verify_password
    monkeypatch.setattr(
        services, "verify_password", lambda *a: checks.append(1) or real(*a)
    )
    assert ensure_user_key(user, OTHER) == KEY_PRESENT  # not even looked at
    assert checks == []


def test_two_old_accounts_get_two_different_keys(app):
    first, second = old_account("oldie"), old_account("oldtwo", OTHER)
    assert ensure_user_key(first, GOOD) == KEY_CREATED
    assert ensure_user_key(second, OTHER) == KEY_CREATED
    rows = db.session.execute(select(UserKey)).scalars().all()
    assert len({r.public_key_pem for r in rows}) == 2
    assert len({r.user_id for r in rows}) == 2


# ------------------------------- the password (NFKC, composed or not)


@pytest.mark.parametrize(
    ("hash_form", "call_form"),
    [
        (TYPED, TYPED),
        (TYPED, NORMALIZED),
        (NORMALIZED, TYPED),
        (NORMALIZED, NORMALIZED),
        (FULL_WIDTH, "full-width-pass12"),
        ("full-width-pass12", FULL_WIDTH),
        (LONG_DECOMPOSED, unicodedata.normalize("NFKC", LONG_DECOMPOSED)),
        (unicodedata.normalize("NFKC", LONG_DECOMPOSED), LONG_DECOMPOSED),
    ],
)
def test_any_equivalent_form_of_the_password_works_and_never_raises(
    hash_form, call_form, app
):
    user = old_account("oldie", hash_form)
    # The same form that logs in ...
    assert authenticate("oldie", call_form) is not None
    # ... is accepted here, and the key opens with the NFKC form.
    assert ensure_user_key(user, call_form) == KEY_CREATED
    row = db.session.get(UserKey, user.id)
    assert open_private(row.encrypted_private_key, call_form)
    assert open_private(row.encrypted_private_key, hash_form)


@pytest.mark.parametrize(
    "typed",
    [OTHER, GOOD + "x", "", GOOD[:-1], "x" * 1025, "a\nb" + GOOD, "\ud800"],
)
def test_a_password_that_does_not_log_in_is_refused_with_a_value_error(
    typed, app, monkeypatch
):
    user = old_account()
    assert authenticate("oldie", typed) is None
    keygen = CountingKeygen(monkeypatch)
    with pytest.raises(ValueError) as caught:
        ensure_user_key(user, typed)
    assert str(caught.value) == "password does not match this account"
    assert keygen.calls == 0 and count(UserKey) == 0
    assert "ud800" not in trace_text(caught.value)


def test_whatever_logs_in_never_makes_ensure_user_key_raise(app):
    forms = [GOOD, TYPED, NORMALIZED, FULL_WIDTH, LONG_DECOMPOSED, "x" * 10,
             "x" * 128, "é" * 128, "é" + "́" * 3 + "abcdefghi"]
    for number, form in enumerate(forms):
        user = old_account("user%d" % number, form)
        assert authenticate("user%d" % number, form) is not None
        assert ensure_user_key(user, form) == KEY_CREATED


# ------------------------------------------ authenticate is read-only


def test_authenticate_writes_nothing_to_the_session_or_database(app):
    old_account()
    statements = []

    def record(conn, cursor, statement, *rest):
        statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        assert authenticate("oldie", GOOD) is not None
        assert authenticate("oldie", OTHER) is None
        assert authenticate("nobody", GOOD) is None
    finally:
        event.remove(db.engine, "before_cursor_execute", record)
    assert statements
    assert all(s.lstrip().upper().startswith("SELECT") for s in statements)
    assert not (db.session.new or db.session.dirty or db.session.deleted)


def test_authenticate_has_no_write_or_rehash_in_its_source():
    source = inspect.getsource(services.authenticate)
    for word in ("commit", "flush", ".add(", "delete", "merge", "rehash",
                 "update("):
        assert word not in source
    assert "rehash" not in inspect.getsource(services)


def test_the_session_has_no_pending_work_when_ensure_runs(app, monkeypatch):
    user = authenticate_user = old_account()
    seen = []
    real = services.generate_user_keypair

    def spy(password):
        seen.append((list(db.session.new), list(db.session.dirty),
                     list(db.session.deleted)))
        return real(password)

    monkeypatch.setattr(services, "generate_user_keypair", spy)
    assert authenticate("oldie", GOOD) is authenticate_user
    assert ensure_user_key(user, GOOD) == KEY_CREATED
    assert seen == [([], [], [])]


# -------------------------------------------------------------- the failures


def test_a_key_pair_that_can_not_be_made_leaves_nothing_and_no_error(
    app, monkeypatch
):
    user = old_account()
    with monkeypatch.context() as patch:
        patch.setattr(services, "generate_user_keypair", failing_keygen())
        assert ensure_user_key(user, GOOD) == KEY_KEYGEN_FAILED
    assert count(UserKey) == 0 and count(User) == 1
    # Nothing is stuck: the next try works.
    assert ensure_user_key(user, GOOD) == KEY_CREATED
    assert count(UserKey) == 1


def test_a_failure_inside_the_real_generator_is_the_same_outcome(
    app, monkeypatch
):
    user = old_account()

    def broken():
        raise RuntimeError("SECRET-DETAIL")

    with monkeypatch.context() as patch:
        patch.setattr(asymmetric, "_generate_rsa_key", broken)
        assert ensure_user_key(user, GOOD) == KEY_KEYGEN_FAILED
    assert count(UserKey) == 0


@pytest.mark.parametrize(
    "error",
    [
        locked(),
        IntegrityError("INSERT", {}, Exception("some other constraint")),
    ],
)
def test_a_key_pair_that_can_not_be_saved_leaves_nothing_and_no_error(
    error, app, monkeypatch
):
    user = old_account()

    def broken():
        raise error

    with monkeypatch.context() as patch:
        patch.setattr(db.session, "commit", broken)
        assert ensure_user_key(user, GOOD) == KEY_SAVE_FAILED
    # The rolled back insert is gone, not just hidden.
    assert count(UserKey) == 0
    assert not (db.session.new or db.session.dirty)
    assert ensure_user_key(user, GOOD) == KEY_CREATED


def test_a_database_that_can_not_be_asked_first_is_a_check_failure(
    app, monkeypatch
):
    user = old_account()
    real_get = db.session.get

    def broken_get(entity, ident, *args, **kwargs):
        if entity is UserKey:
            raise locked("SELECT")
        return real_get(entity, ident, *args, **kwargs)

    keygen = CountingKeygen(monkeypatch)
    with monkeypatch.context() as patch:
        patch.setattr(db.session, "get", broken_get)
        assert ensure_user_key(user, GOOD) == KEY_CHECK_FAILED
    assert keygen.calls == 0 and count(UserKey) == 0
    assert ensure_user_key(user, GOOD) == KEY_CREATED


def test_the_session_is_rolled_back_after_a_failed_check(app, monkeypatch):
    user = old_account()
    real_get, real_rollback = db.session.get, db.session.rollback
    rollbacks = []

    def broken_get(entity, ident, *args, **kwargs):
        if entity is UserKey:
            raise locked("SELECT")
        return real_get(entity, ident, *args, **kwargs)

    def spy():
        rollbacks.append(1)
        real_rollback()

    with monkeypatch.context() as patch:
        patch.setattr(db.session, "get", broken_get)
        patch.setattr(db.session, "rollback", spy)
        assert ensure_user_key(user, GOOD) == KEY_CHECK_FAILED
    assert rollbacks == [1]  # the transaction is released, not left open


def test_register_user_does_not_call_ensure_user_key():
    # A new account already has its key pair; calling it again would only
    # cost a query and hide a bug in register_user.
    assert "ensure_user_key" not in inspect.getsource(register_user)


def test_asking_again_after_a_failed_save_can_fail_too(app, monkeypatch):
    user = old_account()
    real_get = db.session.get
    asked = []

    def flaky_get(entity, ident, *args, **kwargs):
        if entity is UserKey:
            asked.append(1)
            if len(asked) > 1:  # the first question works, the second fails
                raise locked("SELECT")
        return real_get(entity, ident, *args, **kwargs)

    def broken():
        raise locked()

    with monkeypatch.context() as patch:
        patch.setattr(db.session, "get", flaky_get)
        patch.setattr(db.session, "commit", broken)
        assert ensure_user_key(user, GOOD) == KEY_SAVE_FAILED
    assert count(UserKey) == 0


def test_a_failing_rollback_is_not_an_error_either(app, monkeypatch):
    user = old_account()

    def broken_commit():
        raise locked()

    real_rollback = db.session.rollback
    calls = []

    def broken_rollback():
        calls.append(1)
        real_rollback()
        raise locked("ROLLBACK")

    with monkeypatch.context() as patch:
        patch.setattr(db.session, "commit", broken_commit)
        patch.setattr(db.session, "rollback", broken_rollback)
        assert ensure_user_key(user, GOOD) == KEY_SAVE_FAILED
    assert calls  # the rollback was tried
    assert count(UserKey) == 0


def test_only_the_two_expected_error_types_are_caught(app, monkeypatch):
    user = old_account()
    with monkeypatch.context() as patch:
        patch.setattr(
            services, "generate_user_keypair",
            failing_keygen(RuntimeError("a bug")),
        )
        with pytest.raises(RuntimeError):
            ensure_user_key(user, GOOD)
    assert count(UserKey) == 0

    def broken():
        raise ZeroDivisionError("a bug")

    with monkeypatch.context() as patch:
        patch.setattr(db.session, "commit", broken)
        with pytest.raises(ZeroDivisionError):
            ensure_user_key(user, GOOD)


def test_wrong_argument_types_are_programming_errors(app):
    user = old_account()
    for bad_user in (None, "oldie", 1, object()):
        with pytest.raises(TypeError):
            ensure_user_key(bad_user, GOOD)
    for bad_password in (None, b"x" * 12, 123, ["x"]):
        with pytest.raises(TypeError):
            ensure_user_key(user, bad_password)
    with pytest.raises(ValueError):
        ensure_user_key(User(username="unsaved", password_hash="x"), GOOD)
    assert count(UserKey) == 0


def test_source_catches_only_crypto_and_sqlalchemy_errors():
    import ast

    tree = ast.parse(inspect.getsource(services))
    handlers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in (
            "ensure_user_key", "_has_key", "_rollback"
        ):
            for sub in ast.walk(node):
                if isinstance(sub, ast.ExceptHandler):
                    handlers.append(ast.unparse(sub.type)
                                    if sub.type is not None else None)
                if isinstance(sub, ast.Raise) and any(
                    isinstance(p, ast.ExceptHandler)
                    for p in ast.walk(node) if sub in list(ast.walk(p))
                ):
                    raise AssertionError("raise inside an except block")
    assert handlers
    assert set(handlers) <= {"CryptoError", "SQLAlchemyError"}


# ------------------------------------------------------------------ races


@pytest.fixture()
def file_app(tmp_path):
    """An app on a SQLite FILE, so that two connections see the same data."""
    config = TestingConfig()
    config.SQLALCHEMY_DATABASE_URI = "sqlite:///" + str(tmp_path / "race.db")
    config.STORAGE_DIR = tmp_path / "storage"
    flask_app = create_app(config)
    with flask_app.app_context():
        db.create_all()
    yield flask_app
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
        db.engine.dispose()


def test_losing_a_race_uses_the_key_that_won(file_app, monkeypatch):
    with file_app.app_context():
        user = old_account()
        real = services.generate_user_keypair
        winner = {}

        def racing(password):
            ours = real(password)
            # Another login finishes first, through its own connection.
            winner["pair"] = real(password)
            with db.engine.begin() as other:
                other.execute(UserKey.__table__.insert().values(
                    user_id=user.id,
                    public_key_pem=winner["pair"][0],
                    encrypted_private_key=winner["pair"][1],
                ))
            return ours

        monkeypatch.setattr(services, "generate_user_keypair", racing)
        assert ensure_user_key(user, GOOD) == KEY_PRESENT
        db.session.expire_all()
        assert count(UserKey) == 1
        row = db.session.get(UserKey, user.id)
        assert (row.public_key_pem, row.encrypted_private_key) \
            == winner["pair"]
        assert not (db.session.new or db.session.dirty)


def run_in_threads(file_app, work, number=2):
    failures, results = [], []

    def target():
        try:
            results.append(work())
        except Exception as error:  # noqa: BLE001 - reported below
            failures.append(repr(error))

    threads = [threading.Thread(target=target) for _ in range(number)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not any(t.is_alive() for t in threads)
    assert failures == []
    return results


def test_two_simultaneous_first_logins_make_exactly_one_key_pair(
    file_app, monkeypatch
):
    with file_app.app_context():
        old_account()
    barrier = threading.Barrier(2, timeout=60)
    real = services.generate_user_keypair

    def synced(password):
        pair = real(password)
        barrier.wait()  # both have a key pair, neither has saved it yet
        return pair

    monkeypatch.setattr(services, "generate_user_keypair", synced)

    def work():
        with file_app.app_context():
            user = db.session.execute(select(User)).scalar_one()
            return ensure_user_key(user, GOOD)

    results = run_in_threads(file_app, work)
    assert sorted(results) == [KEY_CREATED, KEY_PRESENT]
    with file_app.app_context():
        assert count(UserKey) == 1
        row = db.session.execute(select(UserKey)).scalar_one()
        assert open_private(row.encrypted_private_key, GOOD)


def test_two_simultaneous_logins_over_http_never_answer_500(
    file_app, monkeypatch, caplog
):
    with file_app.app_context():
        old_account()
    barrier = threading.Barrier(2, timeout=60)
    real = services.generate_user_keypair

    def synced(password):
        pair = real(password)
        barrier.wait()
        return pair

    monkeypatch.setattr(services, "generate_user_keypair", synced)

    def work():
        return post_login(file_app.test_client(), "oldie", GOOD).status_code

    assert run_in_threads(file_app, work) == [302, 302]
    with file_app.app_context():
        assert count(UserKey) == 1
    assert [r for r in caplog.records if LOG_START in r.getMessage()] == []


# ------------------------------------------------------------------ the page


def token_from(client, url):
    html = client.get(url).get_data(as_text=True)
    found = TOKEN_PATTERN.search(html)
    assert found, "no CSRF token in the page"
    return found.group(1)


def post_login(client, username, password):
    return client.post(
        "/auth/login",
        data={
            "csrf_token": token_from(client, "/auth/login"),
            "username": username,
            "password": password,
        },
    )


@pytest.fixture()
def site(web):
    @web.get("/protected")
    @login_required
    def protected():
        return "secret"

    return web


@pytest.fixture()
def browser(site):
    return site.test_client()


def is_logged_in(client):
    return client.get("/protected").status_code == 200


def add_old(site, name="oldie", password=GOOD):
    with site.app_context():
        return old_account(name, password).id


def key_rows(site):
    with site.app_context():
        return db.session.execute(select(UserKey)).scalars().all()


def key_logs(caplog):
    return [r.getMessage() for r in caplog.records
            if r.getMessage().startswith(LOG_START)]


def shape(response):
    body = VALUE_PATTERN.sub('value=""', response.get_data(as_text=True))
    return (response.status_code, body,
            response.headers.get("Cache-Control"))


def test_an_old_account_logs_in_and_its_key_pair_appears(site, browser):
    add_old(site)
    assert key_rows(site) == []
    response = post_login(browser, "oldie", GOOD)
    assert response.status_code == 302
    assert is_logged_in(browser)
    (row,) = key_rows(site)
    assert open_private(row.encrypted_private_key, GOOD)
    assert serialization.load_pem_public_key(row.public_key_pem)


def test_the_second_login_does_not_make_the_key_pair_again(
    site, browser, monkeypatch
):
    add_old(site)
    keygen = CountingKeygen(monkeypatch)
    assert post_login(browser, "oldie", GOOD).status_code == 302
    (first,) = key_rows(site)
    before = (first.public_key_pem, first.encrypted_private_key)
    again = site.test_client()
    assert post_login(again, "oldie", GOOD).status_code == 302
    (second,) = key_rows(site)
    assert (second.public_key_pem, second.encrypted_private_key) == before
    assert keygen.calls == 1


def test_a_new_account_is_not_processed_again_at_login(
    site, browser, monkeypatch
):
    with site.app_context():
        user = register_user("alice", GOOD)
        before = (user.key.public_key_pem, user.key.encrypted_private_key)
    keygen = CountingKeygen(monkeypatch)
    assert post_login(browser, "alice", GOOD).status_code == 302
    (row,) = key_rows(site)
    assert (row.public_key_pem, row.encrypted_private_key) == before
    assert keygen.calls == 0


def test_a_wrong_password_makes_no_key_pair(site, browser, monkeypatch):
    add_old(site)
    keygen = CountingKeygen(monkeypatch)
    ensured = []
    monkeypatch.setattr(
        "app.auth.routes.ensure_user_key", lambda *a: ensured.append(a)
    )
    response = post_login(browser, "oldie", OTHER)
    assert response.status_code == 200
    assert LOGIN_FAILED in response.get_data(as_text=True)
    assert not is_logged_in(browser)
    assert key_rows(site) == [] and keygen.calls == 0 and ensured == []


def test_a_failed_login_looks_the_same_for_every_reason(
    site, monkeypatch
):
    add_old(site)
    ensured = []
    monkeypatch.setattr(
        "app.auth.routes.ensure_user_key", lambda *a: ensured.append(a)
    )
    wrong = shape(post_login(site.test_client(), "oldie", OTHER))
    unknown = shape(post_login(site.test_client(), "nobody", OTHER))
    malformed = shape(post_login(site.test_client(), "no body!", OTHER))
    assert wrong == unknown == malformed
    assert ensured == [] and key_rows(site) == []


def test_a_failed_login_runs_no_statement_that_touches_user_key(
    site, monkeypatch
):
    add_old(site)
    statements = []

    def record(conn, cursor, statement, *rest):
        statements.append(statement)

    with site.app_context():
        event.listen(db.engine, "before_cursor_execute", record)
    try:
        post_login(site.test_client(), "oldie", OTHER)
        post_login(site.test_client(), "nobody", OTHER)
    finally:
        with site.app_context():
            event.remove(db.engine, "before_cursor_execute", record)
    assert statements
    assert not [s for s in statements if "user_key" in s.lower()]
    assert not [s for s in statements
                if s.lstrip().upper().startswith(("INSERT", "UPDATE",
                                                  "DELETE"))]


def test_a_blocked_login_never_reaches_the_key_pair(
    site, browser, monkeypatch
):
    add_old(site)
    ensured = []
    gate = site.extensions["throttle"]
    monkeypatch.setattr(gate, "acquire_login",
                        lambda *a: Decision(False, 30))
    monkeypatch.setattr(
        "app.auth.routes.ensure_user_key", lambda *a: ensured.append(a)
    )
    assert post_login(browser, "oldie", GOOD).status_code == 429
    assert ensured == [] and key_rows(site) == []


def test_the_key_pair_comes_after_the_password_check_and_before_login_user(
    site, browser, monkeypatch
):
    add_old(site)
    order = []
    gate = site.extensions["throttle"]
    real_auth, real_ok = services.authenticate, gate.login_succeeded
    real_ensure = services.ensure_user_key
    real_login_user = __import__("app.auth.routes", fromlist=["x"]).login_user

    def auth(*args):
        order.append("authenticate")
        return real_auth(*args)

    def succeeded(ticket):
        order.append("login_succeeded")
        return real_ok(ticket)

    def ensure(*args):
        order.append("ensure_user_key")
        return real_ensure(*args)

    def login_user(*args, **kwargs):
        order.append("login_user")
        return real_login_user(*args, **kwargs)

    monkeypatch.setattr("app.auth.routes.authenticate", auth)
    monkeypatch.setattr(gate, "login_succeeded", succeeded)
    monkeypatch.setattr("app.auth.routes.ensure_user_key", ensure)
    monkeypatch.setattr("app.auth.routes.login_user", login_user)
    assert post_login(browser, "oldie", GOOD).status_code == 302
    assert order == ["authenticate", "login_succeeded", "ensure_user_key",
                     "login_user"]


@pytest.mark.parametrize("typed", [TYPED, NORMALIZED])
def test_the_password_form_does_not_matter_at_login(site, typed):
    add_old(site, "oldie", TYPED)
    client = site.test_client()
    assert post_login(client, "oldie", typed).status_code == 302
    assert is_logged_in(client)
    (row,) = key_rows(site)
    assert open_private(row.encrypted_private_key, NORMALIZED)


def test_a_too_long_password_is_an_ordinary_failed_login(site, browser):
    add_old(site)
    response = post_login(browser, "oldie", "x" * 2000)
    assert response.status_code == 200
    assert LOGIN_FAILED in response.get_data(as_text=True)
    assert key_rows(site) == []


# -------------------------------------- failures at login: login still works


@pytest.mark.parametrize(
    ("reason", "outcome"),
    [
        ("keygen", KEY_KEYGEN_FAILED),
        ("save", KEY_SAVE_FAILED),
        ("check", KEY_CHECK_FAILED),
    ],
)
def test_a_failure_does_not_block_the_login_and_is_logged_and_retried(
    reason, outcome, site, browser, monkeypatch, caplog
):
    user_id = add_old(site)
    caplog.set_level(logging.WARNING)
    real_get = db.session.get

    def broken_get(entity, ident, *args, **kwargs):
        if entity is UserKey:
            raise locked("SELECT")
        return real_get(entity, ident, *args, **kwargs)

    def broken_commit():
        raise locked()

    with monkeypatch.context() as patch:
        if reason == "keygen":
            patch.setattr(services, "generate_user_keypair", failing_keygen())
        elif reason == "save":
            patch.setattr(db.session, "commit", broken_commit)
        else:
            patch.setattr(db.session, "get", broken_get)
        response = post_login(browser, "oldie", GOOD)
        assert response.status_code == 302
        assert is_logged_in(browser) if reason != "check" else True
    assert key_rows(site) == []
    expected = (
        "Could not create the key pair of user %d at login (%s); it will be "
        "tried again at the next login." % (user_id, outcome)
    )
    assert key_logs(caplog) == [expected]
    # The next login tries again, and works.
    again = site.test_client()
    assert post_login(again, "oldie", GOOD).status_code == 302
    assert is_logged_in(again)
    assert len(key_rows(site)) == 1


def test_a_login_that_works_logs_nothing_about_keys(
    site, browser, caplog
):
    add_old(site)
    caplog.set_level(logging.DEBUG)
    post_login(browser, "oldie", GOOD)
    assert key_logs(caplog) == []


# ----------------------------------------------------------------- secrets


def test_nothing_shows_a_password_a_hash_or_a_key(
    site, monkeypatch, caplog, capsys
):
    add_old(site, "oldie", GOOD)
    add_old(site, "oldtwo", OTHER)
    caplog.set_level(0)
    seen = []

    def go(name, password):
        client = site.test_client()
        response = post_login(client, name, password)
        seen.append(response.get_data() + str(response.headers).encode())
        return response

    go("oldie", GOOD)                      # works, key pair made
    with monkeypatch.context() as patch:   # fails, with an injected detail
        patch.setattr(services, "generate_user_keypair", failing_keygen())
        go("oldtwo", OTHER)
    go("oldtwo", OTHER)                    # works, key pair made
    go("oldie", OTHER)                     # wrong password
    shown = capsys.readouterr()
    text = b"\n".join(seen) + (
        shown.out + shown.err + caplog.text
    ).encode()
    with site.app_context():
        hashes = db.session.execute(select(User.password_hash)).scalars()
        secrets_ = [GOOD, OTHER, "SECRET-DETAIL", *hashes]
        for row in db.session.execute(select(UserKey)).scalars():
            body = re.sub(rb"-----[A-Z ]+-----|\s", b"",
                          row.encrypted_private_key)
            secrets_ += [body, base64.b64decode(body)]
    for secret in secrets_:
        for variant in variants(secret):
            assert variant not in text
    for marker in PLAIN_MARKERS:
        assert marker not in text
    assert b"$argon2" not in text


def test_the_stored_blobs_hold_no_password_and_no_plain_marker(app):
    user = old_account()
    assert ensure_user_key(user, GOOD) == KEY_CREATED
    row = db.session.get(UserKey, user.id)
    blob = row.public_key_pem + row.encrypted_private_key
    for marker in PLAIN_MARKERS:
        assert marker not in blob
    for variant in variants(GOOD):
        assert variant not in blob
