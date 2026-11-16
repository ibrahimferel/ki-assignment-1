"""Tests for the key pair that ``register_user`` makes (M1-CP4).

Most tests use the pool of real RSA keys from conftest.py (see the block
about "RSA keys for tests" there); the private key is still encrypted for
real with each user's own password. One test asks for ``real_keygen`` and
generates a fresh key.
"""

import base64
import re
import traceback
import unicodedata

import pytest
from argon2 import PasswordHasher
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import serialization
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.auth import services
from app.auth.services import (
    KeyGenerationError,
    PasswordPolicyError,
    UsernamePolicyError,
    UsernameTakenError,
    authenticate,
    register_user,
)
from app.crypto import CryptoError, asymmetric
from app.extensions import db
from app.models import User, UserKey

GOOD = "correct horse battery"
OTHER = "another long password"
UNICODE_TYPED = "Ｐässwörd-密碼-①"  # NFKC: Pässwörd-密碼-1
KEY_FAILED = "Could not create the account. Please try again."
TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')
PLAIN_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
)


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    """Fast Argon2 for the whole module; a fresh dummy hash every test."""
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


def count(model):
    statement = select(func.count()).select_from(model)
    return db.session.execute(statement).scalar_one()


def open_private(private_pem, password):
    return serialization.load_pem_private_key(
        private_pem, unicodedata.normalize("NFKC", password).encode("utf-8")
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


def failing_keygen(message="SECRET-DETAIL"):
    def fail(password):
        raise CryptoError(message)

    return fail


# --------------------------------------------------------- a normal signup


def test_registration_saves_one_user_key_for_the_new_user(app):
    user = register_user("alice", GOOD)
    assert count(User) == 1 and count(UserKey) == 1
    row = db.session.get(UserKey, user.id)
    assert row is not None and row.user_id == user.id
    assert user.key is row
    assert type(row.public_key_pem) is bytes
    assert type(row.encrypted_private_key) is bytes


def test_the_saved_private_key_opens_with_the_password(app):
    user = register_user("alice", GOOD)
    row = user.key
    private = open_private(row.encrypted_private_key, GOOD)
    public = serialization.load_pem_public_key(row.public_key_pem)
    assert private.public_key().public_numbers() == public.public_numbers()
    assert row.encrypted_private_key.startswith(
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----"
    )


def test_the_saved_blobs_hold_no_password_and_no_plain_marker(app):
    user = register_user("alice", GOOD)
    blob = user.key.public_key_pem + user.key.encrypted_private_key
    for marker in PLAIN_MARKERS:
        assert marker not in blob
    for variant in variants(GOOD):
        assert variant not in blob


def test_each_user_encrypts_the_private_key_with_their_own_password(app):
    alice = register_user("alice", GOOD)
    bobby = register_user("bobby", OTHER)
    assert open_private(alice.key.encrypted_private_key, GOOD)
    assert open_private(bobby.key.encrypted_private_key, OTHER)
    with pytest.raises(ValueError):
        open_private(alice.key.encrypted_private_key, OTHER)
    with pytest.raises(ValueError):
        open_private(bobby.key.encrypted_private_key, GOOD)


def test_the_password_is_normalized_the_same_way_as_at_login(app):
    register_user("alice", UNICODE_TYPED)
    user = authenticate("alice", UNICODE_TYPED)
    assert user is not None
    form = services._check_password_shape(UNICODE_TYPED)
    assert open_private(user.key.encrypted_private_key, form)
    # The same password typed in its NFKC form is the same password.
    assert authenticate("alice", form) is not None
    assert open_private(user.key.encrypted_private_key, form)


# ------------------------------------------ one transaction, no leftovers


def test_user_and_key_pair_go_into_one_commit(app, monkeypatch):
    commits = []
    real_commit = db.session.commit

    def spy():
        commits.append(sorted(type(o).__name__ for o in db.session.new))
        return real_commit()

    monkeypatch.setattr(db.session, "commit", spy)
    register_user("alice", GOOD)
    assert commits == [["User", "UserKey"]]


def test_a_failed_commit_leaves_neither_row(app, monkeypatch):
    def broken():
        raise IntegrityError("INSERT", {"password_hash": "x"}, Exception("x"))

    monkeypatch.setattr(db.session, "commit", broken)
    with pytest.raises(IntegrityError):
        register_user("alice", GOOD)
    monkeypatch.undo()
    assert count(User) == 0 and count(UserKey) == 0


def test_a_failing_key_pair_saves_no_user(app, monkeypatch):
    monkeypatch.setattr(services, "generate_user_keypair", failing_keygen())
    with pytest.raises(KeyGenerationError) as caught:
        register_user("alice", GOOD)
    error = caught.value
    assert error.code == "key_generation_failed"
    assert error.message == str(error) == KEY_FAILED
    assert error.__context__ is None and error.__cause__ is None
    assert "SECRET-DETAIL" not in trace_text(error)
    assert GOOD not in trace_text(error)
    assert count(User) == 0 and count(UserKey) == 0
    # The session is clean: the same signup works as soon as keys work.
    monkeypatch.undo()
    assert register_user("alice", GOOD).key is not None
    assert count(User) == 1 and count(UserKey) == 1


def test_a_failure_inside_the_real_generator_saves_no_user(app, monkeypatch):
    def broken():
        raise RuntimeError("SECRET-DETAIL")

    monkeypatch.setattr(asymmetric, "_generate_rsa_key", broken)
    with pytest.raises(KeyGenerationError) as caught:
        register_user("alice", GOOD)
    assert caught.value.__context__ is None
    assert "SECRET-DETAIL" not in trace_text(caught.value)
    assert count(User) == 0 and count(UserKey) == 0


def test_the_key_pair_is_made_before_the_database_is_touched(app, monkeypatch):
    seen = []
    real = services.generate_user_keypair

    def spy(password):
        seen.append((list(db.session.new), list(db.session.dirty)))
        return real(password)

    monkeypatch.setattr(services, "generate_user_keypair", spy)
    register_user("alice", GOOD)
    assert seen == [([], [])]


@pytest.mark.parametrize(
    ("username", "password", "error"),
    [
        ("alice", "short", PasswordPolicyError),
        ("alice", "password123", PasswordPolicyError),
        ("alicealice1", "alicealice1", PasswordPolicyError),
        ("a", GOOD, UsernamePolicyError),
        ("not valid!", GOOD, UsernamePolicyError),
    ],
)
def test_no_key_pair_is_made_for_input_that_fails_validation(
    username, password, error, app, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        services, "generate_user_keypair", lambda p: calls.append(1)
    )
    with pytest.raises(error):
        register_user(username, password)
    assert calls == []
    assert count(User) == 0 and count(UserKey) == 0


def test_a_taken_username_saves_no_second_key_pair(app):
    first = register_user("alice", GOOD)
    before = (first.key.public_key_pem, first.key.encrypted_private_key)
    with pytest.raises(UsernameTakenError) as caught:
        register_user("alice", OTHER)
    assert caught.value.__context__ is None
    db.session.expire_all()
    assert count(User) == 1 and count(UserKey) == 1
    row = db.session.get(UserKey, first.id)
    assert (row.public_key_pem, row.encrypted_private_key) == before


# ---------------------------------------------------------- no secret shown


def test_nothing_is_printed_or_logged_that_shows_a_secret(
    app, monkeypatch, capsys, caplog
):
    caplog.set_level(0)
    user = register_user("alice", GOOD)
    secrets_ = [GOOD, user.password_hash, user.key.encrypted_private_key]
    monkeypatch.setattr(services, "generate_user_keypair", failing_keygen())
    with pytest.raises(KeyGenerationError) as caught:
        register_user("bobby", OTHER)
    shown = capsys.readouterr()
    text = (
        shown.out + shown.err + caplog.text + trace_text(caught.value)
    ).encode()
    secrets_.append(OTHER)
    for secret in secrets_:
        for variant in variants(secret):
            assert variant not in text


# ------------------------------------------------ the pool of RSA keys (T5)


def test_the_first_three_users_get_different_keys_and_the_fourth_repeats(app):
    users = [
        register_user(name, GOOD)
        for name in ("alice", "bobby", "carol", "dave")
    ]
    publics = [u.key.public_key_pem for u in users]
    assert len(set(publics[:3])) == 3
    assert publics[3] == publics[0]


def test_the_pool_gives_three_different_real_keys_then_wraps(rsa_key_pool):
    keys = [asymmetric._generate_rsa_key() for _ in range(4)]
    assert len({k.n for k in keys[:3]}) == 3
    assert keys[3] is keys[0]
    assert rsa_key_pool[:3] == keys[:3]
    assert len(rsa_key_pool) == 3
    for key in keys[:3]:
        assert isinstance(key, RSA.RsaKey)
        assert key.has_private() and key.size_in_bits() == 3072


@pytest.mark.parametrize("attempt", [1, 2, 3])
def test_the_counter_starts_again_in_every_test(attempt, rsa_key_pool):
    first = asymmetric._generate_rsa_key()
    second = asymmetric._generate_rsa_key()
    assert first is rsa_key_pool[0]
    assert second is rsa_key_pool[1]


def test_the_pool_is_on_unless_real_keygen_is_requested():
    assert asymmetric._generate_rsa_key.__name__ == "next_key"


@pytest.mark.usefixtures("real_keygen")
def test_real_keygen_turns_the_pool_off():
    assert asymmetric._generate_rsa_key.__name__ == "_generate_rsa_key"


@pytest.mark.usefixtures("real_keygen")
def test_a_freshly_generated_key_works_end_to_end(app):
    user = register_user("alice", GOOD)
    row = user.key
    private = open_private(row.encrypted_private_key, GOOD)
    public = serialization.load_pem_public_key(row.public_key_pem)
    assert private.key_size == public.key_size == 3072
    assert private.public_key().public_numbers() == public.public_numbers()
    assert RSA.import_key(
        row.encrypted_private_key, passphrase=GOOD.encode("utf-8")
    ).size_in_bits() == 3072
    with pytest.raises(ValueError):
        open_private(row.encrypted_private_key, OTHER)


# ------------------------------------------------------------- the page


def token_from(browser, url):
    html = browser.get(url).get_data(as_text=True)
    found = TOKEN_PATTERN.search(html)
    assert found, "no CSRF token in the page"
    return found.group(1)


def post_register(browser, username, password):
    return browser.post(
        "/auth/register",
        data={
            "csrf_token": token_from(browser, "/auth/register"),
            "username": username,
            "password": password,
            "confirm": password,
        },
    )


def counts_in(web):
    with web.app_context():
        return count(User), count(UserKey)


def test_the_register_page_saves_the_key_pair(web, web_client):
    response = post_register(web_client, "alice", GOOD)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")
    assert counts_in(web) == (1, 1)


def test_the_register_page_shows_a_fixed_message_when_keys_fail(
    web, web_client, monkeypatch
):
    monkeypatch.setattr(services, "generate_user_keypair", failing_keygen())
    response = post_register(web_client, "alice", GOOD)
    body = response.get_data(as_text=True)
    assert response.status_code == 500
    assert KEY_FAILED in body
    assert "<form" in body
    assert "Traceback" not in body and "SECRET-DETAIL" not in body
    assert GOOD not in body
    assert response.headers["Cache-Control"] == "no-store"
    assert counts_in(web) == (0, 0)
    # Nothing is stuck: once key generation works, the signup works.
    monkeypatch.undo()
    assert post_register(web_client, "alice", GOOD).status_code == 302
    assert counts_in(web) == (1, 1)
