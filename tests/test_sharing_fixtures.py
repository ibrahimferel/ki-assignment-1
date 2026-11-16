"""Tests of the shared A/B/C fixtures of ``tests/sharing_fixtures.py``."""

import base64
import hashlib
import json
import unicodedata
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from flask import has_app_context
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from Crypto.PublicKey import RSA

import sharing_fixtures
from app.auth import services
from app.auth.services import (
    KEY_PRESENT,
    authenticate,
    ensure_user_key,
    normalize_username,
    validate_password,
    verify_password,
)
from app.crypto import asymmetric
from app.extensions import db
from app.models import AccessRequest, CipherCopy, StoredFile, User, UserKey
from app.storage import disk, services as storage_services
from app.storage.validation import detect_content_type
from sharing_fixtures import Party, build_trio

PLAIN_MARKERS = (b"-----BEGIN PRIVATE KEY-----",
                 b"-----BEGIN RSA PRIVATE KEY-----")
ROLES = ["a", "b", "c"]
CHEAP = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)


def count(model):
    return db.session.execute(
        select(func.count()).select_from(model)).scalar_one()


def nfkc_bytes(password):
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def key_row(party):
    return db.session.get(UserKey, party.id)


def opens(private_pem, password):
    results = []
    try:
        serialization.load_pem_private_key(private_pem,
                                           nfkc_bytes(password))
        results.append(True)
    except ValueError:
        results.append(False)
    try:
        RSA.import_key(private_pem, passphrase=nfkc_bytes(password))
        results.append(True)
    except ValueError:
        results.append(False)
    return results


def variants(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return {value, value.hex().encode(), base64.b64encode(value),
            base64.urlsafe_b64encode(value)}


# ------------------------------------------------------------- the users


def test_the_three_users_are_saved_with_their_fixed_names(trio):
    assert [p.username for p in trio] == ["requester-a", "owner-b",
                                          "third-c"]
    assert len({p.id for p in trio}) == 3
    assert count(User) == 3 and count(UserKey) == 3
    for party in trio:
        assert party.user.username == party.username
    assert trio.a.user.id == trio.a.id


def test_the_usernames_and_passwords_follow_the_rules_of_the_app(trio):
    for party in trio:
        assert normalize_username(party.username) == party.username
        validate_password(party.password, party.username)
    assert len({p.password for p in trio}) == 3
    assert len({p.username for p in trio}) == 3


def test_every_user_has_exactly_one_key_row_of_the_documented_shape(trio):
    for party in trio:
        row = key_row(party)
        assert row is not None
        assert type(row.public_key_pem) is bytes
        assert type(row.encrypted_private_key) is bytes
        assert row.public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----")
        assert row.encrypted_private_key.startswith(
            b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
        assert not any(m in row.encrypted_private_key for m in PLAIN_MARKERS)
        assert party.user.key is row


def test_the_three_key_pairs_are_all_different(trio):
    rows = [key_row(p) for p in trio]
    assert len({r.public_key_pem for r in rows}) == 3
    assert len({r.encrypted_private_key for r in rows}) == 3


@pytest.mark.parametrize("role", ROLES)
def test_each_private_key_opens_with_its_own_password_only(trio, role):
    party = getattr(trio, role)
    row = key_row(party)
    assert opens(row.encrypted_private_key, party.password) == [True, True]
    for other in trio:
        if other is not party:
            assert opens(row.encrypted_private_key,
                         other.password) == [False, False]
    private = serialization.load_pem_private_key(
        row.encrypted_private_key, nfkc_bytes(party.password))
    public = serialization.load_pem_public_key(row.public_key_pem)
    assert private.public_key().public_numbers() == public.public_numbers()


def test_the_stored_blobs_hold_no_password_and_no_hash(trio):
    blob = b"".join(key_row(p).public_key_pem
                    + key_row(p).encrypted_private_key for p in trio)
    for party in trio:
        for variant in variants(party.password):
            assert variant not in blob
        for variant in variants(party.user.password_hash):
            assert variant not in blob


@pytest.mark.parametrize("role", ROLES)
def test_each_password_logs_in_and_the_others_do_not(trio, role):
    party = getattr(trio, role)
    assert verify_password(party.user.password_hash, party.password)
    assert authenticate(party.username, party.password) is party.user
    for other in trio:
        if other is not party:
            assert authenticate(party.username, other.password) is None


def test_ensure_user_key_finds_the_key_and_makes_no_new_one(
    trio, monkeypatch
):
    calls = []
    monkeypatch.setattr(services, "generate_user_keypair",
                        lambda password: calls.append(1))
    before = [key_row(p).encrypted_private_key for p in trio]
    for party in trio:
        assert ensure_user_key(party.user, party.password) == KEY_PRESENT
    assert calls == []
    db.session.expire_all()
    assert [key_row(p).encrypted_private_key for p in trio] == before


def test_the_hashes_are_cheap_but_the_real_hasher_is_back(app, make_trio):
    before = (services._HASHER, services._dummy)
    trio = make_trio()
    assert (services._HASHER, services._dummy) == before
    for party in trio:
        assert "$m=8,t=1,p=1$" in party.user.password_hash
        assert verify_password(party.user.password_hash, party.password)


def test_the_real_hasher_is_back_even_when_the_builder_fails(
    app, monkeypatch
):
    before = (services._HASHER, services._dummy)
    real = services.register_user
    calls = []

    def second_one_fails(name, password):
        calls.append(name)
        if len(calls) == 2:
            raise RuntimeError("synthetic failure")
        return real(name, password)

    monkeypatch.setattr(services, "register_user", second_one_fails)
    with pytest.raises(RuntimeError):
        build_trio()
    assert (services._HASHER, services._dummy) == before


# ------------------------------------------------------ the key pool rules


def test_three_users_in_a_row_differ_even_after_other_users(
    app, monkeypatch
):
    monkeypatch.setattr(services, "_HASHER", CHEAP)
    early = services.register_user("early-one", "an early long phrase 1")
    services.register_user("early-two", "an early long phrase 2")
    trio = build_trio()
    keys = {key_row(p).public_key_pem for p in trio}
    assert len(keys) == 3
    # The pool has only three keys: the early user shares one with the trio.
    assert early.key.public_key_pem in keys


def test_a_user_made_after_the_trio_repeats_the_key_of_a(trio, monkeypatch):
    monkeypatch.setattr(services, "_HASHER", CHEAP)
    extra = services.register_user("extra-user", "an extra long phrase 3")
    assert extra.key.public_key_pem == key_row(trio.a).public_key_pem
    assert extra.key.encrypted_private_key != key_row(
        trio.a).encrypted_private_key  # own password, own salt


def test_the_builder_refuses_users_that_share_a_key(app, monkeypatch):
    same = asymmetric._generate_rsa_key()
    monkeypatch.setattr(asymmetric, "_generate_rsa_key", lambda: same)
    with pytest.raises(RuntimeError) as caught:
        build_trio()
    assert "different key pairs" in str(caught.value)
    assert caught.value.__context__ is None


def test_the_users_have_different_keys_with_real_key_generation(
    app, real_keygen, rsa_key_pool
):
    pool_before = len(rsa_key_pool)
    trio = build_trio()
    assert len({key_row(p).public_key_pem for p in trio}) == 3
    assert len(rsa_key_pool) == pool_before  # the pool was not used


# ------------------------------------------------------ web (no context)


def test_web_trio_works_without_an_open_context(web, web_trio, login_as):
    assert not has_app_context()
    clients = []
    for party in web_trio:
        client = web.test_client()
        response = login_as(client, party)
        assert response.status_code == 302
        # A logged in user is sent away from the login page.
        assert client.get("/auth/login").status_code == 302
        clients.append(client)
    anonymous = web.test_client()
    assert anonymous.get("/auth/login").status_code == 200
    with web.app_context():
        assert count(User) == 3 and count(UserKey) == 3


def test_login_as_fails_clearly_and_never_shows_the_password(
    web, web_trio, login_as
):
    wrong = Party(web_trio.a.id, web_trio.a.username, "not the password 77")
    with pytest.raises(AssertionError) as caught:
        login_as(web.test_client(), wrong)
    text = str(caught.value)
    assert "requester-a" in text
    assert "not the password" not in text


def test_parties_show_no_password_in_their_repr(trio, owner_records):
    text = repr(trio) + repr(list(trio)) + repr(trio.a)
    for party in trio:
        assert party.password not in text
    assert str(trio.a.id) in text
    shown = repr(owner_records)
    for record in owner_records:
        assert record.plaintext not in shown.encode()


def test_parties_and_records_can_not_be_changed(trio, owner_records):
    with pytest.raises(AttributeError):
        trio.a.password = "changed"
    with pytest.raises(AttributeError):
        trio.b = trio.a
    with pytest.raises(AttributeError):
        owner_records.personal.kind = "video"


# -------------------------------------------------------- make_request


def test_make_request_saves_a_pending_request_by_default(trio, make_request):
    row = make_request(trio.a, trio.b)
    assert row.id is not None
    assert (row.requester_id, row.owner_id) == (trio.a.id, trio.b.id)
    assert row.status == "pending"
    assert row.reason == "Synthetic request for tests"
    assert row.key_package is None and row.wrapped_share_key is None
    assert row.decided_at is None and row.unlocked_at is None
    assert count(AccessRequest) == 1


def test_make_request_takes_a_party_a_user_or_an_id(trio, make_request):
    first = make_request(trio.a, trio.b, status="approved")
    second = make_request(trio.a.user, trio.b.user, status="rejected",
                          reason="because")
    third = make_request(trio.c.id, trio.a.id)
    assert [r.status for r in (first, second, third)] == [
        "approved", "rejected", "pending"]
    assert second.reason == "because"
    assert third.requester_id == trio.c.id


@pytest.mark.parametrize("bad", ["requester-a", None, True, 1.0, [1]],
                         ids=repr)
def test_make_request_refuses_something_that_is_not_a_user(
    trio, make_request, bad
):
    with pytest.raises(TypeError):
        make_request(bad, trio.b)
    with pytest.raises(TypeError):
        make_request(trio.a, bad)
    assert count(AccessRequest) == 0


def test_make_request_does_not_hide_the_database_rules(trio, make_request):
    make_request(trio.a, trio.b)
    with pytest.raises(IntegrityError):
        make_request(trio.a, trio.b)  # a second pending one
    db.session.rollback()
    with pytest.raises(IntegrityError):
        make_request(trio.a, trio.a)  # to oneself
    db.session.rollback()
    with pytest.raises(IntegrityError):
        make_request(trio.a, trio.c, status="done")
    db.session.rollback()
    assert count(AccessRequest) == 1
    make_request(trio.a, trio.b, status="approved")  # decided ones are fine
    assert count(AccessRequest) == 2


# ---------------------------------------------------------- B's records


def stored(record):
    return db.session.get(StoredFile, record.id)


def test_b_has_five_records_one_of_each_kind(trio, owner_records):
    records = list(owner_records)
    assert [r.kind for r in records] == [
        "personal_data", "id_card", "id_card", "document", "video"]
    assert [r.filename for r in records] == [
        "personal-data.json", "id-card.png", "photo.jpg", "document.pdf",
        "clip.mp4"]
    assert len({r.id for r in records}) == 5
    assert count(StoredFile) == 5
    for record in records:
        assert stored(record).owner_id == trio.b.id
        assert stored(record).kind == record.kind
    for other in (trio.a, trio.c):
        assert db.session.execute(select(func.count()).select_from(
            StoredFile).where(StoredFile.owner_id == other.id)
        ).scalar_one() == 0


def test_every_record_has_its_three_copies_and_their_files(
    app, trio, owner_records
):
    names = set()
    for record in owner_records:
        copies = stored(record).copies
        assert sorted(c.algorithm for c in copies) == ["AES", "DES", "RC4"]
        assert tuple(c.storage_name for c in copies) == record.storage_names
        names.update(record.storage_names)
    assert len(names) == 15 and count(CipherCopy) == 15
    on_disk = {p.name for p in Path(app.config["STORAGE_DIR"]).iterdir()}
    assert on_disk == names


def test_the_files_are_under_the_test_folder_and_nowhere_else(
    app, tmp_path, trio, owner_records
):
    storage = Path(app.config["STORAGE_DIR"]).resolve()
    assert storage.is_relative_to(tmp_path.resolve())
    project = Path(sharing_fixtures.__file__).resolve().parents[1]
    assert not storage.is_relative_to(project / "instance")
    for record in owner_records:
        for name in record.storage_names:
            assert disk.storage_path(name).parent == storage


@pytest.mark.parametrize("algorithm", ["AES", "DES", "RC4"])
def test_every_copy_decrypts_back_to_the_synthetic_data(
    trio, owner_records, algorithm
):
    for record in owner_records:
        plain = storage_services.decrypt_record(stored(record), algorithm)
        assert plain == record.plaintext
        assert hashlib.sha256(plain).hexdigest() == record.sha256
        assert stored(record).plaintext_sha256 == record.sha256
        assert stored(record).content_type == record.content_type


def test_the_ciphertext_files_do_not_hold_the_plaintext(
    trio, owner_records
):
    for record in owner_records:
        for name in record.storage_names:
            assert record.plaintext not in disk.read_ciphertext(name)


def test_the_synthetic_bytes_are_valid_for_the_upload_checks(owner_records):
    for record in owner_records:
        if record.kind == "personal_data":
            assert json.loads(record.plaintext)["nama"].startswith("Pemilik")
            continue
        extension = record.filename.rsplit(".", 1)[1]
        assert detect_content_type(record.plaintext,
                                   extension) == record.content_type


def test_web_owner_records_hold_the_same_facts(web, web_trio,
                                               web_owner_records):
    assert not has_app_context()
    with web.app_context():
        assert count(StoredFile) == 5 and count(CipherCopy) == 15
        names = {n for r in web_owner_records for n in r.storage_names}
        assert len(names) == 15
        for record in web_owner_records:
            row = db.session.get(StoredFile, record.id)
            assert row.owner_id == web_trio.b.id
            plain = storage_services.decrypt_record(row, "AES")
            assert plain == record.plaintext
        on_disk = {p.name for p in Path(web.config["STORAGE_DIR"]).iterdir()}
        assert on_disk == names


def test_the_fixtures_use_only_code_that_was_already_in_the_repository():
    import ast

    tree = ast.parse(Path(sharing_fixtures.__file__).read_text())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(a.name for a in node.names)
    assert {m for m in modules if m.startswith("app")} == {
        "app.auth", "app.extensions", "app.models", "app.storage",
        "app.storage.validation"}
