"""Tests for app/authz.py: data belongs to its owner and to nobody else.

Two users, a few files, and synthetic routes added to the TEST app only (the
real application has no file routes yet). The routes are written the way
docs/auth-integration.md tells the other team members to write theirs.
"""

import ast
import re
from pathlib import Path

import pytest
from argon2 import PasswordHasher
from flask import jsonify, request
from flask_login import current_user, login_required, login_user
from sqlalchemy import event, func, inspect, select
from sqlalchemy.orm import selectinload
from werkzeug.exceptions import NotFound, Unauthorized

from app import authz
from app.auth import services
from app.authz import MAX_ID, get_owned_or_404, owned_select
from app.extensions import db
from app.models import CipherCopy, StoredFile, User

GOOD = "correct horse battery"
OTHER_GOOD = "another long password"
TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


@pytest.fixture(autouse=True)
def cheap_hasher(monkeypatch):
    """Fast Argon2 for the whole module; a fresh dummy hash every test."""
    cheap = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    monkeypatch.setattr(services, "_HASHER", cheap)
    monkeypatch.setattr(services, "_dummy", None)


def make_file(owner_name, name="report.pdf", copies=("AES", "DES", "RC4")):
    """Save a file (with ciphertext copies) for a user; return its id."""
    owner = db.session.execute(
        select(User).where(User.username == owner_name)
    ).scalar_one()
    stored = StoredFile(
        owner=owner,
        kind="document",
        original_filename=name,
        content_type="application/pdf",
        plaintext_size=10,
        plaintext_sha256="0" * 64,
    )
    for algorithm in copies:
        block = algorithm != "RC4"
        stored.copies.append(
            CipherCopy(
                algorithm=algorithm,
                mode="CBC" if block else None,
                iv=b"\x01" * 8 if block else None,
                wrapped_key=b"w" * 60,
                storage_name=f"{owner_name}{name}{algorithm}".ljust(16, "x")
                .replace(".", "-")[:64],
                ciphertext_size=16,
                encrypt_seconds=0.001,
            )
        )
    db.session.add(stored)
    db.session.commit()
    return stored.id


@pytest.fixture()
def site(web):
    """The ``web`` app, two users with files, and synthetic file routes."""

    @web.get("/t/files/<int:file_id>")
    @login_required
    def t_show(file_id):
        stored = get_owned_or_404(
            StoredFile, file_id, options=(selectinload(StoredFile.copies),)
        )
        return jsonify(
            name=stored.original_filename,
            copies=[copy.algorithm for copy in stored.copies],
        )

    @web.get("/t/files")
    @login_required
    def t_list():
        rows = db.session.execute(owned_select(StoredFile)).scalars()
        return jsonify(names=[row.original_filename for row in rows])

    @web.post("/t/files")
    @login_required
    def t_create():
        stored = StoredFile(
            owner_id=current_user.id,  # never taken from the request
            kind="document",
            original_filename=request.form["name"],
            content_type="text/plain",
            plaintext_size=1,
            plaintext_sha256="0" * 64,
        )
        db.session.add(stored)
        db.session.commit()
        return jsonify(id=stored.id, owner_id=stored.owner_id), 201

    @web.post("/t/files/<int:file_id>/delete")
    @login_required
    def t_delete(file_id):
        stored = get_owned_or_404(StoredFile, file_id)
        db.session.delete(stored)
        db.session.commit()
        return jsonify(deleted=file_id)

    @web.get("/t/forgot/<int:file_id>")  # no @login_required on purpose
    def t_forgot(file_id):
        return get_owned_or_404(StoredFile, file_id).original_filename

    @web.get("/t/loaded/<int:file_id>")
    @login_required
    def t_loaded(file_id):
        kept = None  # the identity map only holds rows that are referenced
        try:
            kept = get_owned_or_404(StoredFile, file_id)
        except NotFound:
            pass
        loaded = [
            obj.id
            for obj in db.session.identity_map.values()
            if isinstance(obj, StoredFile)
        ]
        return jsonify(loaded=loaded, found=kept is not None)

    with web.app_context():
        for name, password in (("alice", GOOD), ("bobby", OTHER_GOOD)):
            services.register_user(name, password)
    return web


@pytest.fixture()
def ids(site):
    """The ids of the files: alice has two, bobby has one."""
    with site.app_context():
        return {
            "alice": make_file("alice", "alice-one.pdf"),
            "alice2": make_file("alice", "alice-two.pdf", ("AES",)),
            "bobby": make_file("bobby", "bobby-one.pdf"),
        }


def token_for(client):
    for path in ("/auth/login", "/"):
        found = TOKEN_PATTERN.search(client.get(path).get_data(as_text=True))
        if found:
            return found.group(1)
    raise AssertionError("no CSRF token")


def client_of(site, username=None, password=None):
    client = site.test_client()
    if username:
        response = client.post(
            "/auth/login",
            data={
                "csrf_token": token_for(client),
                "username": username,
                "password": password,
            },
        )
        assert response.status_code == 302
    return client


@pytest.fixture()
def alice(site, ids):
    return client_of(site, "alice", GOOD)


@pytest.fixture()
def bobby(site, ids):
    return client_of(site, "bobby", OTHER_GOOD)


def post(client, path, **data):
    data["csrf_token"] = token_for(client)
    return client.post(path, data=data)


def shape(response):
    return (
        response.status_code,
        response.get_data(),
        dict(response.headers),
    )


# ------------------------------------------------------ owner and the rest


def test_the_owner_gets_the_file_with_its_copies(alice, ids):
    response = alice.get(f"/t/files/{ids['alice']}")
    assert response.status_code == 200
    assert response.get_json() == {
        "name": "alice-one.pdf",
        "copies": ["AES", "DES", "RC4"],
    }


def test_another_user_gets_404_not_the_file(bobby, ids):
    response = bobby.get(f"/t/files/{ids['alice']}")
    assert response.status_code == 404
    assert b"alice" not in response.get_data()
    assert b"alice" not in str(response.headers).encode()


def test_each_user_still_reaches_their_own_file(alice, bobby, ids):
    assert alice.get(f"/t/files/{ids['alice2']}").status_code == 200
    assert bobby.get(f"/t/files/{ids['bobby']}").status_code == 200
    assert alice.get(f"/t/files/{ids['bobby']}").status_code == 404


def test_a_missing_id_is_404(alice):
    assert alice.get("/t/files/999").status_code == 404


def arabic_indic(number):
    return "".join(chr(0x660 + int(digit)) for digit in str(number))


UNREACHABLE_IDS = [
    "0",
    str(MAX_ID),  # the largest id SQLite can store, but nobody has it
    str(MAX_ID + 1),  # SQLite can not store this one
    "9" * 30,
    "-1",
    "00000000000000000000000000000000000000001x",
]


@pytest.mark.parametrize("raw", UNREACHABLE_IDS)
def test_odd_ids_answer_404_and_never_500(alice, raw):
    assert alice.get(f"/t/files/{raw}").status_code == 404


def test_the_answer_is_the_same_for_every_reason(alice, bobby, ids):
    answers = {
        "someone else's file": shape(bobby.get(f"/t/files/{ids['alice']}")),
        "no such id": shape(bobby.get("/t/files/4242")),
        "id zero": shape(bobby.get("/t/files/0")),
        "id above SQLite": shape(bobby.get(f"/t/files/{MAX_ID + 1}")),
        "30 digits": shape(bobby.get(f"/t/files/{'9' * 30}")),
        "negative (routing)": shape(bobby.get("/t/files/-1")),
        "unknown address": shape(bobby.get("/t/no-such-page")),
        "digit look-alike": shape(
            bobby.get(f"/t/files/{arabic_indic(ids['alice'])}")
        ),
    }
    reference = answers["unknown address"]
    assert reference[0] == 404
    for reason, answer in answers.items():
        assert answer == reference, reason


def test_deleting_is_answered_the_same_way_too(alice, bobby, ids):
    foreign = post(bobby, f"/t/files/{ids['alice']}/delete")
    missing = post(bobby, "/t/files/4242/delete")
    assert shape(foreign) == shape(missing)
    assert foreign.status_code == 404


# ------------------------------------------------------------ anonymous


def test_an_anonymous_visitor_gets_401_before_any_lookup(site, ids):
    statements = []

    def spy(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    with site.app_context():
        engine = db.engine
    event.listen(engine, "before_cursor_execute", spy)
    try:
        client = site.test_client()
        existing = client.get(f"/t/forgot/{ids['alice']}")
        missing = client.get("/t/forgot/4242")
        huge = client.get(f"/t/forgot/{MAX_ID + 1}")
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    assert existing.status_code == missing.status_code == 401
    assert huge.status_code == 401
    assert shape(existing) == shape(missing) == shape(huge)
    assert statements == []


def test_the_login_page_still_comes_first_for_login_required(site, ids):
    response = site.test_client().get(f"/t/files/{ids['alice']}")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/auth/login")


# ---------------------------------------------------- how the query is made


def test_the_owner_is_part_of_the_query(site, bobby, ids):
    seen = []

    def spy(conn, cursor, statement, parameters, context, executemany):
        if "FROM stored_file" in statement:
            seen.append((statement, parameters))

    with site.app_context():
        engine = db.engine
    event.listen(engine, "before_cursor_execute", spy)
    try:
        bobby.get(f"/t/files/{ids['alice']}")
    finally:
        event.remove(engine, "before_cursor_execute", spy)
    assert len(seen) == 1
    statement, parameters = seen[0]
    assert "stored_file.owner_id = ?" in statement
    assert "stored_file.id = ?" in statement
    bobby_id = 2
    assert sorted(parameters[:2]) == sorted([ids["alice"], bobby_id])


def test_someone_elses_row_is_never_loaded(bobby, alice, ids):
    foreign = bobby.get(f"/t/loaded/{ids['alice']}").get_json()
    own = bobby.get(f"/t/loaded/{ids['bobby']}").get_json()
    missing = alice.get("/t/loaded/4242").get_json()
    assert foreign == {"loaded": [], "found": False}
    assert own == {"loaded": [ids["bobby"]], "found": True}
    assert missing == {"loaded": [], "found": False}


# ----------------------------------------------- the argument types, direct


def as_user(site, username):
    """A request context in which ``username`` is logged in."""
    context = site.test_request_context()
    context.push()
    user = db.session.execute(
        select(User).where(User.username == username)
    ).scalar_one()
    login_user(user)
    return context


@pytest.fixture()
def alice_context(site, ids):
    context = as_user(site, "alice")
    yield ids
    db.session.remove()
    context.pop()


@pytest.mark.parametrize(
    "bad",
    [True, False, "1", b"1", None, 1.0, 1.5, [1], 0, -5, MAX_ID + 1, 10**30],
    ids=repr,
)
def test_an_id_that_is_not_a_plain_int_in_range_is_404(alice_context, bad):
    with pytest.raises(NotFound):
        get_owned_or_404(StoredFile, bad)


def test_a_real_id_works_and_returns_the_row(alice_context):
    found = get_owned_or_404(StoredFile, alice_context["alice"])
    assert found.original_filename == "alice-one.pdf"
    assert found.owner.username == "alice"


def add_file_with_id(site, owner_name, file_id):
    with site.app_context():
        owner = db.session.execute(
            select(User).where(User.username == owner_name)
        ).scalar_one()
        db.session.add(
            StoredFile(
                id=file_id,
                owner=owner,
                kind="document",
                original_filename=f"id-{file_id}.pdf",
                content_type="text/plain",
                plaintext_size=1,
                plaintext_sha256="0" * 64,
            )
        )
        db.session.commit()


def test_the_largest_storable_id_is_still_reachable(site, ids):
    add_file_with_id(site, "alice", MAX_ID)
    alice = client_of(site, "alice", GOOD)
    bobby = client_of(site, "bobby", OTHER_GOOD)
    assert alice.get(f"/t/files/{MAX_ID}").get_json()["name"] == (
        f"id-{MAX_ID}.pdf"
    )
    assert bobby.get(f"/t/files/{MAX_ID}").status_code == 404


def test_id_zero_is_never_served_even_if_a_row_has_it(site, ids):
    # Ids start at 1; the helper refuses 0 before it asks the database.
    add_file_with_id(site, "alice", 0)
    alice = client_of(site, "alice", GOOD)
    assert alice.get("/t/files/0").status_code == 404


def test_a_class_with_a_plain_owner_id_attribute_is_refused(alice_context):
    class Imitation:
        owner_id = 5

    with pytest.raises(TypeError, match="owner_id"):
        get_owned_or_404(Imitation, 1)
    with pytest.raises(TypeError, match="owner_id"):
        owned_select(Imitation)


@pytest.mark.parametrize("model", [User, CipherCopy, "StoredFile", None, 5])
def test_a_model_without_an_owner_column_is_a_programming_error(
    alice_context, model
):
    with pytest.raises(TypeError, match="owner_id"):
        get_owned_or_404(model, 1)
    with pytest.raises(TypeError, match="owner_id"):
        owned_select(model)


def test_anonymous_gets_401_from_both_helpers(site, ids):
    with site.test_request_context():
        with pytest.raises(Unauthorized):
            get_owned_or_404(StoredFile, ids["alice"])
        with pytest.raises(Unauthorized):
            owned_select(StoredFile)


def test_a_model_without_owner_is_a_programming_error_even_for_anonymous(
    site,
):
    with site.test_request_context():
        with pytest.raises(TypeError):
            get_owned_or_404(CipherCopy, 1)


def test_loader_options_are_used(alice_context):
    plain = get_owned_or_404(StoredFile, alice_context["alice"])
    assert "copies" in inspect(plain).unloaded
    db.session.expunge(plain)  # forget this row so it is read again
    eager = get_owned_or_404(
        StoredFile,
        alice_context["alice"],
        options=(selectinload(StoredFile.copies),),
    )
    assert "copies" not in inspect(eager).unloaded


def test_the_helper_does_not_accept_the_owner_or_extra_arguments(
    alice_context,
):
    with pytest.raises(TypeError):
        get_owned_or_404(StoredFile, alice_context["alice"], owner=2)
    with pytest.raises(TypeError):
        get_owned_or_404(StoredFile, alice_context["alice"], ())


# ------------------------------------------------------- list, create, delete


def test_a_list_shows_only_the_users_own_files(alice, bobby, ids):
    assert sorted(alice.get("/t/files").get_json()["names"]) == [
        "alice-one.pdf",
        "alice-two.pdf",
    ]
    assert bobby.get("/t/files").get_json() == {"names": ["bobby-one.pdf"]}


def test_a_new_user_sees_an_empty_list(site, ids):
    with site.app_context():
        services.register_user("carol", "yet another passphrase")
    carol = client_of(site, "carol", "yet another passphrase")
    assert carol.get("/t/files").get_json() == {"names": []}


def test_created_data_belongs_to_the_logged_in_user_only(site, bobby, ids):
    response = post(bobby, "/t/files", name="new.txt", owner_id="1")
    assert response.status_code == 201
    assert response.get_json()["owner_id"] == 2
    with site.app_context():
        owner = db.session.execute(
            select(StoredFile.owner_id).where(
                StoredFile.original_filename == "new.txt"
            )
        ).scalar_one()
    assert owner == 2


def test_another_user_can_not_delete_a_file(site, alice, bobby, ids):
    assert post(bobby, f"/t/files/{ids['alice']}/delete").status_code == 404
    with site.app_context():
        assert db.session.get(StoredFile, ids["alice"]) is not None
    assert alice.get(f"/t/files/{ids['alice']}").status_code == 200


def count(table):
    return db.session.execute(select(func.count()).select_from(table)).scalar()


def test_the_owner_deletes_and_the_copies_go_with_it(site, alice, ids):
    with site.app_context():
        before = count(CipherCopy)
    response = post(alice, f"/t/files/{ids['alice']}/delete")
    assert response.status_code == 200
    with site.app_context():
        assert db.session.get(StoredFile, ids["alice"]) is None
        assert count(CipherCopy) == before - 3
        assert db.session.get(StoredFile, ids["alice2"]) is not None
    assert post(alice, f"/t/files/{ids['alice']}/delete").status_code == 404
    assert alice.get(f"/t/files/{ids['alice']}").status_code == 404


def test_a_deleted_file_is_gone_for_the_other_user_too(bobby, alice, ids):
    post(alice, f"/t/files/{ids['alice']}/delete")
    assert shape(bobby.get(f"/t/files/{ids['alice']}")) == shape(
        bobby.get("/t/files/4242")
    )


# --------------------------------------------------------- the module itself


AUTHZ_TREE = ast.parse(Path(authz.__file__).read_text())


def test_authz_imports_only_what_it_needs():
    modules = set()
    for node in ast.walk(AUTHZ_TREE):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    assert modules == {
        "flask",
        "flask_login",
        "sqlalchemy",
        "sqlalchemy.orm.attributes",
        "app.extensions",
    }


def test_authz_never_reads_the_request_logs_or_prints():
    names = {
        node.id for node in ast.walk(AUTHZ_TREE) if isinstance(node, ast.Name)
    }
    attributes = {
        node.attr
        for node in ast.walk(AUTHZ_TREE)
        if isinstance(node, ast.Attribute)
    }
    assert not names & {"request", "session", "print", "logging", "logger"}
    assert not attributes & {"args", "form", "values", "headers", "json"}


def test_the_public_names_are_the_two_helpers():
    assert authz.__all__ == ["get_owned_or_404", "owned_select"]
    assert MAX_ID == 2**63 - 1
