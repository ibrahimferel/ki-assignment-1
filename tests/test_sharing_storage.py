"""Records of all kinds with three users, and the files behind them.

Uses the shared fixtures of ``tests/sharing_fixtures.py``. The disk tests
pin only what a RAW SQL delete does (the database removes rows and knows
nothing about files). They say nothing about the ORM or about what the app
does after a delete, so a delete flow that removes the files (an event
listener, a service) stays possible.
"""

from pathlib import Path

import pytest
from flask_login import login_user
from sqlalchemy import func, select, text
from werkzeug.exceptions import NotFound

from app.authz import get_owned_or_404, owned_select
from app.extensions import db
from app.models import (
    AccessRequest,
    CipherCopy,
    SharedCopy,
    StoredFile,
    User,
    UserKey,
)
from app.storage import disk, services as storage_services

KIND_IDS = ["personal", "id_card_png", "id_card_jpg", "document", "video"]


def count(model):
    return db.session.execute(
        select(func.count()).select_from(model)).scalar_one()


def on_disk(app):
    return {p.name for p in Path(app.config["STORAGE_DIR"]).iterdir()}


def share_everything(request, owner_records):
    """One shared copy file per record of B, for one request."""
    names = []
    for number, record in enumerate(owner_records):
        data = b"synthetic shared copy %d" % number
        name = disk.write_ciphertext(data)
        db.session.add(SharedCopy(
            request=request,
            file=db.session.get(StoredFile, record.id),
            nonce=b"n" * 12,
            storage_name=name,
            ciphertext_size=len(data),
        ))
        names.append(name)
    db.session.commit()
    return names


def raw_delete(sql, **params):
    """Delete through the connection: the database does the cascade."""
    db.session.commit()
    db.session.expunge_all()
    db.session.connection().execute(text(sql), params)
    db.session.commit()


# ------------------------------------------------- every kind, three users


@pytest.mark.parametrize("index", range(5), ids=KIND_IDS)
def test_a_record_of_any_kind_is_reachable_by_its_owner_only(
    app, trio, owner_records, index
):
    record = list(owner_records)[index]
    for party, allowed in ((trio.b, True), (trio.a, False), (trio.c, False)):
        with app.test_request_context("/"):
            login_user(party.user)
            if allowed:
                assert get_owned_or_404(StoredFile, record.id).id == record.id
            else:
                with pytest.raises(NotFound):
                    get_owned_or_404(StoredFile, record.id)


def test_each_user_lists_only_their_own_records(app, trio, owner_records):
    wanted = {party.id: [] for party in trio}
    wanted[trio.b.id] = sorted(r.id for r in owner_records)
    for party in trio:
        with app.test_request_context("/"):
            login_user(party.user)
            rows = db.session.execute(owned_select(StoredFile)).scalars()
            assert sorted(r.id for r in rows) == wanted[party.id]


def test_the_routes_give_every_kind_to_b_and_to_nobody_else(
    web, web_trio, web_owner_records, login_as
):
    clients = {}
    for party in web_trio:
        clients[party.username] = web.test_client()
        login_as(clients[party.username], party)
    owner, requester, third = (clients["owner-b"], clients["requester-a"],
                               clients["third-c"])
    listing = owner.get("/storage/").get_json()["items"]
    assert sorted(i["kind"] for i in listing) == sorted(
        r.kind for r in web_owner_records)
    assert requester.get("/storage/").get_json() == {"items": []}
    assert third.get("/storage/").get_json() == {"items": []}
    for record in web_owner_records:
        url = f"/storage/{record.id}/download/AES"
        got = owner.get(url)
        assert got.status_code == 200
        assert got.get_data() == record.plaintext
        for stranger in (requester, third):
            assert stranger.get(url).status_code == 404


# ------------------------------- what a RAW SQL delete leaves on the disk


@pytest.fixture()
def shared(app, trio, owner_records, make_request):
    """An approved request of A to B with a shared copy of every record."""
    request = make_request(trio.a, trio.b, status="approved")
    request_id = request.id
    names = share_everything(request, owner_records)
    return request_id, names


def test_a_raw_delete_of_the_owner_leaves_every_file(
    app, trio, owner_records, shared
):
    _, shared_names = shared
    record_names = {n for r in owner_records for n in r.storage_names}
    assert on_disk(app) == record_names | set(shared_names)
    assert (count(StoredFile), count(CipherCopy), count(SharedCopy),
            count(AccessRequest)) == (5, 15, 5, 1)

    raw_delete('DELETE FROM "user" WHERE id = :id', id=trio.b.id)

    assert count(User) == 2 and count(UserKey) == 2
    assert (count(StoredFile), count(CipherCopy), count(SharedCopy),
            count(AccessRequest)) == (0, 0, 0, 0)
    assert on_disk(app) == record_names | set(shared_names)


def test_a_raw_delete_of_a_record_leaves_its_files(
    app, trio, owner_records, shared
):
    _, shared_names = shared
    victim = owner_records.video
    before = on_disk(app)

    raw_delete("DELETE FROM stored_file WHERE id = :id", id=victim.id)

    assert count(StoredFile) == 4 and count(CipherCopy) == 12
    assert count(SharedCopy) == 4 and count(AccessRequest) == 1
    assert on_disk(app) == before
    assert set(victim.storage_names) <= on_disk(app)


def test_a_raw_delete_of_a_request_leaves_the_shared_files(
    app, trio, owner_records, shared
):
    request_id, shared_names = shared
    before = on_disk(app)

    raw_delete("DELETE FROM access_request WHERE id = :id", id=request_id)

    assert count(AccessRequest) == 0 and count(SharedCopy) == 0
    assert count(StoredFile) == 5 and count(CipherCopy) == 15
    assert on_disk(app) == before
    assert set(shared_names) <= on_disk(app)


# ------------------------- the recipe: collect the names, delete, then clean


def names_of_user(user_id):
    cipher = db.session.execute(
        select(CipherCopy.storage_name).join(StoredFile).where(
            StoredFile.owner_id == user_id)).scalars().all()
    shared = db.session.execute(
        select(SharedCopy.storage_name).join(AccessRequest).where(
            (AccessRequest.owner_id == user_id)
            | (AccessRequest.requester_id == user_id))).scalars().all()
    return cipher + shared


def names_of_file(file_id):
    cipher = db.session.execute(select(CipherCopy.storage_name).where(
        CipherCopy.file_id == file_id)).scalars().all()
    shared = db.session.execute(select(SharedCopy.storage_name).where(
        SharedCopy.file_id == file_id)).scalars().all()
    return cipher + shared


def names_of_request(request_id):
    return db.session.execute(select(SharedCopy.storage_name).where(
        SharedCopy.request_id == request_id)).scalars().all()


@pytest.mark.parametrize("what", ["user", "record", "request"])
def test_collect_the_names_before_the_delete_and_clean_after_the_commit(
    app, trio, owner_records, shared, what
):
    request_id, _ = shared
    before = on_disk(app)
    if what == "user":
        names = names_of_user(trio.b.id)
        target = trio.b.user
    elif what == "record":
        names = names_of_file(owner_records.document.id)
        target = db.session.get(StoredFile, owner_records.document.id)
    else:
        names = names_of_request(request_id)
        target = db.session.get(AccessRequest, request_id)
    assert names and set(names) <= before

    db.session.delete(target)
    db.session.commit()
    assert storage_services.cleanup_ciphertexts(names) == []

    assert on_disk(app) == before - set(names)
    # Every file that is still on disk is still named by a row.
    named = set(db.session.execute(
        select(CipherCopy.storage_name)).scalars()) | set(
        db.session.execute(select(SharedCopy.storage_name)).scalars())
    assert on_disk(app) == named


def test_the_recipe_for_a_user_leaves_an_empty_folder(
    app, trio, owner_records, shared
):
    names = names_of_user(trio.b.id)
    db.session.delete(trio.b.user)
    db.session.commit()
    assert storage_services.cleanup_ciphertexts(names) == []
    assert on_disk(app) == set()
