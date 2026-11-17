"""Contract 3 integration tests using real authentication, crypto and storage."""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select

from app import create_app
from app.config import TestingConfig
from app.crypto import (
    CryptoError,
    encode_key_package,
    encrypt_for_user,
    encrypt_shared,
    new_share_key,
    oaep_label,
    share_aad,
    unwrap_share_key,
)
from app.extensions import db
from app.models import AccessRequest, CipherCopy, SharedCopy, StoredFile, User, UserKey
from app.sharing import services
from app.storage.routes import INLINE_CSP
from sharing_fixtures import PERSONAL_PAYLOAD, TOKEN_PATTERN


class SharingAPI:
    def __init__(self, app, users, records, login_as):
        self.app, self.users, self.records = app, users, records
        self.clients, self.tokens = {}, {}
        for role in ("a", "b", "c"):
            client = app.test_client()
            login_as(client, getattr(users, role))
            token = TOKEN_PATTERN.search(client.get("/").get_data(as_text=True))
            assert token
            self.clients[role], self.tokens[role] = client, token.group(1)

    def post(self, role, path, payload=None):
        return self.clients[role].post(
            path, json=payload, headers={"X-CSRFToken": self.tokens[role]},
        )

    def create(self):
        response = self.post("a", "/sharing/requests", {
            "username": self.users.b.username, "reason": "Synthetic sharing test",
        })
        assert response.status_code == 201
        return response.get_json()["id"]

    def approve(self, request_id, file_ids=None):
        if file_ids is None:
            file_ids = [self.records.id_card_png.id, self.records.document.id]
        response = self.post("b", f"/sharing/requests/{request_id}/approve", {
            "file_ids": file_ids,
        })
        assert response.status_code == 200
        return response.get_json()["key_package"]

    def unlock(self, request_id, package, password=None, role="a"):
        return self.post(role, f"/sharing/requests/{request_id}/unlock", {
            "key_package": package,
            "password": self.users.a.password if password is None else password,
        })

    def paths(self):
        return set(Path(self.app.config["STORAGE_DIR"]).iterdir())


@pytest.fixture()
def api(web, web_trio, web_owner_records, login_as):
    return SharingAPI(web, web_trio, web_owner_records, login_as)


@pytest.fixture()
def approved(api):
    request_id = api.create()
    return api, request_id, api.approve(request_id)


def test_selected_files_only_and_owner_only_package(approved):
    api, request_id, package = approved
    response = api.unlock(request_id, package)
    assert response.status_code == 200
    payload = response.get_json()
    assert {f["id"] for f in payload["files"]} == {
        api.records.id_card_png.id, api.records.document.id,
    }
    deadline = datetime.fromisoformat(payload["unlocked_until"].replace("Z", "+00:00"))
    assert 0 < (deadline - datetime.now(timezone.utc)).total_seconds() <= 900
    for record in (api.records.id_card_png, api.records.document):
        path = f"/sharing/requests/{request_id}/files/{record.id}"
        response = api.clients["a"].get(path + "/download")
        assert response.status_code == 200
        assert response.data == record.plaintext
        assert response.headers["Content-Disposition"].startswith("attachment;")
        assert api.clients["c"].get(path + "/download").status_code == 404
        assert api.clients["b"].get(path + "/download").status_code == 404
        assert api.clients["a"].get(f"/storage/{record.id}/download/AES").status_code == 404
    image = api.clients["a"].get(
        f"/sharing/requests/{request_id}/files/{api.records.id_card_png.id}/view"
    )
    assert image.data == api.records.id_card_png.plaintext
    assert image.headers["Content-Security-Policy"] == INLINE_CSP
    assert image.headers["Cache-Control"] == "no-store"
    assert api.clients["a"].get(
        f"/sharing/requests/{request_id}/files/{api.records.personal.id}/download"
    ).status_code == 404
    path = f"/sharing/requests/{request_id}/key-package"
    assert api.clients["b"].get(path).get_json() == {"key_package": package}
    assert api.clients["a"].get(path).status_code == 404
    assert api.clients["c"].get(path).status_code == 404
    assert api.unlock(request_id, package, role="c").status_code == 404


def test_personal_json_and_non_image_view(api):
    request_id = api.create()
    package = api.approve(request_id, [api.records.personal.id, api.records.document.id])
    assert api.unlock(request_id, package).status_code == 200
    base = f"/sharing/requests/{request_id}/files"
    assert api.clients["a"].get(f"{base}/{api.records.personal.id}/personal").get_json() == PERSONAL_PAYLOAD
    assert api.clients["a"].get(f"{base}/{api.records.document.id}/personal").status_code == 404
    assert api.clients["a"].get(f"{base}/{api.records.document.id}/view").status_code == 404


def test_create_list_privacy_and_reject(api):
    request_id = api.create()
    outgoing = api.clients["a"].get("/sharing/requests").get_json()
    assert outgoing["incoming"] == []
    assert outgoing["outgoing"][0]["status"] == "pending"
    assert outgoing["outgoing"][0]["username"] == api.users.b.username
    assert not {"files", "size", "count", "key_package", "wrapped_share_key"} & outgoing["outgoing"][0].keys()
    assert api.clients["c"].get("/sharing/requests").get_json() == {"incoming": [], "outgoing": []}
    incoming = api.clients["b"].get("/sharing/requests").get_json()["incoming"]
    assert incoming[0]["id"] == request_id
    assert api.post("c", f"/sharing/requests/{request_id}/reject").status_code == 404
    response = api.post("b", f"/sharing/requests/{request_id}/reject")
    assert response.status_code == 204 and response.data == b""
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.status == "rejected" and row.decided_at is not None
    assert api.create() != request_id


@pytest.mark.parametrize("payload", [
    None, [], {}, {"username": 42, "reason": "test"},
    {"username": "owner-b", "reason": " "},
    {"username": "owner-b", "reason": "x" * 501},
])
def test_invalid_request_payload(api, payload):
    assert api.post("a", "/sharing/requests", payload).status_code == 400


def test_normalization_self_unknown_and_duplicate(api):
    response = api.post("a", "/sharing/requests", {
        "username": " " + api.users.b.username.upper() + " ", "reason": "x" * 500,
        "requester_id": api.users.c.id, "owner_id": api.users.c.id,
    })
    assert response.status_code == 201
    with api.app.app_context():
        row = db.session.get(AccessRequest, response.get_json()["id"])
        assert (row.requester_id, row.owner_id) == (api.users.a.id, api.users.b.id)
    for username, expected in ((api.users.a.username, 400), ("unknown-user", 404), (api.users.b.username, 400)):
        assert api.post("a", "/sharing/requests", {
            "username": username, "reason": "test",
        }).status_code == expected


@pytest.mark.parametrize("file_ids", [None, [], [True], [0], [2**63], ["1"], [1, 1]])
def test_invalid_file_selection(api, file_ids):
    request_id = api.create()
    assert api.post("b", f"/sharing/requests/{request_id}/approve", {"file_ids": file_ids}).status_code == 400


def test_approval_requires_owner_and_all_files_exist(api):
    request_id = api.create()
    path = f"/sharing/requests/{request_id}/approve"
    payload = {"file_ids": [api.records.document.id]}
    assert api.post("a", path, payload).status_code == 404
    assert api.post("c", path, payload).status_code == 404
    assert api.post("b", path, {"file_ids": [api.records.document.id, 2**63 - 1]}).status_code == 404
    api.approve(request_id)
    assert api.post("b", path, payload).status_code == 400


def test_wrong_password_throttling_and_csrf(approved):
    api, request_id, package = approved
    path = f"/sharing/requests/{request_id}/unlock"
    assert api.clients["a"].post(path, json={"key_package": package, "password": "wrong"}).status_code == 400
    for _ in range(5):
        assert api.unlock(request_id, package, password="wrong password").status_code == 422
    response = api.unlock(request_id, package, password="wrong password")
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1
    with api.app.app_context():
        assert db.session.get(AccessRequest, request_id).unlocked_at is None


def test_tampered_and_mismatched_packages(approved):
    api, request_id, package = approved
    tampered = package[:-1] + ("A" if package[-1] != "A" else "B")
    assert api.unlock(request_id, tampered).status_code == 422
    other_id = api.create()
    other_package = api.approve(other_id)
    assert api.unlock(request_id, other_package).status_code == 422
    assert api.unlock(other_id, package).status_code == 422
    assert api.unlock(request_id, package).status_code == 200


@pytest.mark.parametrize("field,delta", [
    ("decided_at", services.SHARE_TTL), ("unlocked_at", services.UNLOCK_TTL),
])
def test_expiry_checked_on_every_read(approved, field, delta):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    with api.app.app_context():
        setattr(db.session.get(AccessRequest, request_id), field, services._now() - delta)
        db.session.commit()
    path = f"/sharing/requests/{request_id}/files/{api.records.id_card_png.id}"
    assert api.clients["a"].get(path + "/download").status_code == 404
    assert api.clients["a"].get(path + "/view").status_code == 404
    assert api.unlock(request_id, package).status_code == (404 if field == "decided_at" else 200)


def test_revoke_persists_real_status_and_removes_files(approved):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    with api.app.app_context():
        names = list(db.session.scalars(select(SharedCopy.storage_name)))
    assert api.post("c", f"/sharing/requests/{request_id}/revoke").status_code == 404
    response = api.post("b", f"/sharing/requests/{request_id}/revoke")
    assert response.status_code == 204 and response.data == b""
    assert all(not (Path(api.app.config["STORAGE_DIR"]) / name).exists() for name in names)
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.status == "revoked"
        assert row.wrapped_share_key is row.key_package is row.unlocked_at is None
        assert db.session.scalars(select(SharedCopy)).all() == []
    assert api.clients["a"].get("/sharing/requests").get_json()["outgoing"][0]["status"] == "revoked"
    assert api.clients["a"].get(f"/sharing/requests/{request_id}/files/{api.records.document.id}/download").status_code == 404
    assert api.clients["b"].get(f"/sharing/requests/{request_id}/key-package").status_code == 404
    assert api.unlock(request_id, package).status_code == 404


def test_original_delete_removes_shared_blob_and_preserves_other_copy(approved):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    with api.app.app_context():
        copy = db.session.scalar(select(SharedCopy).where(SharedCopy.file_id == api.records.document.id))
        path = Path(api.app.config["STORAGE_DIR"]) / copy.storage_name
    assert api.post("b", f"/storage/{api.records.document.id}/delete").status_code == 204
    assert not path.exists()
    with api.app.app_context():
        assert db.session.scalar(select(SharedCopy).where(SharedCopy.file_id == api.records.document.id)) is None
    assert api.clients["a"].get(f"/sharing/requests/{request_id}/files/{api.records.document.id}/download").status_code == 404
    assert api.clients["a"].get(f"/sharing/requests/{request_id}/files/{api.records.id_card_png.id}/download").status_code == 200


@pytest.mark.parametrize("suffix", ["download", "view", "personal"])
def test_oversized_file_id_returns_404(approved, suffix):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    assert api.clients["a"].get(f"/sharing/requests/{request_id}/files/{2**63}/{suffix}").status_code == 404


@pytest.mark.parametrize("failure", ["write", "crypto", "commit"])
def test_failed_approval_rolls_back_and_cleans_new_files(api, monkeypatch, failure):
    request_id = api.create()
    before = api.paths()
    write = services.write_ciphertext
    calls = 0

    def fail_write(data):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic disk failure")
        return write(data)

    def fail_crypto(*args):
        raise CryptoError("synthetic crypto failure")

    def fail_commit():
        raise RuntimeError("synthetic commit failure")

    with monkeypatch.context() as patch:
        if failure == "write":
            patch.setattr(services, "write_ciphertext", fail_write)
        elif failure == "crypto":
            patch.setattr(services, "encrypt_for_user", fail_crypto)
        else:
            patch.setattr(db.session, "commit", fail_commit)
        path = f"/sharing/requests/{request_id}/approve"
        payload = {"file_ids": [api.records.document.id, api.records.id_card_png.id]}
        if failure == "crypto":
            assert api.post("b", path, payload).status_code == 422
        else:
            with pytest.raises((OSError, RuntimeError)):
                api.post("b", path, payload)
    assert api.paths() == before
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.status == "pending" and row.wrapped_share_key is row.key_package is None
        assert db.session.scalars(select(SharedCopy)).all() == []


@pytest.mark.parametrize("action", ["revoke", "delete"])
def test_failed_delete_or_revoke_preserves_access_and_files(approved, monkeypatch, action):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    before = api.paths()

    def fail_commit():
        raise RuntimeError("synthetic commit failure")

    path = (f"/sharing/requests/{request_id}/revoke" if action == "revoke"
            else f"/storage/{api.records.document.id}/delete")
    with monkeypatch.context() as patch:
        patch.setattr(db.session, "commit", fail_commit)
        with pytest.raises(RuntimeError):
            api.post("b", path)
    assert api.paths() == before
    assert api.clients["a"].get(f"/sharing/requests/{request_id}/files/{api.records.document.id}/download").status_code == 200


def test_limiter_is_app_local_bounded_and_expires(web, monkeypatch):
    with web.app_context():
        first = services._unlock_throttle()
    other = create_app(TestingConfig())
    with other.app_context():
        second = services._unlock_throttle()
    assert first is not second
    now = [0]
    monkeypatch.setattr(services.time, "monotonic", lambda: now[0])
    limiter = services.UnlockLimiter(limit=2, window=10, max_entries=2)
    assert limiter.acquire(1, 1) is None
    assert limiter.acquire(1, 1) is None
    assert limiter.acquire(1, 1) >= 1
    assert second.acquire(1, 1) is None
    now[0] = 10
    assert limiter.acquire(1, 1) is None
    for key in range(5):
        limiter.acquire(key, key)
    assert len(limiter._hits) <= 2


def test_tampered_shared_ciphertext_is_refused(approved):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    with api.app.app_context():
        copy = db.session.scalar(select(SharedCopy).where(SharedCopy.file_id == api.records.document.id))
        path = Path(api.app.config["STORAGE_DIR"]) / copy.storage_name
    body = path.read_bytes()
    path.write_bytes(bytes([body[0] ^ 1]) + body[1:])
    assert api.clients["a"].get(f"/sharing/requests/{request_id}/files/{api.records.document.id}/download").status_code == 422


CONTRACT_ENDPOINTS = [
    ("POST", "/sharing/requests"),
    ("GET", "/sharing/requests"),
    ("POST", "/sharing/requests/1/approve"),
    ("GET", "/sharing/requests/1/key-package"),
    ("POST", "/sharing/requests/1/reject"),
    ("POST", "/sharing/requests/1/revoke"),
    ("POST", "/sharing/requests/1/unlock"),
    ("GET", "/sharing/requests/1/files/1/download"),
    ("GET", "/sharing/requests/1/files/1/view"),
    ("GET", "/sharing/requests/1/files/1/personal"),
]


@pytest.mark.parametrize("method,path", CONTRACT_ENDPOINTS)
def test_every_contract_endpoint_requires_login(web, method, path):
    client = web.test_client()
    page = client.get("/auth/login").get_data(as_text=True)
    token = TOKEN_PATTERN.search(page).group(1)
    response = client.open(
        path, method=method, json={} if method == "POST" else None,
        headers={"X-CSRFToken": token},
    )
    assert response.status_code == 302
    assert urlsplit(response.headers["Location"]).path == "/auth/login"


@pytest.mark.parametrize("action", ["create", "approve", "reject", "revoke", "unlock"])
@pytest.mark.parametrize("token_kind", ["missing", "invalid", "other-session"])
def test_every_post_requires_own_session_csrf(approved, action, token_kind):
    api, request_id, package = approved
    path = ("/sharing/requests" if action == "create"
            else f"/sharing/requests/{request_id}/{action}")
    role = "a" if action in {"create", "unlock"} else "b"
    payload = {
        "username": api.users.b.username, "reason": "CSRF test",
        "file_ids": [api.records.document.id],
        "key_package": package, "password": api.users.a.password,
    }
    tokens = {"missing": None, "invalid": "wrong", "other-session": api.tokens["c"]}
    token = tokens[token_kind]
    headers = {} if token is None else {"X-CSRFToken": token}
    before = api.paths()
    response = api.clients[role].post(path, json=payload, headers=headers)
    assert response.status_code == 400
    assert b"CSRF" in response.data
    assert api.paths() == before
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.status == "approved" and row.unlocked_at is None


@pytest.mark.parametrize("action,role", [
    (action, role)
    for action in ("approve", "reject", "revoke", "key-package")
    for role in ("a", "c")
] + [
    (action, role)
    for action in ("unlock", "download", "view", "personal")
    for role in ("b", "c")
])
def test_other_users_and_nonexistent_requests_are_indistinguishable(approved, action, role):
    api, request_id, package = approved
    assert api.unlock(request_id, package).status_code == 200
    payload = {"file_ids": [api.records.document.id], "key_package": package,
               "password": api.users.a.password}

    def call(target_id):
        if action in {"download", "view", "personal"}:
            return api.clients[role].get(
                f"/sharing/requests/{target_id}/files/{api.records.document.id}/{action}"
            )
        path = f"/sharing/requests/{target_id}/{action}"
        if action == "key-package":
            return api.clients[role].get(path)
        return api.post(role, path, payload)

    other, missing = call(request_id), call(2**63 - 1)
    assert other.status_code == missing.status_code == 404
    assert other.data == missing.data
    assert other.content_type == missing.content_type


@pytest.mark.parametrize("state", [
    "pending", "approved-locked", "rejected", "revoked", "share-expired", "unlock-expired",
])
def test_all_content_endpoints_enforce_state_and_unlock(api, state):
    request_id = api.create()
    records = [api.records.document, api.records.id_card_png, api.records.personal]
    if state == "rejected":
        assert api.post("b", f"/sharing/requests/{request_id}/reject").status_code == 204
    elif state != "pending":
        package = api.approve(request_id, [record.id for record in records])
        if state != "approved-locked":
            assert api.unlock(request_id, package).status_code == 200
        if state == "revoked":
            assert api.post("b", f"/sharing/requests/{request_id}/revoke").status_code == 204
        elif state.endswith("expired"):
            field, duration = (("decided_at", services.SHARE_TTL) if state == "share-expired"
                               else ("unlocked_at", services.UNLOCK_TTL))
            with api.app.app_context():
                setattr(db.session.get(AccessRequest, request_id), field, services._now() - duration)
                db.session.commit()
    for record, suffix in zip(records, ("download", "view", "personal")):
        path = f"/sharing/requests/{request_id}/files/{record.id}/{suffix}"
        assert api.clients["a"].get(path).status_code == 404
    if state in {"pending", "rejected", "revoked", "share-expired"}:
        assert api.unlock(request_id, "not a valid package").status_code == 404


def test_owner_approves_exactly_two_of_three_records(api):
    for record in (api.records.id_card_jpg, api.records.video):
        assert api.post("b", f"/storage/{record.id}/delete").status_code == 204
    assert len(api.clients["b"].get("/storage/").get_json()["items"]) == 3
    request_id = api.create()
    package = api.approve(request_id)
    response = api.unlock(request_id, package)
    assert response.status_code == 200
    assert {file["id"] for file in response.get_json()["files"]} == {
        api.records.document.id, api.records.id_card_png.id,
    }
    assert api.clients["a"].get(
        f"/sharing/requests/{request_id}/files/{api.records.personal.id}/personal"
    ).status_code == 404


@pytest.mark.parametrize("name,mimetype", [
    ("id_card_png", "image/png"), ("id_card_jpg", "image/jpeg"),
])
def test_inline_image_format_and_sandbox(api, name, mimetype):
    record = getattr(api.records, name)
    request_id = api.create()
    package = api.approve(request_id, [record.id])
    assert api.unlock(request_id, package).status_code == 200
    response = api.clients["a"].get(f"/sharing/requests/{request_id}/files/{record.id}/view")
    assert response.status_code == 200 and response.data == record.plaintext
    assert response.mimetype == mimetype
    assert response.headers["Content-Security-Policy"] == INLINE_CSP
    assert not response.headers.get("Content-Disposition", "").startswith("attachment")


@pytest.mark.parametrize("record_name,suffix", [
    ("document", "download"), ("id_card_png", "view"), ("personal", "personal"),
])
def test_missing_shared_blob_never_falls_back_to_original(api, record_name, suffix):
    record = getattr(api.records, record_name)
    request_id = api.create()
    package = api.approve(request_id, [record.id])
    assert api.unlock(request_id, package).status_code == 200
    with api.app.app_context():
        copy = db.session.scalar(select(SharedCopy).where(SharedCopy.request_id == request_id))
        path = Path(api.app.config["STORAGE_DIR"]) / copy.storage_name
    path.unlink()
    response = api.clients["a"].get(f"/sharing/requests/{request_id}/files/{record.id}/{suffix}")
    assert response.status_code == 404
    assert api.clients["b"].get(f"/storage/{record.id}/download/AES").data == record.plaintext


@pytest.mark.parametrize("forgery", ["wrong-key", "wrong-recipient", "wrong-label"])
def test_valid_rsa_package_must_match_requester_label_and_stored_key(approved, forgery):
    api, request_id, _ = approved
    with api.app.app_context():
        user_id = api.users.c.id if forgery == "wrong-recipient" else api.users.a.id
        public_pem = db.session.get(UserKey, user_id).public_key_pem
    label_id = request_id + 1 if forgery == "wrong-label" else request_id
    forged = encode_key_package(
        request_id, encrypt_for_user(public_pem, new_share_key(), oaep_label(label_id)),
    )
    response = api.unlock(request_id, forged)
    assert response.status_code == 422
    with api.app.app_context():
        assert db.session.get(AccessRequest, request_id).unlocked_at is None


def test_approval_cannot_include_another_owners_file(api):
    request_id = api.create()
    with api.app.app_context():
        foreign_file = db.session.get(StoredFile, api.records.video.id)
        foreign_file.owner_id = api.users.c.id
        db.session.commit()
    before = api.paths()
    response = api.post("b", f"/sharing/requests/{request_id}/approve", {
        "file_ids": [api.records.document.id, api.records.video.id],
    })
    assert response.status_code == 404 and api.paths() == before
    with api.app.app_context():
        assert db.session.get(AccessRequest, request_id).status == "pending"
        assert db.session.scalars(select(SharedCopy)).all() == []


@pytest.mark.parametrize("phase", ["approve", "unlock"])
def test_missing_requester_key_is_refused_without_partial_changes(api, phase):
    request_id = api.create()
    package = api.approve(request_id) if phase == "unlock" else None
    before = api.paths()
    with api.app.app_context():
        db.session.delete(db.session.get(UserKey, api.users.a.id))
        db.session.commit()
    if phase == "approve":
        response = api.post("b", f"/sharing/requests/{request_id}/approve", {
            "file_ids": [api.records.document.id],
        })
        assert response.status_code == 400
    else:
        assert api.unlock(request_id, package).status_code == 422
    assert api.paths() == before
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.unlocked_at is None
        if phase == "approve":
            assert row.status == "pending" and row.wrapped_share_key is None


@pytest.mark.parametrize("payload", [None, [], {}, {"key_package": 42, "password": "x"},
    {"key_package": "x", "password": None}, {"key_package": "x" * 2049, "password": "x"},
    {"key_package": "x", "password": "x" * 1025},
])
def test_invalid_unlock_body_returns_400(approved, payload):
    api, request_id, _ = approved
    assert api.post("a", f"/sharing/requests/{request_id}/unlock", payload).status_code == 400


@pytest.mark.parametrize("action,role", [("create", "a"), ("approve", "b"), ("unlock", "a")])
@pytest.mark.parametrize("body,mimetype", [("{", "application/json"), ("username=test", "application/x-www-form-urlencoded")])
def test_malformed_or_non_json_body_is_rejected(approved, action, role, body, mimetype):
    api, request_id, _ = approved
    path = ("/sharing/requests" if action == "create"
            else f"/sharing/requests/{request_id}/{action}")
    response = api.clients[role].post(path, data=body, content_type=mimetype,
                                     headers={"X-CSRFToken": api.tokens[role]})
    assert response.status_code == 400


def test_original_integrity_failure_rolls_back_shared_copies(api):
    request_id = api.create()
    before = api.paths()
    with api.app.app_context():
        copy = db.session.scalar(select(CipherCopy).where(
            CipherCopy.file_id == api.records.document.id, CipherCopy.algorithm == "AES",
        ))
        path = Path(api.app.config["STORAGE_DIR"]) / copy.storage_name
    body = path.read_bytes()
    path.write_bytes(bytes([body[0] ^ 1]) + body[1:])
    response = api.post("b", f"/sharing/requests/{request_id}/approve", {
        "file_ids": [api.records.id_card_png.id, api.records.document.id],
    })
    assert response.status_code == 422 and api.paths() == before
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.status == "pending" and row.key_package is None
        assert db.session.scalars(select(SharedCopy)).all() == []


@pytest.mark.parametrize("invalid_json", [b"{", b"\xff"])
def test_authenticated_but_invalid_personal_json_returns_422(api, invalid_json):
    request_id = api.create()
    package = api.approve(request_id, [api.records.personal.id])
    assert api.unlock(request_id, package).status_code == 200
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        key = unwrap_share_key(api.app.config["MASTER_KEY"], row.wrapped_share_key, request_id)
        copy = db.session.scalar(select(SharedCopy).where(SharedCopy.request_id == request_id))
        nonce, blob = encrypt_shared(key, invalid_json, share_aad(request_id, copy.file_id))
        (Path(api.app.config["STORAGE_DIR"]) / copy.storage_name).write_bytes(blob)
        copy.nonce, copy.ciphertext_size = nonce, len(blob)
        db.session.commit()
    response = api.clients["a"].get(f"/sharing/requests/{request_id}/files/{api.records.personal.id}/personal")
    assert response.status_code == 422


def test_distinct_requests_use_distinct_keys_and_cannot_read_each_others_selection(api):
    first = api.create()
    first_package = api.approve(first, [api.records.id_card_png.id])
    second = api.create()
    second_package = api.approve(second, [api.records.document.id])
    assert api.unlock(first, first_package).status_code == 200
    assert api.unlock(second, second_package).status_code == 200
    with api.app.app_context():
        keys = [unwrap_share_key(api.app.config["MASTER_KEY"],
                db.session.get(AccessRequest, request_id).wrapped_share_key, request_id)
                for request_id in (first, second)]
        assert keys[0] != keys[1]
    assert api.clients["a"].get(f"/sharing/requests/{first}/files/{api.records.document.id}/download").status_code == 404
    assert api.clients["a"].get(f"/sharing/requests/{second}/files/{api.records.id_card_png.id}/download").status_code == 404


@pytest.mark.parametrize("action", ["reject", "unlock"])
def test_failed_decision_commit_does_not_save_partial_state(api, monkeypatch, action):
    request_id = api.create()
    package = api.approve(request_id) if action == "unlock" else None
    before = api.paths()

    def fail_commit():
        raise RuntimeError("synthetic commit failure")

    with monkeypatch.context() as patch:
        patch.setattr(db.session, "commit", fail_commit)
        with pytest.raises(RuntimeError, match="synthetic commit failure"):
            if action == "unlock":
                api.unlock(request_id, package)
            else:
                api.post("b", f"/sharing/requests/{request_id}/reject")
    assert api.paths() == before
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        assert row.unlocked_at is None
        assert row.status == ("approved" if action == "unlock" else "pending")
        if action == "reject":
            assert row.decided_at is None


def test_sharing_does_not_expose_secrets_or_modify_originals(approved, caplog, capsys):
    api, request_id, package = approved
    root = Path(api.app.config["STORAGE_DIR"])
    originals = {name: (root / name).read_bytes()
                 for record in api.records for name in record.storage_names}
    with api.app.app_context():
        row = db.session.get(AccessRequest, request_id)
        secrets = [api.users.a.password, api.users.b.password, api.users.c.password,
                   api.app.config["SECRET_KEY"], api.app.config["MASTER_KEY"],
                   unwrap_share_key(api.app.config["MASTER_KEY"], row.wrapped_share_key, request_id)]
        secrets.extend(db.session.scalars(select(User.password_hash)).all())
        secrets.extend(db.session.scalars(select(UserKey.encrypted_private_key)).all())
    responses = [api.unlock(request_id, package),
                 api.unlock(request_id, package, password="sentinel-wrong-password-7619"),
                 api.clients["b"].get(f"/sharing/requests/{request_id}/key-package")]
    secrets.append("sentinel-wrong-password-7619")
    for role in ("a", "b", "c"):
        listing = api.clients[role].get("/sharing/requests")
        assert package.encode() not in listing.data
        responses.append(listing)
    responses.append(api.clients["a"].get(
        f"/sharing/requests/{request_id}/files/{api.records.document.id}/download"
    ))
    outputs = [response.data for response in responses]
    outputs.extend(str(dict(response.headers)).encode() for response in responses)
    serializer = api.app.session_interface.get_signing_serializer(api.app)
    for client in api.clients.values():
        cookie = client.get_cookie(api.app.config["SESSION_COOKIE_NAME"])
        assert cookie is not None
        outputs.append(json.dumps(serializer.loads(cookie.value)).encode())
    captured = capsys.readouterr()
    outputs.extend([caplog.text.encode(), captured.out.encode(), captured.err.encode()])
    for secret in secrets:
        raw = secret.encode() if isinstance(secret, str) else secret
        variants = (raw, raw.hex().encode(), raw.hex().upper().encode(),
                    base64.b64encode(raw), base64.urlsafe_b64encode(raw).rstrip(b"="))
        assert not any(value in output for value in variants for output in outputs)
    assert originals == {name: (root / name).read_bytes() for name in originals}
