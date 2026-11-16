"""Shared fixtures for the key-sharing tests (Assignment 2, M1-CP6).

``tests/conftest.py`` imports the fixtures from here with one line, so that
Members 2 and 3 can add their own fixtures to conftest.py without touching
this file. See ``docs/sharing-design.md`` ("Shared test fixtures") for how to
use them. Everything in here is synthetic test data.

What you get
------------
``trio`` / ``web_trio``
    Three saved users with a valid ``user_key``: A (the requester), B (the
    owner of data) and C (a third user). ``trio`` goes with the ``app``
    fixture (an application context is open); ``web_trio`` goes with the
    ``web`` fixture (no context is open, use it with a test client).
``owner_records`` / ``web_owner_records``
    Five records of B, one of each kind, saved with the real storage code
    (three ciphertext copies on disk each).
``make_request``
    Saves an ``access_request`` row. No crypto, no key package.
``login_as``
    Logs a test client in as one of the three users through the real route.
``make_trio``
    The builder itself, for a test that wants to build the users later.

The keys
--------
The users are made by the real ``register_user``, so their key pairs come
from ``generate_user_keypair`` with the test key pool of ``conftest.py``.
The pool gives three different RSA keys in turn, so three users made one
after the other always have three different key pairs. A fourth user of the
same test repeats the key pair of the first (see ``docs/sharing-design.md``).
The builder checks that the three public keys really differ and refuses to
go on if they do not.

The passwords
-------------
Every user has a constant password (``Party.password``) so that a test can
open the private key of that user. The password hashes are made with a cheap
Argon2 setting while the users are built (the real setting is put back
afterwards). A hash made that way is still verified by the real hasher,
because Argon2 reads its settings from the hash string. Nothing in the app
re-hashes a password at login. If that ever changes, a test that depends on
the hash cost has to build its own user.
"""

import re
from dataclasses import dataclass, field

import pytest
from argon2 import PasswordHasher
from flask_login import login_user

from app.auth import services
from app.extensions import db
from app.models import AccessRequest, User
from app.storage import services as storage_services
from app.storage.validation import serialize_personal

__all__ = [
    "OwnerRecords",
    "Party",
    "Record",
    "Trio",
    "build_owner_records",
    "build_trio",
    "login_as",
    "make_request",
    "make_trio",
    "owner_records",
    "trio",
    "web_owner_records",
    "web_trio",
]

# ------------------------------------------------------------------ data

USERNAME_A = "requester-a"
USERNAME_B = "owner-b"
USERNAME_C = "third-c"
# Test-only passwords: long enough, not common, different from each other.
PASSWORD_A = "tidal lantern quarry 4417"
PASSWORD_B = "copper meadow signal 9083"
PASSWORD_C = "velvet harbor compass 2561"

PERSONAL_PAYLOAD = {
    "nama": "Pemilik B (data sintetis)",
    "nik": "0000000000000001",
    "alamat": "Jalan Contoh 1, Kota Contoh",
    "tanggal_lahir": "1990-01-01",
}
# Minimal byte strings that pass ``validation.detect_content_type``.
SYNTHETIC_PNG = b"\x89PNG\r\n\x1a\n" + b"synthetic id card" + b"IEND\xaeB`\x82"
SYNTHETIC_JPEG = b"\xff\xd8\xff\xe0" + b"synthetic photo" + b"\xff\xd9"
SYNTHETIC_PDF = b"%PDF-1.4\n" + b"synthetic document\n" + b"%%EOF\n"
SYNTHETIC_MP4 = b"\x00\x00\x00\x18ftypmp42" + b"synthetic video" * 4

TOKEN_PATTERN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"')


@dataclass(frozen=True)
class Party:
    """One of the three users. Plain data, so it works in any context."""

    id: int
    username: str
    password: str = field(repr=False)

    @property
    def user(self):
        """The ``User`` row, loaded in the CURRENT session (context needed)."""
        return db.session.get(User, self.id)


@dataclass(frozen=True)
class Trio:
    a: Party  # the requester
    b: Party  # the owner of data
    c: Party  # a third user

    def __iter__(self):
        return iter((self.a, self.b, self.c))


@dataclass(frozen=True)
class Record:
    """A saved record of B and what it was made from."""

    id: int
    kind: str
    filename: str
    content_type: str
    plaintext: bytes = field(repr=False)
    sha256: str
    storage_names: tuple  # the three ciphertext file names


@dataclass(frozen=True)
class OwnerRecords:
    personal: Record
    id_card_png: Record
    id_card_jpg: Record  # an image is an ``id_card`` in this app
    document: Record
    video: Record

    def __iter__(self):
        return iter((self.personal, self.id_card_png, self.id_card_jpg,
                     self.document, self.video))


# --------------------------------------------------------------- builders


def build_trio():
    """Create A, B and C in the OPEN application context and return a Trio.

    The users are made one after the other by ``register_user``. A cheap
    Argon2 setting is used for the hashes while they are made; the real one
    is put back in every case.
    """
    real_hasher, real_dummy = services._HASHER, services._dummy
    services._HASHER = PasswordHasher(time_cost=1, memory_cost=8,
                                      parallelism=1)
    services._dummy = None
    try:
        users = [
            services.register_user(name, password)
            for name, password in (
                (USERNAME_A, PASSWORD_A),
                (USERNAME_B, PASSWORD_B),
                (USERNAME_C, PASSWORD_C),
            )
        ]
    finally:
        services._HASHER, services._dummy = real_hasher, real_dummy
    if len({u.key.public_key_pem for u in users}) != 3:
        raise RuntimeError(
            "the three users have no three different key pairs; check the "
            "key pool in tests/conftest.py"
        )
    return Trio(
        a=Party(users[0].id, USERNAME_A, PASSWORD_A),
        b=Party(users[1].id, USERNAME_B, PASSWORD_B),
        c=Party(users[2].id, USERNAME_C, PASSWORD_C),
    )


def build_owner_records(flask_app, trio):
    """Save the five records of B (open application context needed)."""
    owner = db.session.get(User, trio.b.id)
    made = []
    with flask_app.test_request_context("/"):
        login_user(owner)
        for kind, filename, content_type, plaintext in (
            ("personal_data", "personal-data.json", "application/json",
             serialize_personal(PERSONAL_PAYLOAD)),
            ("id_card", "id-card.png", "image/png", SYNTHETIC_PNG),
            ("id_card", "photo.jpg", "image/jpeg", SYNTHETIC_JPEG),
            ("document", "document.pdf", "application/pdf", SYNTHETIC_PDF),
            ("video", "clip.mp4", "video/mp4", SYNTHETIC_MP4),
        ):
            stored = storage_services.create_record(
                plaintext=plaintext, kind=kind, filename=filename,
                content_type=content_type,
            )
            made.append(Record(
                id=stored.id,
                kind=kind,
                filename=filename,
                content_type=content_type,
                plaintext=plaintext,
                sha256=stored.plaintext_sha256,
                storage_names=tuple(c.storage_name for c in stored.copies),
            ))
    return OwnerRecords(*made)


def _user_id(who):
    if isinstance(who, (Party, User)):
        return who.id
    if isinstance(who, int) and not isinstance(who, bool):
        return who
    raise TypeError("expected a Party, a User or an id")


# --------------------------------------------------------------- fixtures


@pytest.fixture()
def make_trio():
    """The builder: call it inside an open application context."""
    return build_trio


@pytest.fixture()
def trio(app):
    """Users A, B and C with a valid ``user_key`` each (``app`` context)."""
    return build_trio()


@pytest.fixture()
def web_trio(web):
    """The same users for tests with a client (``web``, no open context)."""
    with web.app_context():
        return build_trio()


@pytest.fixture()
def owner_records(app, trio):
    """Five records of B, with their ciphertext files in STORAGE_DIR."""
    return build_owner_records(app, trio)


@pytest.fixture()
def web_owner_records(web, web_trio):
    with web.app_context():
        return build_owner_records(web, web_trio)


@pytest.fixture()
def make_request():
    """Return ``make(requester, owner, status="pending", reason=...)``.

    It saves one ``access_request`` row in the CURRENT session and returns
    it. ``requester`` and ``owner`` may be a Party, a User or an id. Nothing
    else is set: no key package, no wrapped key, no decision time.
    """

    def _make(requester, owner, status="pending",
              reason="Synthetic request for tests"):
        row = AccessRequest(
            requester_id=_user_id(requester),
            owner_id=_user_id(owner),
            status=status,
            reason=reason,
        )
        db.session.add(row)
        db.session.commit()
        return row

    return _make


@pytest.fixture()
def login_as():
    """Return ``login(client, party)``: log in through the real login page."""

    def _login(client, party):
        page = client.get("/auth/login")
        found = TOKEN_PATTERN.search(page.get_data(as_text=True))
        assert found, "login_as: no CSRF token on the login page"
        response = client.post("/auth/login", data={
            "csrf_token": found.group(1),
            "username": party.username,
            "password": party.password,
        })
        assert response.status_code == 302, (
            "login_as failed for %s (status %d)"
            % (party.username, response.status_code)
        )
        return response

    return _login
