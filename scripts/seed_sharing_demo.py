"""Create synthetic demo data for trying out the sharing screens.

Run from the project folder:

    python scripts/seed_sharing_demo.py

It writes into the database the app is configured for (``DATABASE_URL`` or
``instance/app.db``, the same one ``python run.py`` uses), so it prints the
target first. It only ever adds users whose names start with ``demo-``, and it
does nothing if ``demo-a`` already exists, so running it twice is safe.

Everything is synthetic. Do not put real data in these accounts.

Accounts (all use the same password, printed at the end):

* demo-a  requester. Also owns one personal record, so it can be an owner too.
* demo-b  owner of five records (personal data, a real PNG, a fake PNG, a PDF,
          an MP4).
* demo-c  a third user, for the "stolen key package" scenario.

Requests created through the real API (so the crypto is real):

  #1 demo-a -> demo-b  approved, active (needs Unlock; owner can show package)
  #2 demo-a -> demo-b  approved, then revoked
  #3 demo-a -> demo-b  rejected
  #4 demo-a -> demo-b  approved, then aged 8 days so it shows as expired
  #5 demo-b -> demo-a  pending (demo-a is the owner here: Approve / Reject)
  #6 demo-c -> demo-b  pending (to try Reject)
  #7 demo-a -> demo-b  pending (to try Approve live)
"""

import struct
import sys
import zlib
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

from flask_login import login_user  # noqa: E402
from sqlalchemy import select  # noqa: E402

from app import create_app  # noqa: E402
from app.auth import services as auth_services  # noqa: E402
from app.database import init_db  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import AccessRequest, User  # noqa: E402
from app.storage import services as storage_services  # noqa: E402
from app.storage.validation import serialize_personal  # noqa: E402
import sharing_fixtures as fx  # noqa: E402

PASSWORD = "demo-password-123"
TOKEN = fx.TOKEN_PATTERN  # finds the CSRF token in a page


def make_png(width=240, height=140):
    """A small real PNG (a colour gradient) so image previews actually show."""
    rows = b"".join(
        b"\x00" + b"".join(
            bytes((x * 255 // width, y * 255 // height, 180))
            for x in range(width)
        )
        for y in range(height)
    )

    def chunk(kind, data):
        body = kind + data
        return (struct.pack(">I", len(data)) + body
                + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF))

    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows))
            + chunk(b"IEND", b""))


def add_records(app, user_id, records):
    with app.test_request_context("/"):
        login_user(db.session.get(User, user_id))
        for kind, name, content_type, data in records:
            storage_services.create_record(
                plaintext=data, kind=kind, filename=name,
                content_type=content_type)


class Session:
    """A logged-in test client that talks to the real JSON API."""

    def __init__(self, app, username):
        self.client = app.test_client()
        page = self.client.get("/auth/login").get_data(as_text=True)
        response = self.client.post("/auth/login", data={
            "csrf_token": TOKEN.search(page).group(1),
            "username": username, "password": PASSWORD})
        assert response.status_code == 302, f"login failed for {username}"
        self.token = TOKEN.search(
            self.client.get("/sharing").get_data(as_text=True)).group(1)

    def post(self, path, payload=None):
        response = self.client.post(
            path, json=payload, headers={"X-CSRFToken": self.token})
        assert response.status_code in (200, 201, 204), (path, response.status_code)
        return response.get_json(silent=True)

    def get(self, path):
        return self.client.get(path).get_json()

    def request(self, owner, reason):
        return self.post("/sharing/requests", {"username": owner, "reason": reason})["id"]


def file_ids(session, *names):
    items = session.get("/storage/")["items"]
    wanted = {i["id"] for i in items if i["name"] in names or (
        i["kind"] == "personal_data" and "personal" in names)}
    return sorted(wanted)


DEMO_NAMES = ("demo-a", "demo-b", "demo-c")


def create_users_and_records(app):
    """Phase 1 (needs an application context): users and their records."""
    users = {n: auth_services.register_user(n, PASSWORD) for n in DEMO_NAMES}
    add_records(app, users["demo-b"].id, [
        ("personal_data", "personal-data.json", "application/json",
         serialize_personal(fx.PERSONAL_PAYLOAD)),
        ("id_card", "scan-synthetic.png", "image/png", make_png()),
        ("id_card", "id-card.png", "image/png", fx.SYNTHETIC_PNG),
        ("document", "report.pdf", "application/pdf", fx.SYNTHETIC_PDF),
        ("video", "clip.mp4", "video/mp4", fx.SYNTHETIC_MP4),
    ])
    add_records(app, users["demo-a"].id, [
        ("personal_data", "personal-data.json", "application/json",
         serialize_personal({**fx.PERSONAL_PAYLOAD,
                             "nama": "Peminta A (data sintetis)",
                             "nik": "0000000000000002"})),
    ])


def create_requests(app):
    """Phase 2: requests through the real API (no application context open,
    so every login session is separate)."""
    a, b, c = (Session(app, name) for name in DEMO_NAMES)
    share = file_ids(b, "scan-synthetic.png", "personal")

    r1 = a.request("demo-b", "Second opinion on my scan")
    b.post(f"/sharing/requests/{r1}/approve", {"file_ids": share})

    r2 = a.request("demo-b", "Insurance check (will be revoked)")
    b.post(f"/sharing/requests/{r2}/approve", {"file_ids": share})
    b.post(f"/sharing/requests/{r2}/revoke")

    r3 = a.request("demo-b", "Curious (will be rejected)")
    b.post(f"/sharing/requests/{r3}/reject")

    r4 = a.request("demo-b", "Old request (will be expired)")
    b.post(f"/sharing/requests/{r4}/approve", {"file_ids": share})
    with app.app_context():  # age it by 8 days: the share lasts 7
        old = db.session.get(AccessRequest, r4)
        old.decided_at = old.decided_at - timedelta(days=8)
        db.session.commit()

    b.request("demo-a", "Please share your details (B asks A)")
    c.request("demo-b", "Hello from C (try Reject)")
    a.request("demo-b", "Approve me live")


def remove_demo_users(app):
    with app.app_context():
        db.session.rollback()
        for name in DEMO_NAMES:
            user = db.session.execute(
                select(User).filter_by(username=name)).scalar_one_or_none()
            if user is not None:
                db.session.delete(user)
        db.session.commit()


def main():
    app = create_app()
    print("Target database:", app.config["SQLALCHEMY_DATABASE_URI"].split("///")[-1])
    init_db(app)
    with app.app_context():
        if db.session.execute(select(User).filter_by(username="demo-a")).first():
            print("demo-a already exists: nothing to do.")
            return
        create_users_and_records(app)
    try:
        create_requests(app)
    except Exception:
        # Do not leave half-made demo users behind, so the script can be
        # run again from a clean start.
        remove_demo_users(app)
        print("Seeding failed; the partly created demo users were removed.")
        raise

    print()
    print("Done. Log in with any of these (same password for all):")
    print("  usernames: demo-a  demo-b  demo-c")
    print("  password :", PASSWORD)
    print()
    print("Then open /sharing. See the top of this file for what each request is.")


if __name__ == "__main__":
    main()
