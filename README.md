# Cryptography Assignments 1 and 2: core module (authentication, database, authorization, encrypted storage, key sharing tables)

A Flask + SQLite + SQLAlchemy web application designed to store personal data,
ID card (KTP) images, documents (PDF/DOC/XLS) and videos in encrypted form
(AES, DES, RC4).

## Prerequisites

- Python 3.9 (tested versions: 3.9.6 on macOS and 3.9.25 on Linux; other
  versions have not been tested).
- `pip` and the `venv` module.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuring `.env` and keys

The application refuses to start without `SECRET_KEY` and `MASTER_KEY`. Copy the
template, then fill in both keys **without printing them to the screen**:

```bash
cp .env.example .env
chmod 600 .env
python - <<'PY'
import re
import secrets
from pathlib import Path

path = Path(".env")
text = path.read_text()
for name in ("SECRET_KEY", "MASTER_KEY"):
    text = re.sub(
        rf"^{name}=[ \t]*$",
        lambda match, name=name: f"{name}={secrets.token_hex(32)}",
        text,
        count=1,
        flags=re.MULTILINE,
    )
path.write_text(text)
print("Keys written to .env (values not shown).")
PY
```
or
```
Get-ChildItem -Force .env*
Copy-Item .env.example .env
@'
import re
import secrets
from pathlib import Path

path = Path(".env")
text = path.read_text()

for name in ("SECRET_KEY", "MASTER_KEY"):
    text = re.sub(
        rf"^{name}=[ \t]*$",
        lambda match, name=name: f"{name}={secrets.token_hex(32)}",
        text,
        count=1,
        flags=re.MULTILINE,
    )

path.write_text(text)
print("Kunci ditulis ke .env (nilai tidak ditampilkan).")
'@ | python -
```

This command only fills lines that are still empty, so it is safe to rerun and
does not overwrite existing keys. The two keys are different from each other.

| Variable | Meaning |
| --- | --- |
| `SECRET_KEY` | required; signs the session cookie and CSRF tokens (at least 32 characters) |
| `MASTER_KEY` | required; 64 hexadecimal characters (32 bytes), must differ from `SECRET_KEY`; protects the per-file keys |
| `FLASK_DEBUG` | `0` (default) or `1` only on your own machine |
| `SESSION_COOKIE_SECURE` | `1` when the site is served over HTTPS; `0` for `http://127.0.0.1` |
| `DATABASE_URL` | optional; default: SQLite in the `instance/` folder |
| `STORAGE_DIR` | optional; default: `instance/storage` |
| `MAX_UPLOAD_MB` | limit for a single upload request, default 50 |

**Do not commit `.env`** (it is already ignored by `.gitignore`). Keep a backup
of `MASTER_KEY` somewhere safe: if it is lost, none of the encrypted files can
be opened again.

## Creating the database

```bash
python init_db.py
```

Creates the tables (`user`, `stored_file`, `cipher_copy`, and for key sharing
`user_key`, `access_request`, `shared_copy`) and the storage folder. Safe to
rerun: it only creates what is missing and never changes existing tables or
data. After pulling Assignment 2, run it again: the three new tables are added
and your existing data stays as it is (there is no need to delete
`instance/app.db`).

If `access_request` already exists with only three allowed statuses, stop the
application and run `python migrate_sharing_status.py instance/app.db` before
using sharing. This explicit upgrade creates a backup, preserves existing rows
and shared copies, and adds `revoked` to the constraint. `init_db.py` does not
alter existing tables. A newly initialized database already has this constraint.

## Key sharing tables (Assignment 2)

The three key sharing tables are described in full in `docs/sharing-design.md`
(the table contract and the access helpers).

| Table | Holds | Key material |
| --- | --- | --- |
| `user_key` | one row per user: the public key and the private key | public key (PEM); the private key is stored encrypted with the user's own password (scrypt, AES-256-CBC); old accounts get it at their next login |
| `access_request` | a request from one user for another user's data, with its status (`pending`, `approved`, `rejected`, `revoked`) | wrapped share key and key package; empty until a request is approved |
| `shared_copy` | one extra encrypted copy of a file for one request | nonce; the ciphertext itself is a file on disk, not in the database |

Rules the database enforces:

- A requester can have only one `pending` request per owner.
- A user cannot request their own data.
- `status` can only be `pending`, `approved`, `rejected` or `revoked`.
- Deleting a user, a file or a request removes the rows that depend on it. The
  ciphertext files on disk are not removed by this cascade; `delete_record` in
  `app/storage/services.py` removes the files of one record. There is no
  user-deletion route or service.

`app/authz.py` also has the requester-side helpers `get_requested_or_404` and
`requested_select`. They check who made the request, not its status.

Current status: the tables, their rules and these helpers exist, and
registering a new account now creates its key pair (RSA-3072; the private key
is encrypted with the account's password, see `docs/sharing-design.md`).
Accounts created before that get their key pair at their next successful
login. The `/sharing` JSON API creates requests, approves selected files,
distributes an RSA-encrypted key package to the owner, unlocks shared copies,
and supports rejection and revocation. Sharing pages are a separate frontend task.

## Running

```bash
python run.py
```

The development server listens on `http://127.0.0.1:8000` (this machine only).
If port 8000 is in use, choose another port:

```bash
python run.py --port 8001
```

Port 5000 is deliberately not the default because on macOS it is often used by
the AirPlay Receiver service. Available pages: `/` (a landing page when
signed out, a temporary storage test page when signed in), `/auth/register`,
`/auth/login` and `/auth/logout`. The signed-in page uses the endpoints under
`/storage/` (list, upload, personal data create/show/update, view, download,
comparison, delete).

## Running the tests

```bash
python -m pytest -q
```

`pytest.ini` turns every warning into an error. Latest result on macOS: 1400
tests passed. Style check (optional, not in `requirements.txt`):
`pip install flake8`, then `flake8 app tests`.

## Folder structure

```
app/
  __init__.py          application factory (create_app), Flask-Login, CSRF, session cookie
  config.py            reading and validating .env (ConfigError if invalid)
  models.py            User, StoredFile, CipherCopy, UserKey, AccessRequest, SharedCopy
  database.py          creating tables and the storage folder (init_db)
  db_pragmas.py        PRAGMA foreign_keys on every SQLite connection
  extensions.py        SQLAlchemy db object
  authz.py             get_owned_or_404, owned_select (data ownership);
                       get_requested_or_404, requested_select (requester side)
  security_headers.py  security headers, CSP, Cache-Control
  request_limits.py    16 KiB body limit for /auth/*
  placeholder.py       page "/": landing page (signed out) or storage test page (signed in)
  auth/                services (Argon2id), forms, routes, throttle, redirects
  crypto/              AES/DES/RC4 engine, per-copy keys, user RSA key pair (asymmetric.py)
  storage/             upload, download and delete service, ciphertext files on disk, routes under /storage/
  templates/           base.html, landing.html, placeholder_home.html, auth/login.html, auth/register.html
  static/              css, js and images for the pages
docs/
  auth-integration.md  guide for other members (protecting routes, CSRF, uploads, CSP)
  data-model.md        data model design and explanation
  sharing-design.md    key sharing tables and access helpers (Assignment 2)
  Conversation With AI_*  conversation records (PDF and ZIP files)
tests/                 automated tests (pytest); shared fixtures for the sharing tests: tests/sharing_fixtures.py
init_db.py             creates the tables and the storage folder
run.py                 development server entry point
design.md              design specification of the web interface
crypto_benchmark.csv   benchmark results (default output of tests/test_crypto_performance.py)
```

## Security summary (implemented and tested)

- **Passwords:** Argon2id hashing (`argon2-cffi` default parameters); length 10 to
  128 characters, NFKC-normalized, rejected if it is a common password.
  Usernames are 3 to 32 ASCII characters (`a-z`, `0-9`, `.`, `_`, `-`).
- **Login:** the same failure message for a wrong password and an unknown
  username; `session.clear()` before login (anti-fixation); `strong` session
  protection.
- **Session:** `HttpOnly`, `SameSite=Lax` cookie, `Secure` when
  `SESSION_COOKIE_SECURE=1`; valid for 2 hours and not extended automatically.
- **CSRF:** required for every state-changing request.
- **Rate limiting:** login allows 5 failures per address+username pair and 20 per
  address within 15 minutes; registration allows 10 per address per hour.
  Responds with 429 and `Retry-After`.
- **Headers:** `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, strict CSP (no inline
  scripts/styles), `Cache-Control: no-store` except for static files,
  HSTS only when the `Secure` cookie is enabled.
- **Body size:** `/auth/*` is limited to 16 KiB (413 if larger); other routes
  follow `MAX_UPLOAD_MB`.
- **Access control:** a user's data can only be accessed by its owner through
  `get_owned_or_404` and `owned_select` (every `/storage/` route that reads,
  changes or deletes a record goes through them); data owned by someone else
  and data that does not exist both return 404. An inventory test checks every
  route in `app.url_map` (static files aside): every route outside the public
  ones (`/`, `/auth/login`, `/auth/register`) must require login, and every
  route that changes state must refuse a missing or wrong CSRF token.
- **Secrets:** `.env`, `instance/` and `*.db` files are ignored by Git; tests
  scan responses and logs for passwords, hashes and keys.

## Limitations

Markers: **[T]** proven by automated tests, **[M]** manual observation,
**[K]** design decision (read from the code), **[B]** BLOCKED (cannot be tested
yet).

1. Rate-limit counters live in the memory of a single process: they are lost when
   the server restarts and are not shared between workers. [T]
2. The limiter only reads `request.remote_addr`, so behind a proxy all clients
   appear as one address; a spoofed `X-Forwarded-For` header does not help. [T]
3. Flask-Login's `strong` session protection uses `X-Forwarded-For` to build the
   session identifier; this does not affect the limiter. [M]
4. The session cookie is valid for 2 hours without extension, and logout only
   deletes the cookie (there is no server-side session revocation). [K]
5. IDs of deleted users and files can be reused (SQLite without
   autoincrement), so an old cookie could map to a new user; revisit this if an
   account-deletion feature is added. [M]
6. Forms under `/auth/*` are limited to 16 KiB (413 if larger); other routes are
   limited by `MAX_CONTENT_LENGTH` (50 MB by default). [T]
7. A urlencoded body without Content-Length (chunked) is not rejected, but it is
   truncated at the limit. This was observed on the Werkzeug development server
   [M]; production servers (gunicorn/nginx) have not been tested [B].
8. 413 responses are not rate-limited (the per-request cost is small because the
   body is not read); however, a 413 is not counted as a login attempt. [K, T]
9. CSP is set with `setdefault`, so a route could technically loosen it; the rule
   against doing so exists only in the documentation. [K]
10. The `Server` header from the development server reveals the Werkzeug and
    Python versions. [M]
11. The effect of the CSP has only been tried manually in Safari 26.2 [M];
    Chrome and Firefox [B].
12. The HSTS header and the `Secure` cookie have only been tested through
    configuration settings, not over a real TLS connection. [T, B]
13. Usernames are ASCII only, and the common-password list is small. [T]
14. The application does not keep an audit log (no log of failed logins or
    429s). [K]
15. The schema is created with `create_all()` without migrations. Adding a new
    table needs no reset (`init_db.py` creates what is missing); changing the
    columns of an existing table means recreating the database. [K]
16. Design: DES and RC4 are weak; all three copies contain the same plaintext,
    so data confidentiality is only as strong as the weakest copy; whoever holds
    `.env` and the database can open all data. [K]
17. The mutation figures in the report were run in a sandbox by an AI assistant
    and have not been reproduced on macOS. [M]
18. Only Python 3.9 has been tested. [M]
19. `stored_file.plaintext_sha256` holds an unsalted SHA-256 of the plaintext in
    the database, so whoever has the database can test guesses of low-entropy
    data. `init_db.py` also refuses a database whose `stored_file` table was
    created without that column ("Table 'stored_file' already exists with
    different columns"); delete `instance/app.db` and run it again. [K]

## Team roles

| Member | Responsibility |
| --- | --- |
| Member 1 | Backend, authentication, and database (this branch) |
| Member 2 | Encryption and decryption algorithms and the key mechanism |
| Member 3 | to be filled in by the team |
| Member 4 | to be filled in by the team |
