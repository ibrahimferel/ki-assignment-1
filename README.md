# Cryptography Assignment 1: core module (authentication, database, authorization)

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

Creates the `user`, `stored_file` and `cipher_copy` tables and the storage folder.
Safe to rerun: existing data is not modified.

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
the AirPlay Receiver service. Available pages: `/` (placeholder page),
`/auth/register`, `/auth/login` and `/auth/logout`.

## Running the tests

```bash
python -m pytest -q
```

`pytest.ini` turns every warning into an error. Latest result on macOS: 958
tests passed. Style check (optional, not in `requirements.txt`):
`pip install flake8`, then `flake8 app tests`.

## Folder structure

```
app/
  __init__.py          application factory (create_app), Flask-Login, CSRF, session cookie
  config.py            reading and validating .env (ConfigError if invalid)
  models.py            User, StoredFile, CipherCopy
  database.py          creating tables and the storage folder (init_db)
  db_pragmas.py        PRAGMA foreign_keys on every SQLite connection
  extensions.py        SQLAlchemy db object
  authz.py             get_owned_or_404, owned_select (data ownership)
  security_headers.py  security headers, CSP, Cache-Control
  request_limits.py    16 KiB body limit for /auth/*
  placeholder.py       placeholder page "/"
  auth/                services (Argon2id), forms, routes, throttle, redirects
  templates/           base.html, placeholder_home.html, auth/login.html, auth/register.html
docs/
  auth-integration.md  guide for other members (protecting routes, CSRF, uploads, CSP)
  data-model.md        data model design and explanation
tests/                 automated tests (pytest)
init_db.py             creates the tables and the storage folder
run.py                 development server entry point
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
  `get_owned_or_404`; data owned by someone else and data that does not exist
  both return 404. An inventory test checks every route in `app.url_map` (each
  must require login and a CSRF token).
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
15. The schema is created with `create_all()` without migrations; changing the
    schema means recreating the database. [K]
16. Design: DES and RC4 are weak; all three copies contain the same plaintext,
    so data confidentiality is only as strong as the weakest copy; whoever holds
    `.env` and the database can open all data. The encryption module is not yet
    in this branch. [K]
17. The mutation figures in the report were run in a sandbox by an AI assistant
    and have not been reproduced on macOS. [M]
18. Only Python 3.9 has been tested. [M]

## Team roles

| Member | Responsibility |
| --- | --- |
| Member 1 | Backend, authentication, and database (this branch) |
| Member 2 | Encryption and decryption algorithms and the key mechanism |
| Member 3 | to be filled in by the team |
| Member 4 | to be filled in by the team |
