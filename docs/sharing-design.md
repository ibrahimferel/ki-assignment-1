# Sharing design (Assignment 2: key management)

Status: **short version, updated in M1-CP5**. The three tables below
(M1-CP2), the two requester-side access helpers in section 6.1 (M1-CP3), the
key pair made at registration (section 6.3, M1-CP4) and the key pair made at
login for old accounts (section 6.5, M1-CP5) are implemented and tested.
Items marked *planned* are agreed but not implemented yet; this file is
completed in M1-CP7.

Author: Member 1 (Backend and Database). Read by: Members 2, 3 and 4.

## 1. What the assignment asks

1. A user can request to see the private data of another user (including
   images and documents).
2. The requested user creates a symmetric key to share the data with the
   requester.
3. The symmetric key is distributed through another channel (email,
   WhatsApp, ...) but must be encrypted with asymmetric encryption.
4. The symmetric key must be stored securely inside the system.

## 2. Agreed flow (A = requester, B = owner)

1. A sends an access request to B (username and reason). Status `pending`.
2. B approves and ticks the records to share.
3. The server creates a random 32-byte share key K for this request.
4. For each ticked record: decrypt B's AES copy, encrypt it again with K
   using AES-256-GCM (AAD = request id + file id), and store the result as a
   separate shared copy.
5. The server stores K only **wrapped with MASTER_KEY**, and builds a key
   package = RSA-OAEP(public key of A, K, label = request id), shown to B.
6. B sends the key package to A by WhatsApp or email (the only step outside
   the application).
7. A pastes the package and types the password. The server opens A's private
   key, decrypts the package, compares the result with the stored K and, if
   it matches, marks the request `unlocked` (column `unlocked_at`).
8. A can now view or download the shared records, only from the shared copies.

## 3. Agreed decisions

| Topic | Decision |
| --- | --- |
| Asymmetric algorithm | RSA-3072 with OAEP and SHA-256 |
| User private key | PKCS#8, encrypted with the user's own password (scrypt N = 2^14, r = 8, p = 1, AES-256-CBC; see 6.3), created on the server |
| Key pair for new accounts | made by `register_user`, saved with the user in one transaction (M1-CP4) |
| Key package | one block of text: version, request id, base64 ciphertext |
| Existing users | accounts created before M1-CP4 get a key pair at their next successful login, made by `ensure_user_key` (M1-CP5, section 6.5) |
| Database reset | not needed: `python init_db.py` adds the new tables |
| Share key K | random, 32 bytes, one per request; stored only wrapped with MASTER_KEY |
| Shared copy cipher | AES-256-GCM, AAD = request id + file id |
| GCM tag | **appended to the end of the ciphertext**; there is no tag column |
| `shared_copy.ciphertext_size` | length of that whole blob (ciphertext + tag); the nonce is not included |
| `shared_copy.nonce` | the GCM nonce, in its own column |
| Password form | the NFKC-normalised password, encoded as UTF-8, the same form `authenticate` uses; `generate_user_keypair` applies it itself (see 6.3) |

## 4. Table contract (as implemented)

Style: `db.Column`, named constraints and indexes, `ondelete="CASCADE"` with
`passive_deletes=True`. SQLite foreign keys are switched on by
`app/db_pragmas.py`. Times are naive UTC.

### 4.1 `user_key` (model `UserKey`): one row per user

| Column | Type | Rules |
| --- | --- | --- |
| `user_id` | integer, PK | FK `user.id`, ON DELETE CASCADE |
| `public_key_pem` | blob | NOT NULL; public |
| `encrypted_private_key` | blob | NOT NULL; private key encrypted with the user's password |
| `created_at` | datetime | NOT NULL, filled by the application |

Both key columns are `bytes`, as returned by `generate_user_keypair`.

### 4.2 `access_request` (model `AccessRequest`)

| Column | Type | Rules |
| --- | --- | --- |
| `id` | integer, PK | automatic |
| `requester_id` | integer | NOT NULL; FK `user.id`, CASCADE; indexed |
| `owner_id` | integer | NOT NULL; FK `user.id`, CASCADE; indexed |
| `status` | string(16) | NOT NULL; `pending`, `approved` or `rejected`; ORM default `pending` |
| `reason` | string(500) | NOT NULL |
| `created_at` | datetime | NOT NULL, filled by the application |
| `decided_at` | datetime | NULL until the owner decides |
| `wrapped_share_key` | blob | NULL until approved; K wrapped with MASTER_KEY |
| `key_package` | text | NULL until approved; the RSA-OAEP package |
| `unlocked_at` | datetime | NULL until the requester unlocked it |

Constraints:

- `ck_access_request_status`: status is one of the three values.
- `ck_access_request_distinct_users`: `requester_id != owner_id`.
- `uq_access_request_pending_pair`: a **partial unique index** on
  (`requester_id`, `owner_id`) `WHERE status = 'pending'`: at most one pending
  request per pair and direction. Approved and rejected requests do not count,
  so a new request is possible after a decision. A duplicate raises
  `sqlalchemy.exc.IntegrityError`.
- Indexes `ix_access_request_requester_id` and `ix_access_request_owner_id`.

### 4.3 `shared_copy` (model `SharedCopy`)

| Column | Type | Rules |
| --- | --- | --- |
| `id` | integer, PK | automatic |
| `request_id` | integer | NOT NULL; FK `access_request.id`, CASCADE |
| `file_id` | integer | NOT NULL; FK `stored_file.id`, CASCADE; indexed |
| `nonce` | blob | NOT NULL |
| `storage_name` | string(64) | NOT NULL, unique; random file name under `STORAGE_DIR` |
| `ciphertext_size` | integer | NOT NULL; ciphertext + tag, in bytes |

Constraints: unique (`request_id`, `file_id`) and unique `storage_name`.
`request_id` has no separate index because the unique pair already serves
lookups by `request_id`. `storage_name` must match the same pattern as
`cipher_copy.storage_name` (16 to 64 letters, digits, `_` or `-`).

### 4.4 Relationships

| From | Attribute | To |
| --- | --- | --- |
| `User` | `key` (one) | `UserKey` |
| `User` | `requests_made`, `requests_received` | `AccessRequest` |
| `AccessRequest` | `requester`, `owner` | `User` |
| `AccessRequest` | `shared_copies` | `SharedCopy` |
| `StoredFile` | `shared_copies` | `SharedCopy` |
| `SharedCopy` | `request`, `file` | `AccessRequest`, `StoredFile` |

### 4.5 What a delete removes (database rows only)

| Deleted | Rows removed with it |
| --- | --- |
| a user | their `user_key`, every request they made or received, and those requests' shared copies; plus their own files, as before |
| a stored file | the shared copies of that file (the requests stay) |
| an access request | its shared copies (the files stay) |

## 5. Notes for the other members

- **Files on disk are not removed by the cascade.** The database removes the
  `shared_copy` rows, but the ciphertext files named by `storage_name` stay in
  `STORAGE_DIR`. The delete flow (Member 3) must collect the `storage_name`
  values of the shared copies **before** the delete, and remove the files after
  the commit, like `delete_record` does for `cipher_copy`. The same holds for
  deleting a user or a request.
- `cipher_copy.storage_name` and `shared_copy.storage_name` are each unique
  inside their own table, not across both tables. Names are random, so a
  collision is not expected, but the database does not enforce it.
- `status` has an ORM default (`pending`) but no database default: a raw SQL
  insert must give it.
- `reason` is limited to 500 characters by validation (Member 3), not by
  SQLite, which does not enforce `VARCHAR` length.
- No migrations: the three tables are final once pushed. A later column change
  forces everyone to delete their database file.
- A private-key check must look for the **plain** markers (`BEGIN PRIVATE KEY`,
  `BEGIN RSA PRIVATE KEY`). An encrypted PKCS#8 document starts with
  `BEGIN ENCRYPTED PRIVATE KEY`, so searching for "PRIVATE KEY" alone matches
  it too.

## 6. Access helpers and planned work

### 6.1 Implemented in M1-CP3: `app/authz.py`

```python
get_owned_or_404(model, object_id, *, options=())      # owner side (as before)
owned_select(model)                                    # owner side (as before)
get_requested_or_404(model, object_id, *, options=())  # requester side (new)
requested_select(model)                                # requester side (new)
```

The two new helpers are exact twins of the owner helpers; they filter
`requester_id` instead of `owner_id`. Rules, the same for all four:

- The user is always `current_user`. It is not a parameter, so a route can not
  check the wrong user and a request can not choose it.
- The check is part of the SQL (`WHERE id = :id AND requester_id = :user`).
  "No such row" and "someone else's row" take the same path and give the same
  plain 404 page.
- An anonymous visitor gets 401 before anything else. Routes still need
  `@login_required`.
- An `object_id` that is not a plain `int` between 1 and 2**63 - 1 answers 404.
- A model without a `requester_id` column raises `TypeError` (for example
  `StoredFile`, `CipherCopy`, `SharedCopy`). Only `AccessRequest` has one, so
  the requested helpers are for `AccessRequest` only.
- `authz.py` gained no import.

### 6.2 How Member 3 uses them

| Who | What | Helper |
| --- | --- | --- |
| owner B | see, approve or reject a request made to B; list the requests B received | `get_owned_or_404(AccessRequest, request_id)`, `owned_select(AccessRequest)` |
| requester A | see or unlock A's own request; list the requests A made | `get_requested_or_404(AccessRequest, request_id)`, `requested_select(AccessRequest)` |
| creating a request | set `requester_id=current_user.id`; find the owner by username | never take `requester_id` or `owner_id` from the form |
| shared copies | `request.shared_copies` after one of the helpers above | never look them up by an id from the URL |
| owner's original record | `get_owned_or_404(StoredFile, file_id)`; A gets 404, which is correct | A sees data only through shared copies |

```python
from sqlalchemy.orm import selectinload

from app.authz import get_requested_or_404

@login_required
def show_request(request_id):
    access = get_requested_or_404(
        AccessRequest,
        request_id,
        options=(selectinload(AccessRequest.shared_copies),),
    )
    ...  # the route checks status and unlocked_at, see below
```

Things the helpers do **not** do:

- They check **who**, not the **state**. A requester also gets their own
  `pending` or `rejected` request. The route must check `status == "approved"`
  (and `unlocked_at` for viewing or downloading) and must not show file
  metadata (names, kinds, sizes) before the owner approved.
- A user can be the requester of one request and the owner of another. The
  helper you pick decides the role; do not try one and then the other.
- The same 404 for "not yours" and "not there" is part of the design (no
  request id can be probed). Do not answer 403 or put ids in the message.

### 6.3 Implemented in M1-CP4: the key pair at registration

`app/crypto/asymmetric.py` holds one public function (contract 1). The other
functions of the contract belong to Member 2 and are not in that file.

```python
generate_user_keypair(password) -> (public_pem, encrypted_private_pem)  # both bytes
```

- RSA, 3072 bits, public exponent 65537.
- Public key: PEM `SubjectPublicKeyInfo` (`BEGIN PUBLIC KEY`).
- Private key: PEM PKCS#8 `BEGIN ENCRYPTED PRIVATE KEY`, protected by PBES2
  with scrypt and AES-256-CBC. The parameters are written inside the PEM, so a
  reader needs no configuration: **N = 2^14, r = 8, p = 1**, 16-byte random
  salt (about 16 MiB of memory per guess).
- **Why N = 2^14.** It was chosen for compatibility with `cryptography`
  41.0.3, the version pinned in `requirements.txt`: with N = 2^15 or larger
  that version fails to open the key ("Could not deserialize key data", tested),
  while pycryptodome opens it. It is much stronger than the 2048-round PBKDF2
  that `cryptography` 41.0.3 uses for a password-encrypted PKCS#8 (the rounds
  can not be set in that version), **but it is below the current OWASP
  recommendation** for scrypt (N = 2^17, r = 8, p = 1; that advice is for
  password storage and is applied here by analogy). The value is a constant in
  the module. Raising it later needs every reader of these keys to be able to
  open the larger value; keys already stored keep the parameters written in
  their own PEM.
- **The password.** The function applies NFKC and then UTF-8 itself. That is
  the same normalisation `authenticate` uses (`_check_password_shape`), so a
  password that logs in also opens the private key. NFKC is idempotent, so a
  caller that already normalised the password changes nothing. There is no
  separate public helper in `app/auth/services.py` (this replaces the earlier
  plan). **Whoever opens the private key later (Member 2's
  `decrypt_with_password`, Member 3 at unlock) must apply the same two steps:
  NFKC, then UTF-8 bytes.** Trap: pycryptodome turns a `str` passphrase into
  latin-1 bytes, which does not match; always pass the UTF-8 `bytes`.
- **Errors.** `CryptoError` with a fixed message, raised outside every `except`
  block (no `__context__`): one message for an unusable password (not a `str`,
  empty, longer than 1024 characters or not encodable), one for any failure
  while making the key pair. The password policy itself (length, control
  characters, common passwords) stays in `validate_password`.
- **`register_user`.** Order: validate the username and password, hash the
  password, make the key pair, then add the user and its `UserKey` and commit
  once. A failure while making the key pair raises `KeyGenerationError`
  ("Could not create the account. Please try again.", no `__context__`) before
  the database is touched, so no `user` row is left behind. The register page
  shows that message with HTTP status 500. Registering costs about one second
  more (key generation); a username that is already taken still pays it,
  because there is no pre-check, and the register throttle limits the damage.
- Accounts created before M1-CP4 have no key pair until their next successful
  login (section 6.5).

### 6.4 Test keys (`tests/conftest.py`)

Making an RSA-3072 key takes about a second, so tests get their keys from a
small pool of three REAL, DIFFERENT RSA keys, built lazily once per pytest
session. The counter starts again in every test: the first key made in a test
is pool key 1, the second key 2, the third key 3, then it wraps to key 1.
**Only the first three users of one test are guaranteed to have different key
pairs; the fourth gets the same key pair as the first.** Every private key is
still encrypted for real with its own user's password. A test that needs a
freshly generated key asks for the `real_keygen` fixture. Tests that check
"a third user can not use A's package" must keep their users within the first
three of the test (the shared fixtures A, B and C of M1-CP6 will).

### 6.5 Implemented in M1-CP5: the key pair at login (`ensure_user_key`)

`ensure_user_key(user, password)` in `app/auth/services.py` gives an old
account (a `user` row without a `user_key` row) its key pair. The login route
calls it after `authenticate` and `login_succeeded` have succeeded and before
`login_user`, with the password that was just verified. Failed, unknown and
throttled logins never reach it.

It returns one of five values and does not raise for database or key
generation problems:

| Value | Meaning |
| --- | --- |
| `KEY_PRESENT` | the user already has a key pair; nothing was changed |
| `KEY_CREATED` | a key pair was made and saved (one commit) |
| `KEY_KEYGEN_FAILED` | `generate_user_keypair` failed; nothing was saved |
| `KEY_SAVE_FAILED` | the commit failed; rolled back, nothing was saved |
| `KEY_CHECK_FAILED` | the first question to the database failed; nothing was done |

- **Order.** Look for an existing `user_key` row first (cheap); only when
  there is none, check the password again, make the key pair, add the row and
  commit once. An account that already has a key pair costs one query.
- **Password check inside the function.** It uses `verify_password`, the same
  NFKC path as `authenticate`, so a password that logged in is never refused
  here (tested with decomposed, composed and full-width forms). A password that
  does not match raises `ValueError`; a wrong type raises `TypeError`; so does
  a `user` that is not a `User`. The key pair is encrypted with the password
  and must never be made from a password that was not verified.
- **Only two exceptions are caught:** `CryptoError` and `SQLAlchemyError`.
  Any other exception is a bug and is not hidden.
- **A failure never blocks the login.** The user logs in without a key pair
  and nothing half-finished is left in the database. The login route writes a
  WARNING to the app log with the user id and the reason only (for example
  `keygen_failed`), never a password, a key or an exception text. The next
  successful login tries again.
- **Race.** Two first logins at the same time may both make a key pair, but
  `user_key.user_id` is the primary key, so only one row is saved. The loser
  gets an `IntegrityError`, rolls back, reads the winner's row and returns
  `KEY_PRESENT`. The first login of an old account costs about one second
  more (key generation).
- **`authenticate` is unchanged.** It only reads (there is no password rehash
  anywhere), so the `rollback()` in `ensure_user_key` can not discard a pending
  write of the login.

**For Member 3.** A user who logs in while key creation failed enters
**without** a `user_key` row. Code that needs the key pair (creating or
unlocking a request) must check for it and handle its absence explicitly (a
clear message, not a 500). `ensure_user_key` is public: it can be called again
when the user types the password again, for example at unlock.

**No change-password feature exists.** If one is added, the private key in
`user_key` must be re-encrypted with the new password in the same change.

### 6.6 Planned (not implemented yet)

- Shared test fixtures for a requester (A), an owner (B) and a third user (C),
  each with a valid `user_key` (M1-CP6).

## 7. Out of scope

Share expiry and the 15-minute unlock window, revoke, unlock rate limiting
(HTTP 429), automatic `wa.me` / `mailto:` buttons, public key fingerprints,
an SMTP server, browser-side crypto (WebCrypto), a database migration system,
and any change to the Assignment 1 encryption, the three-copy design or the
existing routes.
