# Assignment 2 — Member 3 Sharing Service & API Specification

**Source:** `Assignment 2 Key Management — Team.txt` (Team Work Plan, 15 November 2026).  
**Scope:** Member 3 only — sharing service, JSON API, integration and tests.  
**Status:** Specification based on the team's proposed contracts; verify kickoff decisions and actual repository before implementation. This file does **not** assert that any code exists or tests have passed.

## 1. Ownership and deliverables

Member 3 integrates Member 1's database/authentication and Member 2's cryptography. Expected files:

- `app/sharing/services.py` — sharing business logic and storage coordination.
- `app/sharing/routes.py` — JSON HTTP endpoints.
- `app/sharing/validation.py` — request validation.
- `app/sharing/__init__.py` — package/blueprint setup as appropriate.
- `app/__init__.py` — register the sharing blueprint.
- Tests for happy paths and all refusal scenarios below (place them according to repository conventions).

Do not rewrite Member 1 models/authentication or Member 2 crypto implementations. All sharing routes require login; all POST requests require CSRF protection.

## 2. API contract (Contract 3)

| Method | Path | Actor | Request body | Success response |
|---|---|---|---|---|
| POST | `/sharing/requests` | Requester | `{ "username": "...", "reason": "..." }` | `201 { "id": ... }` |
| GET | `/sharing/requests` | Both | None | `{ "incoming": [...], "outgoing": [...] }` |
| POST | `/sharing/requests/<id>/approve` | Owner | `{ "file_ids": [...] }` | `200 { "key_package": "..." }` |
| GET | `/sharing/requests/<id>/key-package` | Owner | None | `200 { "key_package": "..." }` |
| POST | `/sharing/requests/<id>/reject` | Owner | None | `204` |
| POST | `/sharing/requests/<id>/revoke` | Owner | None | `204` |
| POST | `/sharing/requests/<id>/unlock` | Requester | `{ "key_package": "...", "password": "..." }` | `200 { "files": [...], "unlocked_until": ... }` |
| GET | `/sharing/requests/<id>/files/<file_id>/download` | Requester | None | File attachment |
| GET | `/sharing/requests/<id>/files/<file_id>/view` | Requester | None | Inline JPG/PNG with storage sandbox CSP |
| GET | `/sharing/requests/<id>/files/<file_id>/personal` | Requester | None | Personal-data JSON |

**Error conventions:** `400` invalid input; `404` for nonexistent or unauthorized resources (indistinguishable); `422` unable to decrypt; `429` excessive unlock attempts. Match existing `/storage` behavior. Other status codes and detailed response schemas are **not specified** by the source; agree on them with Member 4 rather than inventing a contract.

## 3. Database dependencies (Contract 2, Member 1)

| Model/table | Fields from the team contract | Constraints / behavior |
|---|---|---|
| `user_key` | `user_id`, `public_key_pem`, `encrypted_private_key`, `fingerprint`, `created_at` | One per user; cascade on user deletion |
| `access_request` | `id`, `requester_id`, `owner_id`, `status`, `reason`, `created_at`, `decided_at`, `expires_at`, `wrapped_share_key`, `key_package`, `unlocked_until` | `pending / approved / rejected / revoked`; requester != owner; one pending request per pair |
| `shared_copy` | `id`, `request_id`, `file_id`, `nonce`, `storage_name`, `ciphertext_size` | Unique `(request_id, file_id)`; cascade on request or original-file deletion |

Other existing dependencies: `StoredFile`, `owned_select(StoredFile)`, `get_owned_or_404`, new `get_requested_or_404`, authentication/CSRF and Member 1's unlock throttling. Verify exact names and signatures in repository.

## 4. Crypto dependencies (Contract 1, Member 2)

```python
# app/crypto/asymmetric.py
generate_user_keypair(password: str) -> Tuple[bytes, bytes]
public_key_fingerprint(public_pem: bytes) -> str
encrypt_for_user(public_pem: bytes, data: bytes, label: bytes) -> bytes
decrypt_with_password(encrypted_private_pem: bytes, password: str,
                      ciphertext: bytes, label: bytes) -> bytes

# app/crypto/share.py
new_share_key() -> bytes
encrypt_shared(key: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]
decrypt_shared(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes
wrap_share_key(master_key: bytes, key: bytes, request_id: int) -> bytes
unwrap_share_key(master_key: bytes, wrapped: bytes, request_id: int) -> bytes
encode_key_package(request_id: int, encrypted_key: bytes) -> str
decode_key_package(text: str) -> Tuple[int, bytes]
```

Use existing `decrypt_record(stored, "AES")` to read the owner's AES copy before re-encrypting. Do not implement RSA/AES primitives in Member 3.

**Proposed crypto parameters from the source:** RSA-3072 + OAEP SHA-256, label = request id; one random 32-byte AES-256 key per approved request; AES-GCM AAD = request id + file id; wrapped share key stored with MASTER_KEY; RSA-encrypted key package contains version, request id and base64 ciphertext. Exact byte encodings and serialization must be taken from Member 2's actual code, not guessed.

## 5. Service behavior

### Request and list

- Create access request by username; refuse self-request, unknown username and duplicate pending request for the same pair.
- Return incoming/outgoing requests according to the authenticated user.
- Before approval, requester may see owner username and status, **not** file names, counts or sizes.

### Approve

1. Confirm caller is owner of a pending request.
2. Accept only file IDs selected from the owner's files using `owned_select(StoredFile)`.
3. Generate one fresh share key for this request.
4. For each selected file, call `decrypt_record(stored, "AES")`, then `encrypt_shared` with matching AAD; write a separate encrypted shared copy.
5. Wrap share key with MASTER_KEY and encrypt it to requester's RSA public key using the request-specific OAEP label.
6. Encode key package and persist the approval, wrapped key, package and shared-copy rows in one DB transaction.
7. If anything fails, roll back database changes and remove any newly written files (follow existing `create_record` cleanup pattern).

Do not modify original owner files. The source proposes default-all selection in the UI; the API takes explicit `file_ids`.

### Reject, revoke and key-package retrieval

- Owner may reject pending requests.
- Owner may revoke access; remove shared-copy database rows, then physical files, and clear wrapped share key as specified by the team's plan. Check cleanup/error consistency with actual storage code.
- Owner can retrieve the saved RSA-encrypted key package again.

### Unlock

1. Confirm authenticated user is the requester and request is approved and not expired.
2. Parse package and ensure embedded request id matches URL request id.
3. Decrypt with requester's encrypted RSA private key and supplied password.
4. Unwrap server-stored share key and compare using `hmac.compare_digest`.
5. On success set `unlocked_until`; on failure count attempts through Member 1's throttle.
6. Never return or log plaintext share key, private key or password.

**Proposed policy:** share expires 7 days after approval; unlock lasts 15 minutes; e.g. five failed attempts per request per 15 minutes, with six consecutive failures yielding `429` and `Retry-After` (check actual throttle policy).

### Shared content

For every download, view or personal-data request, verify requester ownership, `approved` status, unexpired share, valid unlock window, and that the requested file is among approved `shared_copy` rows. Decrypt via Member 2's `decrypt_shared` with the exact original AAD. Download as attachment; image view uses the same sandbox CSP as the existing `/storage/<id>/view`; personal data returns JSON. Never grant direct access to owner's original `/storage` URLs.

## 6. Test requirements

| # | Scenario | Expected |
|---|---|---|
| 1 | A requests B; B approves 2 of 3 files; A unlocks with valid package/password | A sees exactly 2 approved files; images view and documents download |
| 2 | Correct package, wrong password | `422`, no unlock, failure counted |
| 3 | Third user C attempts A's package | Refused; C is not requester |
| 4 | Tamper with one character of package | `422` |
| 5 | Package from request 1 used for request 2 | Refused (request id/OAEP label mismatch) |
| 6 | Owner revokes after requester unlocks | Requester gets `404`; shared files removed |
| 7 | Share expiry or 15-minute unlock expiry | Refused until new request or unlock as appropriate |
| 8 | Owner deletes original shared record | Corresponding shared copy deleted |
| 9 | Requester accesses owner's original `/storage/<id>/...` URL | `404` |
| 10 | Six wrong unlock attempts | `429` with `Retry-After` |

Additional checks: login and CSRF on every new route, cross-user authorization, no pre-approval metadata leakage, no secrets in HTTP responses/cookies/logs, and no regression in Assignment 1.

**Project commands from team plan:**

```bash
python -m pytest -q
```

Also run `tests/test_auth_routes.py` and `tests/test_security_inventory.py` after routes are added. The plan says the route inventory must be updated by Member 1; coordinate rather than silently editing another member's area.

## 7. Implementation boundaries and integration

- Merge dependency order: Member 1 models/auth → Member 2 crypto → Member 3 service/API → Member 4 frontend.
- Keep endpoints consistent with Contract 3 so Member 4 can consume them.
- Do not create unspecified endpoints, response fields or crypto formats without team agreement.
- Source proposes resetting `instance/app.db` and running `python init_db.py` when schema changes; **do not delete any existing database without confirming it is disposable**.
- Source limitations: server remains trusted; unlock window is per request, not per browser; encrypted shared copies consume additional disk; original Assignment 1 DES/RC4 copies remain unchanged.

## 8. Verification note

This is a **design specification**, not a repository audit. Model names, helpers, import paths, CSRF configuration, storage paths, actual function signatures, agreed defaults and test results must be verified against the checked-out code. Where the source does not define exact JSON item shapes, MIME handling or transaction details, reuse established project conventions and explicitly flag decisions for team agreement.
