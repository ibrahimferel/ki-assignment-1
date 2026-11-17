# Sharing frontend handoff: Member 3 → Member 4

**Task for Member 4** build the sharing UI against the
existing Flask backend described below. Extend the current Flask/Jinja frontend
and reuse its login, storage UI patterns, and styling. Keep the API contracts intact.

## 1. Existing implementation

Member 3 has implemented and tested the backend:

| Code | Responsibility |
|---|---|
| [`app/sharing/routes.py`](../app/sharing/routes.py) | Sharing HTTP endpoints and responses |
| [`app/sharing/services.py`](../app/sharing/services.py) | Request lifecycle, selected-file sharing, key packages, expiry, unlock, revocation |
| [`app/sharing/validation.py`](../app/sharing/validation.py) | JSON validation and input limits |
| [`app/crypto/share.py`](../app/crypto/share.py) | Server-side sharing cryptography |
| [`app/storage/routes.py`](../app/storage/routes.py) | Owner's file list for the approval picker |
| [`tests/test_sharing_routes.py`](../tests/test_sharing_routes.py) | API behavior and integration tests |

The existing vault page is [`app/templates/placeholder_home.html`](../app/templates/placeholder_home.html),
served at `/` after login. Its JS is [`app/static/js/storage.js`](../app/static/js/storage.js).
Sharing pages are still to be implemented. Add the sharing UI to the vault or
create a linked, authenticated Jinja page with external JS/CSS.

## 2. Member 4 requirements

Requester and owner are roles **per request**; one account can act as both.

| UI to build | Required behavior |
|---|---|
| Request access form | Submit the owner's username and a reason. Show validation and success feedback. |
| Incoming / outgoing lists | Load both lists; show counterpart username, reason, status, and dates. Include loading, empty, and error states. |
| Owner approval picker | Load the owner's records from `GET /storage/`; select specific files and approve. Offer Reject for pending requests. |
| Owner key-package panel | Show the full package after approval with a copy button. Allow retrieval again while the share is active. The owner sends it manually outside the app. |
| Requester unlock form | Accept the received package and the **requester's own account password**. Show shared files only after a successful unlock. |
| Shared-file panel | Provide downloads, JPG/PNG previews, and a personal-data viewer. Display share expiry and unlock deadline. |
| Owner revocation | Offer Revoke for approved requests; refresh the lists after success. |

Refresh request lists after create/approve/reject/revoke. Disable action buttons
while submitting. Catch network errors and avoid automatic POST retries: the
server may already have committed the action.

## 3. Authentication and request setup

- Use the same origin as Flask and cookie sessions from `/auth/login`.
- All sharing endpoints require login. Unauthenticated requests normally redirect
  to login (`302`); `fetch` follows redirects and may return login HTML with `200`.
  Check `response.redirected` before parsing the body.
- Every POST needs `X-CSRFToken`, read from `input[name="csrf_token"]` on the
  current page. The signed-in vault already includes it in the logout form.
  For a new Jinja page, include a hidden input with `value="{{ csrf_token() }}"`.
  Get a fresh token after login/reload; there is no CSRF token endpoint.
- Send JSON bodies with `Content-Type: application/json` and
  `credentials: "same-origin"`. Reject/revoke need no body.
- Put JS/CSS in external static files; the page CSP blocks inline scripts/styles.

Example call from an external JS file; apply the response handling in section 6:

```javascript
const response = await fetch("/sharing/requests", {
  method: "POST",
  credentials: "same-origin",
  headers: {
    "Content-Type": "application/json",
    "X-CSRFToken": document.querySelector('input[name="csrf_token"]').value,
  },
  body: JSON.stringify({ username: "owner-b", reason: "Medical review" }),
});
```

## 4. API contract

Base path: `/sharing/requests`. No trailing slash. `id` is an access-request ID;
`file_id` is an owner's stored-record ID, not a shared-copy ID.

| Method / path | Role | JSON body | Success |
|---|---|---|---|
| `POST /sharing/requests` | Requester | `{"username":"owner-b","reason":"Medical review"}` | `201 {"id":1}` |
| `GET /sharing/requests` | Both | — | `200 {"incoming":[],"outgoing":[]}` |
| `POST /sharing/requests/<id>/approve` | Owner | `{"file_ids":[2,4]}` | `200 {"key_package":"..."}` |
| `GET /sharing/requests/<id>/key-package` | Owner | — | `200 {"key_package":"..."}` |
| `POST /sharing/requests/<id>/reject` | Owner | — | `204`, empty body |
| `POST /sharing/requests/<id>/revoke` | Owner | — | `204`, empty body |
| `POST /sharing/requests/<id>/unlock` | Requester | `{"key_package":"...","password":"requester password"}` | `200`, unlock response below |
| `GET /sharing/requests/<id>/files/<file_id>/download` | Requester | — | Attachment, `application/octet-stream`, original filename |
| `GET /sharing/requests/<id>/files/<file_id>/view` | Requester | — | Inline `image/jpeg` or `image/png` |
| `GET /sharing/requests/<id>/files/<file_id>/personal` | Requester | — | Personal-data JSON below |

### Response shapes

Each incoming/outgoing entry has this shape (example values):

```json
{
  "id": 1,
  "username": "owner-b",
  "reason": "Medical review",
  "status": "approved",
  "created_at": "2026-11-17T08:00:00Z",
  "decided_at": "2026-11-17T09:00:00Z",
  "expires_at": "2026-11-24T09:00:00Z"
}
```

`incoming` means the current user is owner; `username` identifies the requester.
`outgoing` means the current user is requester; `username` identifies the owner.
Both lists use descending request ID. Status is `pending`, `approved`, `rejected`,
or `revoked`. `decided_at` is null while pending; `expires_at` is null unless
approved. Dates are UTC ISO 8601 ending in `Z`, optionally with microseconds.
Listing contains **no files, key package, or unlock deadline**.

The approval picker uses `GET /storage/`:

```json
{"items":[{"id":2,"name":"id-card.png","kind":"id_card","size":12345}]}
```

Successful unlock returns:

```json
{
  "files": [
    {"id":2,"name":"id-card.png","kind":"id_card","content_type":"image/png","size":12345},
    {"id":4,"name":"report.pdf","kind":"document","content_type":"application/pdf","size":67890}
  ],
  "unlocked_until": "2026-11-17T09:15:00Z"
}
```

Files use ascending file ID; `size` is plaintext bytes. Kinds are `id_card`,
`document`, `video`, and `personal_data`. Build sharing URLs using these IDs.
`GET .../personal` only accepts `personal_data` and returns:

```json
{"nama":"Owner B","nik":"0000000000000001","alamat":"Example Street 1","tanggal_lahir":"1990-01-01"}
```

Keep these field names unchanged. Render user text with `textContent`.
Use `<img src="SHARING_VIEW_URL">` for JPG/PNG and normal links for downloads.
Other formats use download; iframe/object previews are blocked by security headers.

## 5. Validation and access rules

- **Create:** username is trimmed/lowercased; 3–32 ASCII characters (`a-z`, digits,
  `.`, `_`, `-`), starting/ending with a letter or digit. Reason is trimmed,
  required, and at most 500 characters. Self-requests and duplicate pending
  requests in the same direction return `400`; unknown usernames return `404`.
- **Approve/reject:** pending requests only. Approval requires 1–100 unique integer
  file IDs (`1..2^63-1`), all owned by the approver. Strings/bools are invalid IDs.
  Repeating a decision returns `400`. A new request is allowed once the previous
  request is no longer pending.
- **Key package:** opaque text, copied in full and transferred manually (e.g.,
  WhatsApp/email). Only the owner can retrieve it. Backend sends no messages.
- **Unlock:** package ≤2048 characters; password ≤1024 raw characters. Send both
  as strings. Do not trim/change the password. Empty strings reach cryptographic
  validation and return `422` on an active share.
- **Expiry:** share lasts 7 days from approval; unlock lasts 15 minutes from a
  successful unlock. Every file read checks both deadlines. An expired share
  still has status `approved`; use `expires_at` to display expiry.
- **Re-unlock:** allowed while the share is active. Reloading the page loses the
  frontend file list/deadline; the requester can unlock again. Unlock state is
  stored per request, not per browser.
- **Revoke:** approved requests with an available share key only; repeating it
  returns `400`. Revocation removes shared copies and invalidates package/unlock
  access. Previously downloaded files cannot be withdrawn.
- **File access:** always use `/sharing/...` for requester reads. Owner `/storage/...`
  URLs remain inaccessible. Unselected files, wrong roles, inactive shares, and
  missing/expired unlocks return `404`.

Approval creates encrypted content snapshots; later original edits do not update
them. Deleting an original removes its shared copies. The frontend needs no RSA/AES
implementation and receives no plaintext share key. Never persist passwords in
URLs, logs, cookies, localStorage, or sessionStorage; clear the password field after use.

## 6. Frontend error handling

| Response | Required handling |
|---|---|
| Login redirect | Navigate to login; obtain fresh CSRF after login. |
| `400` | Show validation/state feedback. CSRF errors may require reload/login. |
| `404` | Refresh state; offer re-unlock only if the share is still active. Never fall back to owner URLs. |
| `422` | Show a generic decryption/input error; allow package/password correction. |
| `429` | Disable unlock retries for `Retry-After` seconds. Default: five failed attempts per user/request in 15 minutes; success resets the count. |
| `413` / `500` | Show a general size/server error; refresh state before retrying a POST. |
| `204` | Success with no body; do not call `response.json()`. |

Check `Content-Type` before parsing JSON: CSRF, `abort(404)`, and other errors can
return HTML. JSON errors use `{"error":"..."}`; existing messages may be Indonesian.
Do not depend on exact message text. There is no sharing `409` response.

## 7. Member 4 acceptance checklist

- [ ] Requester A can request access to owner B; both see the correct list entry.
- [ ] B selects two of three records; approval produces a copyable package.
- [ ] A unlocks with that package and A's password; only the two selected records appear.
- [ ] Downloads, image previews, and personal-data display use sharing endpoints.
- [ ] Reject/revoke refresh the UI; revoked access fails even after a prior unlock.
- [ ] Expiry, re-unlock, wrong password/package, `429`, login redirect, and CSRF errors have usable feedback.
- [ ] No password persistence, inline scripts, or assumed endpoints/response fields.

No separate shared-file listing, notifications, username search, server pagination,
or editing file selection after approval exists. Use the endpoints above.
Validate backend compatibility with `python -m pytest tests/test_sharing_routes.py`;
verify the UI flow manually using two accounts.