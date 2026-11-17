# MedVault: Assignment 2 (Key Management): Member 4 Project Guide

**Role:** Member 4, Frontend & Demo
**Course:** Information Security (I), Group 2
**Branch:** `feature/frontend`
**Sources:** the team plan *"Assignment 2 — Key Management: Rencana Kerja Tim"* (PDF) and Member 3's `sharing-api-handoff.md` (`docs/sharing-api-handoff.md`).

> **Precedence rule.** The PDF is the original plan and was written before the backend existed. The handoff describes what Member 3 actually built. Where they disagree, **the handoff wins** (see section 3). Do not change the API contracts. Use them as they are.

---

## 1. What the assignment asks for

MedVault (the Assignment 1 app) must let one user view another user's private data, such as images and documents, under four requirements:

| # | Slide requirement | How MedVault meets it |
|---|---|---|
| 1 | A user can request to view another user's private data (images, documents). | Requester submits the owner's username plus a reason. Owner approves and picks which records to share. |
| 2 | The owner creates a symmetric key to share the data. | On approve, the server makes a random 32-byte AES-256 share key `K` per request. Selected records are decrypted and re-encrypted under `K` (AES-256-GCM) as separate "shared copies". |
| 3 | The symmetric key is sent through another channel (email, WhatsApp) but encrypted with asymmetric encryption. | `K` is encrypted with the requester's RSA-3072 public key (RSA-OAEP, label = request id). The result is the **key package**, a short text block. The owner copies it and sends it manually. |
| 4 | The symmetric key is stored securely in the system. | `K` is stored only wrapped with `MASTER_KEY` (`access_request.wrapped_share_key`). It never appears as plaintext in the DB, logs, responses, or cookies. |

### The 8-step flow (A = requester, B = owner)

1. A sends a request to B (username + reason). Status: `pending`.
2. B sees the incoming request, clicks **Approve**, and ticks which records to share.
3. Server creates share key `K` for this request.
4. For each selected record the server decrypts B's AES copy and re-encrypts it with `K` (AAD = request id + file id) as a shared copy.
5. Server stores `K` wrapped with `MASTER_KEY` and builds the key package `RSA-OAEP(A.public_key, K, label=request_id)`. B sees the package on screen.
6. **B sends the package to A through WhatsApp or email.** This is the only step outside the app.
7. A pastes the package and types their own account password. The server opens A's private key with that password, decrypts the package, and compares the result with the stored `K`. A match marks the request unlocked.
8. A views and downloads the shared records. Images show as previews, documents download, and personal data is displayed.

### Key types (for your report section and demo narration)

- **User RSA key pair (3072-bit):** created at register, or at first login for old accounts. The public key is stored plain. The private key is stored as PKCS#8 encrypted with the user's password.
- **Share key `K` (AES-256):** one per request, stored wrapped with `MASTER_KEY`. It only opens that request's shared copies.
- **Per-copy key (Assignment 1, unchanged):** `cipher_copy.wrapped_key`, for the owner's own AES/DES/RC4 copies.
- **`MASTER_KEY` (Assignment 1, unchanged):** lives only in `.env`.

---

## 2. Your scope as Member 4

You build the screens users touch to request, approve, unlock, and view shared data. You also prepare the demo, the screenshots, and the report section "Screenshots and demo walkthrough".

- **Your files:** `app/templates/` (vault page or a new linked, authenticated Jinja page), `app/static/js/sharing.js` (new), `app/static/css/` (new or extended). Reuse the Assignment 1 look and patterns.
- **You depend on:** Member 3's JSON API (done, see section 5), and the Assignment 1 frontend patterns (`storage.js`, vault template).
- **Team status:** Members 1, 2, and 3 are done. The backend is tested, and the sharing UI is the only part left. Merge order is Member 1, 2, 3, then you.

### UI rules

- **English** UI text, consistent with Assignment 1.
- **MedVault style** from [design.md](design.md): dark theme, teal accent `#2DD4BF`, rounded cards, Inter font.
- **No inline `<script>` and no inline `style=`.** The CSP blocks both. All JS goes in `sharing.js`, all CSS in `.css` files.
- Render server text with `textContent`, **never `innerHTML`**.

---

## 3. Differences between the PDF and the handoff (read this first)

The PDF's section 13 lists features as **out of scope**. Member 3's handoff shows the backend **did implement** them, so the UI must now handle them:

| Feature | PDF says | Handoff says (use this) |
|---|---|---|
| Share expiry | Out of scope | Share lasts **7 days** from approval. `expires_at` is returned in list entries. Show it. |
| Unlock window | Out of scope | Unlock lasts **15 minutes**. Unlock response includes `unlocked_until`. Show it. |
| Revoke | Out of scope | `POST .../revoke` exists. Owner needs a **Revoke** button for approved requests. |
| Unlock throttling | Out of scope | `429` with `Retry-After`. Disable unlock retries for that many seconds. |
| Request statuses | `pending / approved / rejected` | Adds **`revoked`**. |
| Re-unlock | Not mentioned | Allowed while the share is active. Unlock state is per request, not per browser. |

Items from the PDF's out-of-scope list that remain **out of scope** for the UI: `wa.me` and `mailto:` buttons (only a **Copy** button, plus optional Download `.txt`), public-key fingerprint display, WebCrypto in the browser, SMTP, and any DB migration system.

Other points where the handoff is more specific than the PDF:

- Approval picker uses `GET /storage/`, which returns `{"items":[{"id","name","kind","size"}]}`.
- A 404 on shared files can mean expired, revoked, or not-unlocked. The handoff gives specific handling for each case in section 7 below.
- Requester list entries carry **no files, key package, or unlock deadline**. Those only come from the unlock response.

---

## 4. Existing frontend you will build on

| File | What it is |
|---|---|
| `app/templates/base.html` | Base layout (`{% block head %}`, `{% block content %}`). |
| `app/templates/placeholder_home.html` | The vault page at `/` after login. Has `#vault` root, header nav, logout form with `csrf_token`, panels, `<dialog>` elements (delete and view). |
| `app/static/js/storage.js` | Vault JS (an IIFE). Has the patterns to copy: `request()` wrapper (handles `response.redirected`, 400/404/413/422, connection failures), `post()` (adds `X-CSRFToken`, optional JSON header), `makeButton()`, `say()` notice banner. |
| `app/static/css/storage.css`, `storage-refinements.css` | Panel, button, notice, record-list, dialog, and responsive styles. Reuse classes: `.panel`, `.tag`, `.primary.button`, `.subtle-button`, `.danger-button`, `.notice` / `.error-notice`, `.record-list`, `.record-item`, `.record-actions`, `.field-hint`. |
| `design.md` | Full visual spec (colors, typography, spacing). |
| `tests/test_sharing_routes.py` | Backend contract tests. A good reference for exact behavior. |
| `tests/sharing_fixtures.py` | Shared fixtures (users A, B, C, B's records). Described in `docs/sharing-design.md` section 6.6. |

**Placement decision.** Either add sharing panels to the vault page, or create a linked authenticated Jinja page (for example `/sharing` rendered from a new template, with its own `sharing.js` and `sharing.css`). The handoff allows both. Whichever you pick:

- The page must contain `<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">`, because `sharing.js` reads the token from there.
- Add a nav link between the two pages (the vault header has `nav` links).
- If you add a new route, it needs `@login_required`, and `tests/test_security_inventory.py` must still pass.

---

## 5. API contract (Member 3, do not change)

Base path `/sharing/requests` (no trailing slash). `id` = access-request ID. `file_id` = the owner's stored-record ID (not a shared-copy ID).

| Method and path | Role | Body | Success |
|---|---|---|---|
| `POST /sharing/requests` | Requester | `{"username","reason"}` | `201 {"id":1}` |
| `GET /sharing/requests` | Both | none | `200 {"incoming":[],"outgoing":[]}` |
| `POST /sharing/requests/<id>/approve` | Owner | `{"file_ids":[2,4]}` | `200 {"key_package":"..."}` |
| `GET /sharing/requests/<id>/key-package` | Owner | none | `200 {"key_package":"..."}` |
| `POST /sharing/requests/<id>/reject` | Owner | none | `204`, empty body |
| `POST /sharing/requests/<id>/revoke` | Owner | none | `204`, empty body |
| `POST /sharing/requests/<id>/unlock` | Requester | `{"key_package","password"}` | `200` unlock response |
| `GET .../<id>/files/<file_id>/download` | Requester | none | Attachment, `application/octet-stream`, original filename |
| `GET .../<id>/files/<file_id>/view` | Requester | none | Inline `image/jpeg` or `image/png` |
| `GET .../<id>/files/<file_id>/personal` | Requester | none | Personal-data JSON |
| `GET /storage/` | Owner | none | `{"items":[{"id","name","kind","size"}]}` (approval picker source) |

### Response shapes

**List entry** (same shape in `incoming` and `outgoing`):

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

- `incoming` means the current user is the **owner**, and `username` is the **requester**.
- `outgoing` means the current user is the **requester**, and `username` is the **owner**.
- Both lists are sorted by descending request ID.
- Status is one of `pending`, `approved`, `rejected`, `revoked`.
- `decided_at` is `null` while pending. `expires_at` is `null` unless approved.
- Dates are UTC ISO 8601 ending in `Z`, optionally with microseconds.
- An expired share still has status `approved`. **Compare `expires_at` to the current time** to show "Expired".

**Unlock response:**

```json
{
  "files": [
    {"id":2,"name":"id-card.png","kind":"id_card","content_type":"image/png","size":12345},
    {"id":4,"name":"report.pdf","kind":"document","content_type":"application/pdf","size":67890}
  ],
  "unlocked_until": "2026-11-17T09:15:00Z"
}
```

Files are sorted by ascending file ID. `size` is plaintext bytes. Kinds: `id_card`, `document`, `video`, `personal_data`.

**Personal data** (`.../personal`, only valid for `personal_data` records). Keep these field names unchanged:

```json
{"nama":"Owner B","nik":"0000000000000001","alamat":"Example Street 1","tanggal_lahir":"1990-01-01"}
```

**Errors:** JSON errors look like `{"error":"..."}`. Messages may be in Indonesian, so **do not depend on message text**. CSRF errors and `abort(404)` can return **HTML**, so check `Content-Type` before calling `response.json()`. There is no sharing `409`.

---

## 6. Request setup rules

- Same origin as Flask. Cookie session from `/auth/login`. Use `credentials: "same-origin"`.
- Every **POST** needs the header `X-CSRFToken`, read from `input[name="csrf_token"]` on the current page. After login or reload the token is fresh. There is no token endpoint.
- JSON bodies need `Content-Type: application/json`. Reject and revoke need no body.
- **Login redirect:** unauthenticated requests redirect (`302`). `fetch` follows the redirect and may return login HTML with `200`. **Check `response.redirected` before parsing**, then navigate to login.
- **`204` has no body.** Do not call `response.json()`.
- Do **not** auto-retry POSTs. The server may already have committed the action. After an uncertain failure, refresh state first.

Reference call:

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

---

## 7. Validation, access rules, and error handling

### Validation (mirror client-side for friendly messages, server stays authoritative)

- **Create request:** username is trimmed and lowercased, 3 to 32 ASCII characters (`a-z`, digits, `.`, `_`, `-`), starting and ending with a letter or digit. Reason is trimmed, required, at most 500 characters. Self-requests and a duplicate pending request in the same direction return `400`. Unknown username returns `404`.
- **Approve and reject:** pending requests only. Approval needs 1 to 100 unique integer file IDs (`1..2^63-1`), all owned by the approver. Strings and booleans are invalid IDs. Repeating a decision returns `400`. A new request is allowed once the previous one is no longer pending.
- **Unlock:** key package at most 2048 characters. Password at most 1024 raw characters. Send both as strings. **Do not trim or alter the password.** Empty strings reach crypto validation and return `422` on an active share.
- **Revoke:** approved requests with an available share key only. Repeating it returns `400`. It removes shared copies and invalidates package and unlock access. Files already downloaded cannot be withdrawn, so say so in the confirmation text.
- **Key package:** opaque text. Copy it in full. Only the owner can retrieve it. The backend sends no messages.

### Time rules

- Share lasts **7 days** from approval (`expires_at`).
- Unlock lasts **15 minutes** from a successful unlock (`unlocked_until`).
- Every file read checks both deadlines.
- Reloading the page loses the file list and deadline in the browser, but the requester can **unlock again** while the share is active.

### Error-handling table

| Response | Required handling |
|---|---|
| Login redirect (`response.redirected`) | Navigate to login. Get a fresh CSRF token after login. |
| `400` | Show validation or state feedback. A CSRF error (HTML body) may need a reload or re-login. |
| `404` | Refresh state. Offer re-unlock **only if** the share is still active. **Never fall back to `/storage/...` owner URLs.** |
| `422` | One generic message, for example "Could not unlock. Check the key package and your password." Allow correction. Do not say whether the package or password was wrong. |
| `429` | Disable unlock retries for `Retry-After` seconds (default limit: 5 failed attempts per user and request in 15 minutes; success resets it). Show a countdown. |
| `413` / `500` | General size or server error. Refresh state before retrying a POST. |
| `204` | Success, no body. |
| Network failure | Catch, show "Connection failed", re-enable the button. No automatic retry. |

---

## 8. Required UI components

Requester and owner are roles **per request**. One account can be both, so show both lists on the same page.

| # | Component | Required behavior |
|---|---|---|
| 1 | **Request access form** | Owner username + reason. Client-side validation hints. Success message on `201`. Clear messages for `400` and `404` (for example "User not found"). Refresh lists after success. |
| 2 | **Incoming / Outgoing lists** | Load both from `GET /sharing/requests`. Show counterpart username, reason, status, and dates. Include **loading, empty, and error states**. Show only the buttons that fit each status (see matrix below). Outgoing shows no file names before unlock. |
| 3 | **Owner approval picker** | On Approve, load the owner's records from `GET /storage/` into a checklist (default all checked, per the PDF). Block submit with a message if nothing is checked. Send `file_ids` of checked items. Offer **Reject** for pending requests. |
| 4 | **Owner key-package panel** | After approval show the full package in a read-only textarea with a **Copy** button (optional Download `.txt`). Short hint: "Send this text to the requester through WhatsApp or email. It is encrypted and only the requester can open it with their password." Do not claim more than that. Provide **Show key package** (`GET .../key-package`) to retrieve it again while the share is active. The package is never stored in localStorage, cookies, or URLs. |
| 5 | **Requester unlock form** | Package textarea (paste; the PDF also suggests an optional `.txt` file picker using `FileReader`) and a password input of `type="password"`, which is the **requester's own account password**. **Clear the password field after every submit**, success or failure. Show the shared-file panel only after a successful unlock. |
| 6 | **Shared-file panel** | Per file: download link, JPG/PNG preview via `<img src=".../view">`, personal-data viewer via `fetch(".../personal")` rendered with `textContent`. Display **share expiry** (`expires_at` from the list entry) and **unlock deadline** (`unlocked_until`). Other formats (PDF, MP4) use download only, because iframe and object previews are blocked by security headers. |
| 7 | **Owner revocation** | **Revoke** button for approved requests, with a confirmation dialog. Refresh lists after success. |

### Button matrix per status

| Status | Incoming (I am owner) | Outgoing (I am requester) |
|---|---|---|
| `pending` | Approve, Reject | none (waiting) |
| `approved`, share active | Show key package, Revoke | Unlock (re-unlock allowed) |
| `approved`, past `expires_at` | none (show "Expired") | none (show "Expired") |
| `rejected` | none | none |
| `revoked` | none | none |

### Cross-cutting behavior

- **Refresh both lists** after create, approve, reject, and revoke.
- **Disable action buttons while a request is in flight**, and re-enable them in `finally`.
- Use `textContent` for all server-provided text (usernames, reasons, file names, personal data).
- Never put the password or the key package in a URL, log, cookie, `localStorage`, or `sessionStorage`.
- Prefer `fetch` for downloads and previews where you can, so errors (404, 422) become friendly messages instead of raw JSON. Plain download links are acceptable, but they can show raw JSON on error.
- Accessibility: reuse `role="status"` / `aria-live` patterns from the vault, `<dialog>` for confirmations, and keyboard-reachable controls.
- Responsive: match the existing breakpoints at 850px and 650px.

---

## 9. Suggested task plan

The PDF's 9 tasks, updated for the finished backend. Check each box only when it truly passes.

- [ ] **T1: Page scaffold.** Decide placement (vault panels or a `/sharing` page). Add the CSRF hidden input, nav link, `sharing.js` (deferred), and `sharing.css`. Console has no CSP errors.
- [ ] **T2: Shared helpers in `sharing.js`.** `apiRequest()` wrapper (redirect check, content-type check, 204 handling, 429 `Retry-After`, network catch), `postOptions()`, `say()` banner, a date formatter for UTC `Z` timestamps, and an `isExpired()` helper.
- [ ] **T3: Request access form** (component 1).
- [ ] **T4: Incoming and outgoing lists** (component 2), including loading, empty, and error states and the status matrix.
- [ ] **T5: Approval dialog with picker** (component 3), plus Reject.
- [ ] **T6: Key-package panel** (component 4): Copy, optional Download `.txt`, Show key package.
- [ ] **T7: Unlock dialog** (component 5): paste or file, password clear, `422` and `429` handling.
- [ ] **T8: Shared-file panel** (component 6): preview, download, personal data, expiry and unlock deadline display.
- [ ] **T9: Revoke** (component 7) with confirmation.
- [ ] **T10: Error and CSP pass.** Walk through every row of the error table. Open DevTools: no CSP violations on any screen.
- [ ] **T11: Manual end-to-end test** with two accounts in two browsers (see section 10).
- [ ] **T12: Demo and report material:** screenshots and walkthrough (section 11).

**Optional early step.** The PDF suggests starting with mock JSON. The backend is already merged, so build against the real API. You only need mock data if you want to preview error states you cannot easily trigger, such as `429` or expiry. Keep any mock block easy to delete.

---

## 10. Testing and acceptance

### Setup

```bash
python init_db.py
python -m pytest -q
python -m pytest tests/test_sharing_routes.py
python run.py
```

`init_db.py` only adds missing tables, so there is no need to delete `instance/app.db`. Use two accounts in two browsers (or one normal window and one private window). Add a third account C for the stolen-package demo. Use **synthetic data only**.

### Acceptance checklist (from the handoff)

- [ ] Requester A can request access to owner B, and both see the correct list entry.
- [ ] B selects 2 of 3 records and approval produces a copyable package.
- [ ] A unlocks with that package and **A's** password, and only the 2 selected records appear.
- [ ] Downloads, image previews, and personal-data display use `/sharing/...` endpoints only.
- [ ] Reject and revoke refresh the UI. Revoked access fails even after a prior unlock.
- [ ] Expiry, re-unlock, wrong password or package, `429`, login redirect, and CSRF errors all have usable feedback.
- [ ] No password persistence, no inline scripts, no assumed endpoints or response fields.

### End-to-end scenarios (PDF section 9, UI-relevant ones)

1. A requests B, B approves 2 of 3, A pastes the package and the correct password. A sees exactly 2 records. The image previews, the document downloads, and the personal data is readable.
2. Correct package, **wrong password** gives `422`, and nothing opens.
3. Third user C pastes A's package in their own account. This is rejected, because C is not the requester and C's private key cannot open it.
4. One character of the package changed gives `422`.
5. A package from request 1 used on request 2 is rejected (the request id and OAEP label do not match).
6. Before approve and unlock, A cannot learn B's file names, count, or sizes.
7. A opens B's `/storage/<id>/...` URL directly and gets `404`.
8. B deletes a shared original record, and the shared copy is removed too.
9. A cannot approve their own request, and other users cannot approve requests that are not theirs (`404`).

Also test: revoke after unlock, re-unlock, a share past `expires_at`, unlock after the 15-minute window, five wrong unlock attempts (`429`), and an expired session (login redirect).

### Security self-check for your code

- [ ] No `innerHTML` with server data.
- [ ] No inline `<script>` or `style=`.
- [ ] Password field cleared after use and not left in DOM, history, or storage.
- [ ] Key package not in localStorage, sessionStorage, cookies, or URLs.
- [ ] No `/storage/<id>` URL used for the requester.
- [ ] No automatic POST retries.
- [ ] No real personal or medical data in screenshots.

---

## 11. Demo and report deliverables

**Demo (about 5 minutes), run twice in a row without re-prep other than a data reset:**

1. A sends a request to B.
2. B approves 2 of 3 records and copies the key package.
3. A pastes the package, types their password, and sees the 2 records.
4. Scenario 3: C pastes A's package and is rejected, which shows a stolen package is useless.

Optional extras if time allows: revoke, and the expiry display.

**Report section "Screenshots and demo walkthrough" (your draft):**

- A **real** screenshot at every step. Never fabricate screenshots or results.
- Short caption per screenshot, in the order of the 8-step flow.
- Synthetic data only.
- Everyone on the team reviews all report sections, and you review the others too.

**Limitations to acknowledge with the team (PDF section 12):**

- The server is still trusted. Whoever holds `.env` and the database can open share keys.
- The requester's private key is decrypted on the server during unlock.
- The key package acts as a distribution channel and proof of private-key possession, because the server already stores `K`.
- The public key comes from the server database, with no out-of-band fingerprint check.
- A forgotten password means the private key is lost, so the user needs a new key pair.
- Shared copies duplicate data on disk.
- The owner's DES and RC4 copies from Assignment 1 are unchanged.
- Previously downloaded files cannot be withdrawn after revoke.

---

## 12. Pitfalls and rules

- Do not change API contracts or response field names (`nama`, `nik`, `alamat`, `tanggal_lahir`, and so on).
- Do not assume extra endpoints. There is **no** shared-file listing endpoint, notification, username search, server pagination, CSRF-token endpoint, or way to edit file selection after approval. After a page reload the file list is only available by unlocking again.
- Do not trim, normalize, or log the password.
- Do not infer expiry from status alone. Use `expires_at`.
- Do not parse non-JSON error bodies as JSON.
- Do not commit `.env`, `instance/app.db`, keys, or real data. **Do not use `git add .`**. Add files one by one. (`output/` is currently untracked and is not part of the work.)
- Do not use `wa.me` or `mailto:` buttons, fingerprints, or any other out-of-scope feature from the PDF's section 13.
- Keep Assignment 1 behavior intact. `python -m pytest -q` must stay green after your merge.

---

## 13. Quick reference

| Topic | Value |
|---|---|
| Share lifetime | 7 days from approval (`expires_at`) |
| Unlock window | 15 minutes (`unlocked_until`) |
| Unlock attempt limit | 5 failed per user and request per 15 min, then `429` + `Retry-After` |
| Key package max length | 2048 characters |
| Password max length | 1024 raw characters |
| Reason max length | 500 characters |
| Username format | 3 to 32 chars, `a-z 0-9 . _ -`, starts and ends alphanumeric |
| Files per approval | 1 to 100 unique integer IDs |
| Statuses | `pending`, `approved`, `rejected`, `revoked` |
| File kinds | `id_card`, `document`, `video`, `personal_data` |
| Previewable types | JPG and PNG (`<img>` to `/view`). Everything else uses download. |
| Backend code | `app/sharing/{routes,services,validation}.py`, `app/crypto/share.py` |
| Backend tests | `tests/test_sharing_routes.py` |
| Design spec | [design.md](design.md) |
