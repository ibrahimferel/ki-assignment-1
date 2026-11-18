# Sharing frontend (Assignment 2, Member 4): change log and explanation

This file records everything Member 4 added or changed, and why. It is the
companion to [`project.md`](../project.md) (the plan) and
[`sharing-api-handoff.md`](sharing-api-handoff.md) (the backend contract).
Update it whenever the sharing UI changes.

## 1. Summary

The backend for sharing (Members 1 to 3) already worked but had no screens.
Member 4 added a new authenticated page, **`/sharing`**, linked from the vault.
It uses only the existing JSON API; no backend contract was changed and no
crypto runs in the browser.

Placement decision: a **separate linked page** instead of more panels on the
vault page. The vault page is already long, and a separate page keeps the
sharing JavaScript and CSS apart from `storage.js`.

## 2. Files added or changed

| File | Status | What it is |
|---|---|---|
| `app/templates/sharing.html` | new | The page: request form, two request lists, shared-files panel, four dialogs. |
| `app/static/js/sharing.js` | new | All behaviour. Talks to `/sharing/requests/...` and `/storage/`. |
| `app/static/css/sharing.css` | new | Styles for the new parts. Reuses `storage.css` for frame, panels, buttons, dialogs. |
| `app/placeholder.py` | changed | Added the `GET /sharing` page route (`main.sharing_page`, `@login_required`). |
| `app/templates/placeholder_home.html` | changed | One nav link, "Sharing", in the vault header. |
| `scripts/seed_sharing_demo.py` | new | Creates synthetic demo users, records and requests in every state (section 11). |
| `tests/test_sharing_page.py` | new | 4 tests for the page shell (see section 6). |
| `tests/test_auth_routes.py` | changed | Added `("/sharing", ("GET",))` to the pinned route table. |
| `project.md` | new | The Member 4 plan and reference (written earlier). |
| `docs/sharing-frontend.md` | new | This file. |

Not touched: anything under `app/sharing/`, `app/crypto/`, `app/storage/`,
`app/models.py`, `app/security_headers.py`.

## 3. The page route

`GET /sharing` in `app/placeholder.py` renders `sharing.html`. It requires
login, so the security-inventory test treats it like every other private
page. It carries no data itself: the page loads, then `sharing.js` fetches
everything from the JSON API. Page markup passes three URLs to the script
through `data-*` attributes on `#sharing`, so no URL is hard-coded in JS
(`data-requests-url`, `data-records-url`, `data-login-url`).

The CSRF token comes from the logout form in the page header
(`<input name="csrf_token" value="{{ csrf_token() }}">`); `sharing.js` reads it
at the time of each POST.

### Layout (revised after first review)

Two separate panels side by side (stacked under 1000 px): **YOU ASK** on the
left (the request form, then "Your requests", where Unlock lives) and **ASKED OF
YOU** on the right (Incoming requests, where Approve, Reject and Revoke live).
Each list puts requests that still need action first (pending, then active
shares) and moves finished ones (rejected, revoked, expired) into a collapsed
"Past requests (n)" section. A one-line summary above each list says what needs
attention, for example "2 requests are waiting for your decision". The first
version put both lists in one long panel, which buried Outgoing and mixed
finished requests with live ones.

## 4. What the page contains (and which requirement it covers)

| Component | Element(s) | Behaviour |
|---|---|---|
| Request access form | `#request-form` | Username and reason, client-side checks mirroring the server rules (3 to 32 chars `a-z0-9._-`, reason required, 500 max, live counter). Sends `POST /sharing/requests` with the username trimmed and lowercased. Success message; clear texts for 400 and 404. |
| Incoming and Outgoing lists | `#incoming-list`, `#outgoing-list` | One `GET /sharing/requests`. Shows counterpart username, reason, status badge, and dates. Has loading, empty and error states. Buttons depend on status: see the matrix below. |
| Owner approval picker | `#approve-dialog` | Loads the owner's records from `GET /storage/` into a checklist, all ticked by default. Blocks sending when none are ticked (and over 100). Sends `{file_ids}`. |
| Key-package panel | `#package-dialog` | Read-only box with the full package, **Copy package**, **Download .txt**. Reopened later with **Show key package** (`GET .../key-package`). Hint text says only what is true: the text is encrypted and only the requester can open it with their password. |
| Requester unlock form | `#unlock-dialog` | Paste the package, or choose a `.txt` file (`FileReader`). Password field (`type=password`) for the requester's own account password. |
| Shared-files popup | `#shared-dialog` | A popup (not a panel at the bottom of the page) opened after a successful unlock. Per file: Download link, JPG/PNG `<img>` preview, personal-data "View details". Shows share expiry and a live unlock countdown. While the unlock window is open, the request row in "Your requests" shows **View files** (reopens the popup with no password) and **Unlock again**; after the window ends it goes back to **Unlock**. |
| Owner revoke | `#revoke-dialog` | Confirmation (states that downloaded files cannot be withdrawn), then `POST .../revoke`. |

### Button matrix (what the lists show)

| Status | Incoming (I am owner) | Outgoing (I am requester) |
|---|---|---|
| pending | Approve, Reject | none |
| approved, active | Show key package, Revoke | Unlock; or View files + Unlock again while the 15-minute unlock window is open |
| approved, past `expires_at` | none (badge "expired") | none (badge "expired") |
| rejected / revoked | none | none |

Expiry is computed in the browser from `expires_at`, because the server keeps
the status `approved` after expiry.

## 5. How `sharing.js` works

Everything is inside one function scope; no globals. Main parts:

- **`api(url, {method, body, messages})`**: the single place that talks to
  the server. It adds `X-CSRFToken` to POSTs, sends JSON with
  `credentials: "same-origin"`, and handles every response kind from the
  handoff: network failure; `response.redirected` (login redirect, then sends
  the user to the login page); `204` (no body); non-JSON error bodies (a 400
  that is not JSON is treated as a CSRF failure: "This page has expired");
  `Retry-After` on 429. It **never retries** a request. Callers pass friendlier
  per-action messages for 400, 404 and 422.
- **`busy(button, task)`**: disables a button while its request is in flight and
  re-enables it afterwards. Used for every action button.
- **`loadRequests()`**: reloads both lists. A counter drops stale answers if two
  loads overlap. It is called after create, approve, reject, revoke, and after
  failures that suggest the server state changed (400/404), because the server
  may already have committed an action.
- **Dates**: parsed from UTC ISO strings ending in `Z`; microseconds are cut to
  milliseconds because browsers only read three digits reliably.
- **Unlock**: password sent exactly as typed (no trim). The password field is
  cleared in a `finally` block after every attempt. The package field is
  cleared when the dialog closes. On `429` the Unlock button is disabled for
  `Retry-After` seconds with a countdown; this lock lives in memory only.
- **Shared files**: the unlock response is kept in memory in a map keyed by
  request id (`unlocked`), because the server has no endpoint that lists a
  share's files. `openShared()` draws the popup from that map. A one-second
  `tick()` updates the countdown and drops unlocks whose 15-minute window or
  share has ended: it closes the popup with a message and swaps the row's
  buttons back. List refreshes do the same check, so a revoke is noticed. The
  popup is emptied (previews removed) whenever it closes, including with Esc.
- **Previews** use `<img src=".../view">` with an `error` handler. **Downloads**
  are plain links to `.../download`, as the handoff specifies. **Personal data**
  is fetched as JSON and drawn with `textContent`.

## 6. Security and rule compliance

| Rule from the plan and handoff | How it is met |
|---|---|
| No inline scripts or styles (CSP) | One external script and stylesheet. `tests/test_sharing_page.py` asserts no inline `<script>` code, no `style=` and no `on...=` attributes. DevTools showed no CSP violations during the run. |
| Server text only via `textContent` | All lists, dialogs and the personal-data viewer use `textContent`; there is no `innerHTML` in the file. |
| Password never persisted | Not in a URL, cookie, `localStorage` or `sessionStorage`. Cleared after each attempt and when the dialog closes or the page returns from the back/forward cache. |
| Key package not persisted | Only in a dialog text box while it is open; cleared on close. Not in storage, cookies or URLs. |
| No automatic POST retries | `api()` has no retry logic. After a failure the UI refreshes state first. |
| Never use owner `/storage/...` URLs for the requester | Requester reads use only `/sharing/requests/<id>/files/<file_id>/...`. `/storage/` is called only by the owner's approval picker. |
| Do not depend on error text | Handling is by status code and content type. Server message text is never shown or parsed. |
| English UI, MedVault style | Text is English; classes and colors come from `storage.css` and `design.md`. |

## 7. Tests

`tests/test_sharing_page.py`:

1. The page redirects to login when signed out.
2. The signed-in page has the CSRF input, the `data-*` URLs, and links the new script and stylesheet.
3. The page has no inline script code, `style=` or event-handler attributes.
4. The vault page links to `/sharing`.

`tests/test_auth_routes.py`: the pinned route table now includes `/sharing`.

Run:

```bash
python -m pytest -q tests/test_sharing_page.py tests/test_auth_routes.py tests/test_security_inventory.py
```

### Full-suite result (17 Nov 2026, Windows)

1573 passed, 14 skipped, 6 failed. None of the failures is caused by this work:

- 4 in `tests/test_init_db.py` fail on this Windows account with
  `WinError 1314` (creating a symlink needs a privilege the account lacks).
  They fail the same way with all Member 4 changes stashed.
- 2 (`test_login_key.py`, `test_models.py`) failed once with an unclosed SQLite
  connection warning and passed when re-run, so they are flaky and unrelated.

## 8. Manual verification done

A throwaway database (users `demo-a`, `demo-b`, synthetic records) was served on
port 8765. `127.0.0.1` and `localhost` were used as two separate browser
sessions (cookies are per host). Result of each check:

| Check | Result |
|---|---|
| A sends a request (valid and invalid input) | Works; invalid input gets a clear message. |
| B sees it, opens the picker, submits with nothing ticked | Blocked with a message; nothing sent. |
| B approves 2 of 3 records | Package of 545 characters shown; list shows the new status. |
| A unlocks with a wrong password | Generic message; password field cleared. |
| A unlocks with the package of another request | Same generic message. |
| A unlocks correctly | Only the 2 selected records appear, with expiry and unlock countdown. |
| Personal-data viewer | Shows all four fields. |
| Image preview (a real synthetic PNG) | Displays. A 33-byte fixture "PNG" is not a decodable image, so the fallback message shows instead. |
| B revokes | B's list updates; A's next file call returns 404, which is handled, and a refresh locks the panel. |
| Five wrong unlocks | The sixth returns 429; Unlock is disabled with a countdown. |
| Invalid CSRF token | "This page has expired. Reload the page and try again." |
| Session ended on the server, then Refresh | Browser is sent to the login page. |
| Mobile width (375 px) | No horizontal scroll. |

Not yet done: the PDF's scenarios 3 (user C pastes A's package), 4 (one
character changed), 6 to 9 in two real browsers, the 15-minute and 7-day
expiry paths with real time passing, and the real screenshots and walkthrough for
the report. Download links were checked for the right `href` but a browser
download was not saved and compared by hash.

## 9. Known limitations and notes

- Plain download links show raw JSON in the browser if the server returns an
  error. The handoff asks for normal links; a `fetch`-and-save version would give
  friendlier errors but holds the file in memory.
- After a reload the shared-file list is gone (no listing endpoint exists, and
  the list is deliberately not saved in browser storage). The requester must
  unlock again while the share is active. "View files" only works while the
  unlock window is open and the page has not been reloaded.
- If the owner revokes while the popup is open, the popup closes the next time
  the requester opens a file or the list refreshes, not instantly.
- The unlock lock after a 429 is per page load, in memory. The server still
  enforces its own limit after a reload.
- Browser clock differences can make the expiry and countdown display a little
  early or late. The server is the authority and answers 404 when it has ended.
- Sessions use "strong" protection, so changing the browser's user agent (for
  example by switching to mobile emulation) logs you out.

## 10. Remaining work

- Run the full two-browser scenarios on every team member's laptop.
- Take real screenshots for the report section "Screenshots and demo
  walkthrough", and rehearse the 5-minute demo twice in a row.
- Optional: a `fetch`-based download that shows friendly errors.

## 11. Demo data

`scripts/seed_sharing_demo.py` creates synthetic data through the real code, so
the crypto is real. It writes to the database the app is configured for (the
one `python run.py` uses) and prints that path first. It only adds users named
`demo-a`, `demo-b`, `demo-c` (password printed at the end), and does nothing if
`demo-a` exists. If it fails part-way it removes the demo users it made.

```bash
python scripts/seed_sharing_demo.py
```

| Request | State | Use it to test |
|---|---|---|
| demo-a to demo-b, "Second opinion on my scan" | approved, active | Unlock (as demo-a), Show key package and Revoke (as demo-b) |
| demo-a to demo-b, "Insurance check" | revoked | revoked badge, past list |
| demo-a to demo-b, "Curious" | rejected | rejected badge, past list |
| demo-a to demo-b, "Old request" | expired (aged 8 days) | expired badge, no actions |
| demo-b to demo-a | pending | one account in both roles (demo-a approves or rejects) |
| demo-c to demo-b | pending | Reject; demo-c is also the "stolen package" user |
| demo-a to demo-b, "Approve me live" | pending | the live approve walkthrough |

demo-b owns five records (personal data, a real PNG that previews, a fake PNG
that shows the preview fallback, a PDF, an MP4); demo-a owns one personal record.

A running dev server caches templates. After pulling UI changes, restart
`python run.py`.
