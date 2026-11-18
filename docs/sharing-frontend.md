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

### Layout (second revision, design review)

The first version had two panels full of headings, tags and grey sub-text, and
an approved request was only a green badge. The page was reduced to:

- **One title row**: "Sharing", a Refresh button and one primary button,
  **Request access** (the form lives in a dialog, because it is used rarely).
- **Two clear choices**, shown as two side-by-side selector cards, each with a
  title and one line saying what it is for: **Review requests** ("People who want
  to see your records", where the user approves or declines) and **My requests**
  ("Records you asked to see", where the user unlocks). A teal number on a card
  counts requests that wait for the user: pending requests on "Review requests",
  approved-but-not-unlocked requests on "My requests". On first load the card
  with something waiting is opened.
- **One card per request.** The top of the card is a sentence ("You shared
  records with **name**"), the reason in quotes, and at most one highlighted
  **next-step line** telling the user what to do. A footer row, separated by a
  thin line, holds the dates on the left and the buttons on the right. The footer
  wraps on narrow screens, so buttons never run off the edge. No uppercase status
  badges, no section tags, no avatars.
- **Past requests** (declined, removed, expired) in a collapsed section, dimmed.
  When a tab has no open requests but has past ones, a single short line says so
  ("No requests are waiting for your review.") and the past list is opened once, so
  the tab is never an empty gap with a folded section underneath.

Wording of the rows (this is the whole state model the user sees):

| Who | State | Sentence | Next step shown | Actions |
|---|---|---|---|---|
| Owner | pending | "**name** asked to see your records" + chip "Needs your decision" | none | Approve, Decline |
| Owner | approved, active | "You shared records with **name**" | "Send name the key package so they can unlock the files." | Get key package, Remove access |
| Owner | declined / removed / expired | "You declined name", "You removed access for name", "name's access ended" | none | none |
| Requester | pending | "Waiting for **name** to respond" | none | none |
| Requester | approved, active | "**name** approved your request" + chip "Ready to unlock" | "Ask name for the key package, then unlock the files." | Unlock files |
| Requester | unlocked (window open) | same sentence | "Files are unlocked until 8:15 AM." | Open files, Unlock again |
| Requester | declined / removed / expired | "name declined your request", "name removed your access", "Your access to name's records ended" | none | none |

Within a tab, requests that need the user come first, then newest first.

## 4. What the page contains (and which requirement it covers)

| Component | Element(s) | Behaviour |
|---|---|---|
| Request access | `#request-dialog`, `#request-form` | Opened by the **Request access** button. Username and reason, client-side checks mirroring the server rules (3 to 32 chars `a-z0-9._-`, reason required, 500 max, live counter). Sends `POST /sharing/requests` with the username trimmed and lowercased. On success the dialog closes, a message is shown and the "My requests" tab opens. Clear texts for 400 and 404. |
| Requests lists | `#incoming-list`, `#outgoing-list`, tabs | One `GET /sharing/requests`. Loading, empty and error states appear as one centered line only when the list has nothing to show. Row wording and buttons: see the table above. |
| Owner approval picker | `#approve-dialog` | **Approve** opens it. Loads the owner's records from `GET /storage/` into a checklist, all ticked by default. Blocks sending when none are ticked (or more than 100). Sends `{file_ids}`. |
| Key-package step | `#package-dialog` | Opens right after approving, and later from **Get key package** (`GET .../key-package`). Title "Send the key package to name", one sentence explaining what to do with it, the text box, **Copy key package**, **Download .txt**, **Done**. |
| Unlock | `#unlock-dialog` | **Unlock files** opens it. Paste the package or choose a `.txt` file (`FileReader`), and the MedVault password (`type=password`). |
| Shared-files popup | `#shared-dialog` | Opens after a successful unlock, and from **Open files** while the unlock window is open. One meta line: "Access ends ... · Unlocked for m:ss". Per file: Download link, JPG/PNG `<img>` preview, personal-data "View details". |
| Remove access | `#revoke-dialog` | "Remove access for name?" and what it means (downloaded files stay with them), then `POST .../revoke`. |

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
  unlock again while the share is active. "Open files" only works while the
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
| demo-a to demo-b, "Second opinion on my scan" | approved, active | Unlock files (as demo-a), Get key package and Remove access (as demo-b) |
| demo-a to demo-b, "Insurance check" | revoked | revoked badge, past list |
| demo-a to demo-b, "Curious" | rejected | rejected badge, past list |
| demo-a to demo-b, "Old request" | expired (aged 8 days) | expired badge, no actions |
| demo-b to demo-a | pending | one account in both roles (demo-a approves or rejects) |
| demo-c to demo-b | pending | Decline; demo-c is also the "stolen package" user |
| demo-a to demo-b, "Approve me live" | pending | the live approve walkthrough |

demo-b owns five records (personal data, a real PNG that previews, a fake PNG
that shows the preview fallback, a PDF, an MP4); demo-a owns one personal record.

A running dev server caches templates. After pulling UI changes, restart
`python run.py`.
