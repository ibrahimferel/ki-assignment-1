# MedVault — Design Specification

## 1. Purpose and source fidelity

MedVault is the provisional name for an English-language personal health vault: an interface for the project's existing account authentication, personal-data CRUD, and encrypted file storage. Medical imagery and language provide the theme; the application does not provide clinical advice, appointments, diagnosis, or treatment.

This document is the design deliverable. It does not implement the frontend, change backend contracts, add benchmark scripts, or draft the final report. Preserve existing uncommitted work when implementation begins.

### Reference inventory

The four user-supplied screenshots are the visual source of truth. Their original attachment filenames identify them even if temporary files are later removed:

| Reference | Attachment | Original composition |
| --- | --- | --- |
| 1: Hero | `codex-clipboard-a7fef84e-8290-4dcd-a63e-2e3a12c76c40.png` | Full-background portrait, transparent navigation, centered display headline, bright CTA, reassurance strip |
| 2: Results | `codex-clipboard-4d9787a5-8f9e-4eb7-8262-0c75d6cd7ebe.png` | Centered section introduction, three tabs, text card and split visual card |
| 3: Pricing | `codex-clipboard-1f7a9510-0e0f-45b6-99d5-935f75ea4941.png` | Two equal feature cards, one dark and one saturated with an ambient glow |
| 4: Solution | `codex-clipboard-13723263-0ef2-4b05-96c2-1ccfbcfac133.png` | Wide text card beside a portrait, three bottom highlights |

All measurements below are approximations inferred from the 1600 × 1200 screenshots, not verified source CSS. Preserve their visual hierarchy and relative geometry. The original font is unconfirmed; Inter is the implementation choice. References establish appearance, not product instructions or evidence for claims.

Keep the dark photographic treatment, generous negative space, rounded borders, centered introductions, oversized uppercase headings, and understated surface separation. Replace gym imagery, coaching language, red promotional accents, ratings, prices, scarcity messages, and testimonials with the specified vault content. Do not fabricate usage figures, clinical outcomes, certifications, or compliance claims.

## 2. Visual foundations

### Frame, grid, and spacing

- At 1600px viewport width, use a charcoal page canvas and a continuous inset near-black frame approximately 1480px wide, starting 60px from either side and 60px from the top. Give it a 5px border, 32px corner radius, and soft shadow. The references show separate screenshot frames; the actual landing page has one continuous frame around all sections.
- Center a content container with `max-width: 1200px`. At the reference width its left and right edges sit near x=200 and x=1400. Use 24px grid gaps.
- Desktop sections use 120–160px vertical padding. The hero is approximately 1060px tall including navigation at the reference viewport; allow content to determine height on smaller screens rather than clipping it.
- Cards have 24px corners, a 1px border, and 32–40px padding. Image frames use 10px inset padding and 20px inner corners. Buttons use 12px corners; compact badges use 8px corners.
- Use a spacing scale of 4, 8, 12, 16, 24, 32, 40, 56, 80, 120, and 160px. Prefer 24–32px between introductory elements and 48–56px before a main content grid.

### Color tokens

| Token | Value | Role |
| --- | --- | --- |
| `canvas` | `#191B1B` | Outside the frame |
| `background` | `#090C0D` | Page interior |
| `surface` | `#111718` | Cards and form panels |
| `surface-raised` | `#192326` | Hover surfaces and selected dark controls |
| `border` | `#253033` | Decorative card/frame boundaries |
| `control-border` | `#657D82` | Input boundaries that must remain visible |
| `text` | `#F4F7F7` | Main text |
| `text-muted` | `#B7C3C5` | Descriptions and metadata |
| `primary` | `#2DD4BF` | Main teal accent |
| `primary-deep` | `#0F766E` | Gradient endpoint and ambient lighting |
| `secondary` | `#38BDF8` | Supporting blue accents |
| `success` | `#4ADE80` | Completed operations |
| `danger` | `#F87171` | Errors and destructive actions |
| `on-accent` | `#062C2A` | Text on bright teal buttons |

Teal is the dominant accent; blue is secondary and green communicates success. Red is reserved for destructive or error states. Never rely on color alone to communicate state.

Primary buttons use a bright teal fill, dark text, a subtle inset highlight, and a soft teal shadow. Secondary buttons use raised dark surfaces and light text. Destructive confirmation uses a dark-red surface with readable light text and an explicit Delete label.

Use an accent-card background approximating `linear-gradient(145deg, #2DD4BF, #0F766E)`. Keep its descriptive text on dark inset surfaces or use dark text over a sufficiently light local fill; do not assume white body text is readable over bright teal. Verify contrast in the rendered implementation.

### Typography

Locally host Inter in WOFF2 format, subject to availability and its license; until available use `system-ui, -apple-system, "Segoe UI", sans-serif`. Do not load remote font services.

| Style | Desktop size / line height | Weight and treatment |
| --- | --- | --- |
| Hero | 76px / 1.12 | 700, uppercase, -0.04em tracking |
| Landing section heading | 60px / 1.1 | 700, uppercase, -0.035em |
| Feature-card headline | 48px / 1.2 | 700, -0.03em |
| Application page heading | 32px / 1.2 | 700, sentence case |
| Application card heading | 22px / 1.3 | 600, sentence case |
| Landing body | 20px / 1.65 | 400 |
| Application body and inputs | 16px / 1.5 | 400 |
| Metadata | 14px / 1.5 | 400 |
| Eyebrow / nav / button | 12–14px / 1.4 | 600, uppercase, 0.1em |

Keep body copy, field labels, filenames, and validation messages in normal case. Landing headings may fade from muted light gray at the top to white at the bottom, provided all text remains readable. The plus sign in the hero is teal. Dashboard numbers use 32px bold type, without the landing headline treatment.

### Lighting, imagery, and motion

- Hero photography fills its section using cover cropping, with the medical professional on the right half and subdued clinical context to the left. Apply a dark overlay around 65–80% opacity plus a bottom fade into the page background; text must remain readable across the full crop.
- The solution image is a portrait of a medical professional in a clinical environment. Keep natural skin tones, subdued cool surroundings, and a slight teal ambient glow behind the frame.
- Use locally served, licensed imagery depicting fictional or non-identifiable clinical contexts. Decorative photography must not depict an uploaded private record. Decorative images have empty alternative text; meaningful preview illustrations have descriptive labels.
- Assets to supply during implementation: a landscape medical photograph, a portrait medical photograph, the local font, and a small pulse-line brand mark. No asset is supplied by this documentation change. Use a solid dark fallback when photography is unavailable, preserving text and layout.
- Use small, consistent 20–24px outline icons for files, upload, download, lock, visibility, and navigation. Keep the pulse-line brand mark abstract rather than using a protected medical emblem.
- Transitions last approximately 160–200ms for hover, focus, and tab changes. Avoid parallax and looping decorative animation. Honor reduced-motion preferences by removing nonessential animation.

## 3. Landing page

Page order: **Hero (reference 1) → How It Works (reference 4) → Your Records (reference 2) → Storage Options (reference 3) → FAQ → Footer**.

### Hero — reference 1

Place a transparent navigation row near the top of the frame. Its inner width matches the 1200px content container. Left: a 40px teal mark and MedVault wordmark, followed by Features, How It Works, and FAQ anchor links. Right: Log In as a quiet text action and Create Account as a compact dark button. Omit social icons and booking actions.

Center the main content over the photograph. Begin with a small glowing teal dot and the factual eyebrow **PERSONAL HEALTH VAULT**. Allow approximately 40px before the headline. At desktop width, use these three lines:

> YOUR HEALTH + RECORDS  
> IN ONE PLACE  
> UNDER YOUR CONTROL.

Supporting copy, centered within approximately 620px:

> Keep your personal details and health documents organized, with encrypted storage and access through your account.

Use a 56px-high **Create Your Vault** button approximately 270px wide, with 32–40px above it. Signed-in visitors see **Open Your Vault**, linking to the dashboard. Keep approximately 100px before the lower reassurance strip: **Personal Data · Encrypted Files · Owner-Only Access**, accompanied by small outline icons. These labels describe implemented capabilities, not a medical certification.

### How It Works — reference 4

Use a 60/40 split: approximately 704px text card, 472px portrait frame, and a 24px gap. Target equal heights around 620px at the reference size. The text card uses 32px padding, with a subtle teal glow toward its right edge.

Eyebrow: **HOW IT WORKS**. Headline:

> KEEP YOUR RECORDS  
> WITHIN REACH.

Body copy:

> Create an account to organize your personal information and uploaded files in one place. Your records are linked to your account and stored using the project's encryption system.

> Add your details, upload a document, and retrieve the original file when you need it.

Anchor three evenly spaced highlights near the bottom: **01 Create** / Your account, **02 Store** / Details and files, **03 Retrieve** / Your original files. These replace numerical achievement claims. Crop the portrait to fill the adjacent image frame.

### Your Records — reference 2

Center the **YOUR RECORDS** outlined badge, then the heading:

> PERSONAL INFORMATION.  
> CLEARLY ORGANIZED.

Supporting copy:

> Keep personal details, documents, identity images, and videos together in your own vault.

Place three rounded tabs 48px below the description: **Personal Data**, **Documents**, and **Identity & Video**. Personal Data is initially selected. Selected tabs use a raised dark surface and light text; inactive tabs remain visibly actionable.

Below, preserve the approximately 628px left text card and 548px right preview card, separated by 24px. Target a minimum height of 350px. Left card content changes with the tab:

| Tab | Heading | Description |
| --- | --- | --- |
| Personal Data | Your details, together. | Save your full name, NIK, address, and date of birth. View or update a record when needed. |
| Documents | Documents, easy to find. | Upload PDF, Word, and Excel documents, then recover the original from an encrypted copy. |
| Identity & Video | More than documents. | Keep supported identity images and MP4 videos alongside your other files. |

The right card shows a designed fictional preview, not a live user record. Add **FICTIONAL DEMO** visibly. For personal data use “Alex Morgan,” a masked placeholder NIK, and generic field rows; for documents show `sample-health-document.pdf`; for media show `sample-identity.png` and `sample-video.mp4`. Preserve the reference's vertical visual division with two static columns labeled **Record** and **Stored copies**. The latter lists AES, DES, and RC4 as text. Do not implement a before/after slider or imply that encryption makes information anonymous.

### Storage Options — reference 3

Center the **YOUR VAULT** badge and heading:

> EVERY RECORD.  
> A CLEAR PLACE.

Supporting copy:

> Choose what to add. Keep your details and supporting files organized through the same account.

Place two equal-width cards in a 24px-gap grid. Target approximately 588px square cards at the reference width. Preserve the original padding and bottom-aligned buttons. Left card is dark; right card uses the teal gradient and surrounding glow.

| Element | Left card | Right card |
| --- | --- | --- |
| Badge | PERSONAL DATA | FILE STORAGE |
| Large title | Personal Details | Health Documents |
| Description | Your essential information, organized in one record. | Supporting documents and media, stored as encrypted copies. |
| Feature list | Full name; NIK; Address; Date of birth | Identity images: JPG/PNG; Documents: PDF/DOC/DOCX/XLS/XLSX; Videos: MP4; Original-file downloads |
| CTA | Add Personal Data | Upload a File |

For visitors, both buttons lead to registration. For signed-in users, they lead to the relevant application form. Do not imply one card is a paid tier or offers stronger encryption than the other.

### FAQ and footer

Use a compact dark accordion with four questions: **What can I store?**, **How do downloads work?**, **How large can an upload be?**, and **Which algorithms are used?** Answers reflect the integration rules below. Explain that AES, DES, and RC4 are coursework comparisons and that DES and RC4 are legacy algorithms unsuitable for protecting real sensitive medical information. This context belongs in the algorithm explanation, not in every task flow.

Footer: MedVault wordmark, “Personal records, thoughtfully organized,” and links to Features, How It Works, FAQ, and Log In. Do not add dead privacy-policy, support, or social links.

## 4. Application screens and components

### Shared application shell

Use the same continuous frame with a more compact 80px header and 40–56px top content padding. Brand left; Dashboard, Personal Data, and Files navigation in the center; current username and a POST Log Out button right. Mark the active destination with teal text and an underline or filled indicator. Use sentence-case headings and compact content spacing for everyday tasks.

During later implementation, keep `main.index` as the authentication redirect destination: show the landing page for anonymous visitors and the dashboard for authenticated users. Personal Data and Files are authenticated views; their page routing may be added without changing existing storage API URLs. Use `url_for` for routes and server-generated data attributes for JavaScript endpoint configuration.

### Login and registration

At desktop width use a two-column centered panel: a darkened medical photograph with a short welcome statement on the left, and a 420px-wide form on the right. Keep inputs at least 48px high. On mobile hide the decorative image and show a single form card.

- Login heading: **Welcome back**. Fields: Username and Password. Submit: **Log In**. Link: “New to MedVault? Create an account.”
- Registration heading: **Create your vault**. Fields: Username, Password, Repeat password. Submit: **Create Account**. Link: “Already have an account? Log in.”
- Reuse `LoginForm`, `RegisterForm`, `form.hidden_tag()`, existing autocomplete attributes, and server field errors. Display username/password helper text using the provided `limits` values, not duplicated magic numbers. Current registration limits are username 3–32 characters and password 10–128; server normalization and password policy remain authoritative.
- Preserve the intentionally permissive login field configuration: do not impose registration length or username-format constraints on login.
- Show a form-level error summary above the submit area and associated errors under affected fields. Keep the existing generic invalid-credentials message. Never repopulate passwords in a server response.
- Password visibility buttons are non-submit buttons with accessible Show/Hide labels and state. Disable repeat submissions while pending; use **Logging in…** or **Creating account…** and restore controls on failure.
- Registration success leads to login with the existing success flash. Respect server-validated `next` redirects. Rate-limited forms show the existing generic message and honor `Retry-After` without automatic resubmission.
- Do not add remember-me, email, password reset, or social sign-in controls; those capabilities are absent.

### Dashboard

Heading: **Your vault**. Subtitle: “Manage your personal details and stored files.” Primary actions: **Add Personal Data** and **Upload File**.

Use three summary cards for **Personal records**, **Uploaded files**, and **Original data size**. Derive counts and sums from the authenticated storage list. Original size includes all listed records and represents plaintext bytes, not encrypted disk usage or an allocated quota.

Below, show the newest five records with filename, readable category, original size, and actions. The list is already newest-first by ID; do not invent timestamps. For personal records use a safe summary such as “Personal record #12”; the list API does not return decrypted names or NIKs. The full Personal Data screen handles record details.

First-use state: **Your vault is ready** with a short explanation and both primary actions. Loading: labeled skeleton blocks with `aria-busy`. Load failure: **We couldn't load your records** and Retry; show unavailable values rather than zero counts. Populated state uses only actual API results, with a View All link to the Files view.

### Personal data list, view, and form

Filter the storage list by `kind=personal_data`. Rows expose View, Edit, Download, and Delete. Open a selected record through its personal-data endpoint before showing or editing its content. Do not decrypt all records automatically just to populate summaries.

Use a single-column form within a maximum 720px card. On desktop, Name and NIK may share a row; Address spans the card; Date of birth is below. Provide **Create Record** or **Save Changes**, plus Cancel. The detail view shows the same fields read-only with Edit and Download actions.

| Visible label | API field | Input and server rules |
| --- | --- | --- |
| Full name | `nama` | Required string; trimmed; 1–100 characters |
| NIK | `nik` | Required string; exactly 16 ASCII digits; numeric input mode, never a numeric input that loses leading zeroes |
| Address | `alamat` | Required textarea; trimmed; 1–1000 characters |
| Date of birth | `tanggal_lahir` | Required date; `YYYY-MM-DD`; valid date no later than today |

Send exactly these four fields as JSON. CSRF belongs in the request header, not in the JSON object. Summary snippets, if displaying an already-loaded NIK, show only its last four digits. Show the full NIK in the selected detail view and editable form only. Do not add diagnoses, medications, doctor assignments, or medical-history fields.

When saving fails, retain in-memory form input and show the error. On success refresh affected lists and counts, announce the result, and leave the editor. Cancel discards the unsaved edit and returns focus to the initiating control.

### File list and upload

The Files view lists all storage records with filters **All**, **Personal Data**, **Identity Images**, **Documents**, and **Videos**. Filtering is client-side over the returned authenticated list. Show filename, category, original size, and Download/Delete actions; personal-data entries also link to View/Edit. Do not show dates, encryption timings, or key metadata that the list API does not return.

The Upload File card contains a required category selector, a bordered drop zone backed by a labeled native file input, a selected-file summary, and **Upload File** / Cancel controls. Allow one file at a time. File acceptance follows category:

| Category label | `kind` | Extensions |
| --- | --- | --- |
| Identity image | `id_card` | `.jpg`, `.jpeg`, `.png` |
| Document | `document` | `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx` |
| Video | `video` | `.mp4` |

Update the input's `accept` hint when category changes, but keep the server as the validation authority. Show filename and size, not a sensitive file-content preview. Do not upload automatically on selection or drop.

Helper text: **One file per upload. The default request limit is 50 MiB, including upload overhead.** The server's configured request limit and the validation module's 50 MiB file cap both apply; the effective allowance is the stricter limit. Reflect configuration when rendering the helper; do not promise that a file exactly at the nominal request size will fit multipart overhead.

Pending text: **Uploading and encrypting…**. Disable duplicate submission and file changes until the request resolves. Use an indeterminate indicator; do not invent a percentage or claim completion before a successful response. On failure retain the selection where the browser permits, show the error, and offer manual retry. On success clear the picker, refresh records/counts, and announce **File added to your vault**.

### Download and delete

Download opens a small accessible dialog with the filename, a select labeled **Encrypted copy**, and **Download Original**. Options are AES (default), DES, and RC4. Include: “The selected copy is decrypted on the server and returned as the original file.” A short secondary note identifies DES and RC4 as legacy coursework options. No encryption-mode or key controls are exposed.

Use the existing download URL for the chosen uppercase algorithm. Prefer a native same-origin download link to avoid buffering a large decrypted file in browser JavaScript. Do not display a success toast claiming a native download completed; the page cannot reliably observe that. Download failures should retain the server's status semantics; friendly error presentation can be added while preserving statuses and attachment behavior.

Delete opens a keyboard-accessible confirmation: **Delete this record?** and “This removes the record and its encrypted copies.” Buttons: Cancel and **Delete Record**. Initial focus is Cancel; Escape closes the dialog; focus stays within it and returns to the trigger on dismissal. During deletion prevent repeat submission. After a 204 response remove the row, refresh counts, and announce **Record deleted**. On failure keep the dialog and its context available for retry.

### Shared feedback

Use success banners for completed changes, inline messages for field guidance, and a form-level alert for request failures. Use `role=status` for nonurgent updates and `role=alert` for errors. Preserve error text as text, never HTML.

Fetch handling must check redirects, HTTP status, and response content type before parsing JSON. An expired session can redirect to an HTML login page; show **Your session has expired. Log in again to continue.** and a login action rather than attempting JSON parsing. Reload after authentication to obtain a fresh CSRF token. Do not persist sensitive drafts or automatically replay mutations.

For invalid/expired CSRF, offer a page refresh with a clear draft-loss notice. For 413 show an upload-size explanation; for 422 show that the record could not be read or decrypted; for 404 show **Record unavailable**, without distinguishing a missing record from another user's record. Network failures retain local form state and offer manual retry. Backend storage messages currently include Indonesian; map recognized messages to English presentation copy and use a generic English fallback without altering backend responses.

## 5. Existing integration contracts

The source code is authoritative; the README currently predates the encryption/storage implementation. Preserve these interfaces. The frontend is Flask/Jinja plus locally served CSS and JavaScript, with no new SPA or client-side encryption requirement.

### Authentication

| Method and URL | Input | Result |
| --- | --- | --- |
| `GET/POST /auth/register` | Form: `username`, `password`, `confirm`, CSRF | Render form/errors; success redirects to login |
| `GET/POST /auth/login` | Form: `username`, `password`, CSRF; optional validated `next` query | Render form/errors; success redirects to accepted next URL or `main.index` |
| `POST /auth/logout` | CSRF | Clear session and redirect to login |

Reuse the authentication services, constants, server validation, throttle behavior, session lifetime, and safe redirects. No authentication API changes are required.

### Storage

All endpoints below require authentication; all POSTs require CSRF. URLs are existing API contracts, not proposed HTML page routes.

| Method and URL | Request | Success response |
| --- | --- | --- |
| `GET /storage/` | None | `200 {"items": [{"id": 12, "name": "sample.pdf", "kind": "document", "size": 1024}]}` |
| `POST /storage/upload` | Multipart `file` and `kind` | `201 {"id": 12}` |
| `POST /storage/personal` | JSON containing exactly the four personal fields | `201 {"id": 12}` |
| `GET /storage/<file_id>/personal` | None | `200` JSON object containing the four decrypted personal fields |
| `POST /storage/<file_id>/personal/update` | JSON containing exactly the four personal fields | `200 {"id": 12}` |
| `GET /storage/<file_id>/download/<algorithm>` | Uppercase `AES`, `DES`, or `RC4` in URL | Original-file attachment, `application/octet-stream` |
| `POST /storage/<file_id>/delete` | No domain payload | `204`, empty body |

Example fictional personal-data payload:

```json
{
  "nama": "Alex Morgan",
  "nik": "0000000000000000",
  "alamat": "Fictional demonstration address",
  "tanggal_lahir": "1995-01-15"
}
```

This example is only a format illustration, not a real identity. The backend creates AES, DES, and RC4 copies for each record and verifies recovered plaintext integrity. Algorithm choice is a retrieval choice, not an upload setting. The list response supplies no decrypted personal fields, creation timestamp, storage quota, or copy-level metadata.

### Security and asset boundaries

- Reuse existing `owned_select` / `get_owned_or_404` enforcement and storage services. Never send `owner_id`, keys, IVs, or storage paths from the UI. Ownership stays server-controlled.
- Every server mutation form includes a CSRF hidden field. Expose a page token through a server-rendered meta element for fetch requests, and send it as `X-CSRFToken` on every mutation. Do not manually set multipart `Content-Type`; the browser supplies its boundary. Personal JSON uses `Content-Type: application/json`.
- Use local external stylesheets and scripts. The current CSP permits same-origin resources and disallows inline scripts/styles and third-party assets. Avoid inline handlers, style attributes, remote fonts, and CDN dependencies; do not loosen the CSP for the design.
- Let Jinja escape server-rendered values and use text-safe DOM operations for dynamic filenames and errors. Keep decrypted records only in transient page memory. Do not put private data into localStorage, sessionStorage, IndexedDB, service-worker caches, analytics, URLs, or console logs.
- Keep the existing no-store response policy and POST logout. Retain the distinction between plaintext original-size totals and actual encrypted storage usage.

## 6. Responsive behavior and accessibility

| Viewport | Layout behavior |
| --- | --- |
| 1024px and above | Desktop grid; 1200px maximum content width; 76px hero and 60px section headings at wide sizes; frame margins shrink as needed to maintain usable content width |
| 768–1023px | 24px outer margins, 24px content gutters, 80px section padding, approximately 56px hero and 44px section headings; keep two columns where content remains readable |
| Below 768px | 16px outer margins, 16px content gutters, 56px section padding; stack all feature/auth grids; collapse navigation into an accessible menu; full-width primary actions; record tables become labeled cards |
| 375px target | 36–40px hero, 30–32px section headings, 20px card padding, 18px landing body, 16px inputs; reduced frame radius; no horizontal overflow |

Remove forced desktop heading breaks when they create awkward wrapping. Preserve the headline wording while allowing natural line wrapping. Tabs may wrap into rows; they must not overflow the viewport. On mobile the solution text precedes its image, the category description precedes its preview, and storage cards remain Personal Details then Health Documents.

- Meet WCAG AA text contrast and visible control-boundary contrast; measure actual foreground/background combinations, including gradients and photography.
- Use at least 44 × 44px touch targets. Give all fields visible labels, helper associations, and `aria-invalid` when appropriate.
- Provide a skip link and semantic header, navigation, main, section, and footer landmarks. Use one page H1 and an ordered heading hierarchy.
- Use a 2px blue focus ring with an offset on dark surfaces; never remove focus without a visible replacement.
- Implement tabs with tablist/tab/tabpanel semantics, selected state, and arrow-key navigation. Collapse navigation with a named toggle and `aria-expanded` state.
- Dialogs have accessible titles, focus containment, Escape behavior, and focus restoration. Native file picking remains available without drag-and-drop.
- Keep loading messages readable by assistive technology without repeating announcements. Respect reduced motion and avoid disabling page zoom.

## 7. Acceptance and later verification

### Documentation acceptance

- Each of the four screenshots is identified and translated into concrete geometry, copy, imagery, colors, and interaction behavior.
- The document covers landing, login, registration, dashboard, personal-data list/view/create/edit/delete, file list/upload/download/delete, and major success/error/empty/pending states.
- Proposed fields and user actions map to existing backend capabilities; illustrative content is visibly fictional. Future HTML views are distinguished from existing API contracts.
- The deliverable is this root-level document only. No application source, authentication policy, encryption behavior, schema, benchmark, or report is changed.

### Frontend implementation checklist

- [ ] Compare the 1600px desktop rendering against each reference for frame, alignment, line breaks, card proportions, typography, photography, and glow treatment.
- [ ] Inspect tablet and 375px mobile layouts for readable forms, reachable navigation, stacked cards, and horizontal overflow.
- [ ] Exercise keyboard navigation, tabs, menu, password toggles, dialogs, screen-reader feedback, contrast, and reduced motion.
- [ ] Verify registration success/errors, login success/generic failure, existing username/password limits, validated redirects, throttling, and POST logout.
- [ ] Create, view, update, and delete a fictional personal record; confirm exact JSON fields, NIK string handling, masking, and server validation.
- [ ] Upload each supported category; check empty/invalid files, size rejection, pending state, success refresh, and retry behavior.
- [ ] Download AES, DES, and RC4 copies and compare recovered file bytes with the original. Check missing/corrupted records without claiming false download success.
- [ ] Verify empty/populated lists, accurate counts and original-size totals, deletion cancellation/failure/success, and filtered records.
- [ ] Verify CSRF enforcement, expired-token handling, session-expiry redirects, and no cross-user access; preserve existing backend regression tests.
- [ ] Confirm no CSP violations, third-party asset requests, plaintext persistent storage, or sensitive console output.

### Chosen defaults

English UI; MedVault provisional branding; personal health vault positioning; teal-dominant accents; dark appearance only; fictional demonstrations; AES as the initial download selection; existing Flask/Jinja and API behavior preserved. Photography and font assets are acquired during frontend implementation, not by this document.
