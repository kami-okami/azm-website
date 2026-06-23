# CLAUDE.md — azm_secure_site

Business website for **عزم لتجارة قطع الغيار ومستلزمات الطرق والجسور** (AZM Supply).
Flask app deployed at https://www.azmsupply.com — Arabic RTL, Iraq market.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python / Flask 3.1.1 |
| Templating | Jinja2 (templates/) |
| Styling | Plain CSS (static/style.css, v41+) |
| Database | SQLite (messages.db — contact form submissions) |
| Production server | Gunicorn |
| Third-party | Meta Pixel + CAPI, Google reCAPTCHA v3, SMTP email |

---

## Project Layout

```
app.py                  — All backend logic (~896 lines)
static/
  style.css             — All styles (CSS variables, RTL, responsive)
  logo.svg              — Company logo
  img/hero/             — Responsive hero images (WebP + PNG, 640/1280/1920w)
  img/products/         — Product category images
  catalog/              — PDF catalog download
templates/
  base.html             — Master layout: nav, footer, Meta Pixel JS, CAPI JS
  home.html             — Hero, product overview, FAQ
  about.html            — Mission, vision, values
  products.html         — 6 product category cards
  catalog.html          — Accordion + PDF download
  contact.html          — Contact form (reCAPTCHA, phone validation)
  thank_you.html        — Success page + Lead event firing
  login.html            — Admin login
  admin_messages.html   — Admin inbox (paginated, modal viewer)
.env                    — All secrets (never commit)
requirements.txt        — Python dependencies
```

---

## Critical: Do Not Break These

### Meta Pixel & CAPI (tracking)
- **Pixel JS init** lives in `templates/base.html` inside the `=== BEGIN META PIXEL BASE ===` anchored block. Never delete or move it.
- **AZM helper script** (`azm.uuidv4`, `azm.getCookie`) lives in the `=== BEGIN AZM HELPERS ===` anchored block in `base.html`. CAPI wiring depends on it — if it disappears, all dedup eventIDs become `undefined` and Meta double-counts every event.
- **CAPI wiring block** (PageView dedup, Contact-on-link-click, ViewContent on /catalog, sessionStorage PII caching for event quality) lives in the `=== BEGIN CAPI WIRING ===` anchored block in `base.html`.
- **CAPI relay route** is `/capi/track` in `app.py` (see the `=== BEGIN CAPI RELAY ROUTE ===` block). Never remove it.
- **Server-side Lead event** fires inside the `/contact` POST handler in `app.py` (see the `=== BEGIN SERVER-SIDE LEAD EVENT ===` block).
- **Thank-you Lead dedup** — `templates/thank_you.html` fires a one-shot Lead event using a server-generated `event_id` stored in the session. The dedup logic must stay intact.
- All CAPI helper functions in `app.py`: `_sha256`, `_normalize_phone_for_capi`, `_extract_fbp_fbc_from_request`, `_send_to_capi`.
- `META_PIXEL_ID` and `META_CAPI_TOKEN` come from `.env` — never hardcode.

### SEO & Meta-ad previews (base.html)
- **Open Graph block** (`og:type`, `og:locale`, `og:title`, `og:description`, `og:url`, `og:image`) drives Facebook ad creative previews. Critical for Meta ads — if dropped, ads stop rendering rich previews.
- **Structured Data JSON-LD** (`Organization` + `LocalBusiness` schema with phone numbers, knowsAbout terms, contactPoints) drives Google rich results. Critical for SEO.
- **Canonical + hreflang block** prevents duplicate-content penalties.
- **Meta description block** (with Jinja fallback) drives page-level SEO snippets.

### Performance (base.html)
- **Font loading chain** (dns-prefetch, preconnect, async Changa/Tajawal load with swap) — affects FCP.
- **LCP preload** for responsive hero image — affects LCP score directly.
- **Stylesheet preload** — `style.css?v=N`. The version query `?v=N` may be bumped (it's a cache-buster, that's its job). Nothing else in the stylesheet block may be modified.

### Contact Form (contact.html)
- The `<form>` must POST to `/contact` and keep all `name="..."` field attributes unchanged.
- CSRF token hidden input must stay.
- reCAPTCHA widget must stay.
- Iraq phone validation runs both client-side (JS in contact.html) and server-side (app.py). Both must stay.

### Security features (app.py)
- CSRF token validation (contact, login, logout routes)
- Rate limiting: 3 contact POSTs / 60 sec per IP; 8 login attempts / 600 sec per IP
- reCAPTCHA v3 server-side verification
- Session hardening (HTTPOnly, SameSite=Lax, 8hr lifetime, Secure in production)
- Security headers (CSP, X-Frame-Options, etc.) in after_request hook

---

## Base.html Protected Anchors

Base.html uses the same `=== BEGIN <NAME> — DO NOT MODIFY ===` / `=== END <NAME> ===` anchor pattern as app.py. Any block wrapped in anchors is off-limits. Anything outside anchors is open for redesign.

### Anchored blocks (13 total — do not modify contents)

| Block | Purpose |
|-------|---------|
| `HEAD META` | charset, viewport, title, favicons, manifest |
| `META DESCRIPTION` | page-level SEO meta with Jinja fallback |
| `CANONICAL HREFLANG` | canonical URL + Arabic/x-default hreflang |
| `OPEN GRAPH` | Meta ad preview tags |
| `STRUCTURED DATA` | Organization + LocalBusiness JSON-LD |
| `FONT LOADING` | dns-prefetch, preconnect, async Changa/Tajawal |
| `LCP PRELOAD` | responsive hero image preload |
| `STYLESHEET` | style.css preload + link (only `?v=N` may be bumped) |
| `META PIXEL BASE` | fbq init script + noscript fallback img |
| `AZM HELPERS` | azm.uuidv4, azm.getCookie (CAPI depends on these) |
| `FLASH MESSAGES` | Flask flash rendering inside `<main>` |
| `MOBILE MENU SCRIPT` | initNav targets id="navToggle" + id="primaryNav" |
| `CAPI WIRING` | PageView/Contact/ViewContent client+server dedup |

### Open zones (Claude Code may redesign)

- `<header class="site-header">` — entire `<header>` element including brand, hamburger, nav links
- `<footer class="container footer">` — when ready, in a separate commit
- WhatsApp FAB block — restyling only; `{{ whatsapp_number }}` Jinja must be preserved

### Constraints inside the open `<header>` zone

When redesigning the nav, the following MUST be preserved:

- `id="navToggle"` on the hamburger button and `id="primaryNav"` on the nav element — the mobile menu JS (anchored block) targets these IDs by name. Rename them and the mobile menu silently dies.
- All nav links must use `{{ url_for(...) }}` — never hardcode paths like `/about`.
- The `{% if active_page == 'X' %}active{% endif %}` pattern on each nav link — drives active-state highlighting.
- The `{% if session.get('logged_in') %}` admin block — must keep the admin link AND the logout `<form>` with `<input type="hidden" name="_csrf" value="{{ csrf_token }}">` and `action="{{ url_for('logout') }}"`.
- The brand `<picture>` element — must keep both `<source type="image/svg+xml">` and the `<img>` fallback. Must keep `width="204" height="68"` to prevent CLS.
- The `.site-title` (company name) and `.site-subtitle` (Arabic tagline) text content.

### Sanity check

After any base.html anchor edit, verify both counts match:

```powershell
Select-String -Path templates/base.html -Pattern "=== BEGIN" | Measure-Object | Select-Object Count
Select-String -Path templates/base.html -Pattern "=== END" | Measure-Object | Select-Object Count
```

Both must return 13. Mismatch means an orphaned anchor and Claude Code's pattern matching will fail.

---

## Safe to Edit (Frontend Work)

| What | Where | Rule |
|------|-------|------|
| All visual styles | `static/style.css` | Open |
| Page structure & content | `templates/home.html`, `about.html`, `products.html`, `catalog.html`, `contact.html`, `thank_you.html` | Open (preserve Jinja blocks, form attrs, tracking events inside the page) |
| Header markup | `<header>` block in `base.html` | Open, with constraints (see Base.html Protected Anchors above) |
| Footer markup | `<footer>` block in `base.html` | Open |
| WhatsApp FAB markup/styling | base.html FAB block | Open; preserve `{{ whatsapp_number }}` |
| Product images | `static/img/products/` | Swap freely |
| Hero images | `static/img/hero/` | Keep srcset filenames OR update both HTML and files together |
| Fonts | Inside anchored `FONT LOADING` block | Protected — do not change without explicit unlock |

For any file with `=== BEGIN === / === END ===` anchors: edits outside anchored blocks are allowed; edits inside anchored blocks are not.

---

## Frontend Rebuild Workflow

- All rebuild work happens on the `frontend-rebuild` branch.
- `main` stays untouched until the rebuild is smoke-tested and merged.
- Commit per page. Minimum two commits per page: one after Stitch integration, one after Impeccable polish.
- Never deploy `frontend-rebuild`. Local test only until merge.
- Base.html changes affect every page — after any base.html edit, smoke-test ALL pages, not just the one being rebuilt.

---

## Before Any Rebuild Edit (Echo Gate)

Before editing any template or stylesheet during the rebuild, echo back:

1. The full protected list from "Critical: Do Not Break These" (Pixel, CAPI, AZM helpers, OG, structured data, canonical, meta description, font loading, LCP preload, stylesheet rules, contact form fields, CSRF, reCAPTCHA, security headers).
2. The list of `=== BEGIN === / === END ===` anchors in app.py (CAPI HELPERS, SERVER-SIDE LEAD EVENT, CAPI RELAY ROUTE, SECURITY HEADERS).
3. The list of `=== BEGIN === / === END ===` anchors in base.html (13 anchors — see Base.html Protected Anchors).
4. The open zones in base.html (header, footer, FAB) and the constraints inside the header zone.

Quote anchor names verbatim. Do not paraphrase. If you cannot list them from memory, re-read this file before proceeding.

---

## Smoke Test After Each Rebuilt Page

### Before testing

1. Verify only one or two `python.exe` processes are running (one Flask parent + one debug reloader). Multiple Python processes mean ghost Flask instances serving stale templates:
```powershell
   Get-Process python | Format-Table Id, ProcessName, StartTime
```
   If more than two: `Get-Process python | Stop-Process -Force`, then restart Flask.
2. Verify file changes saved to disk before testing. After any template edit:
```powershell
   Select-String -Path templates/<file>.html -Pattern "<expected_class_or_marker>"
```
   If the expected content isn't in the on-disk file, the editor buffer is unsaved. Ctrl+S, re-verify.

### Functional smoke test

1. `flask run`
2. Open in incognito (extensions disabled, no cache)
3. Page renders correctly
4. Meta Pixel Helper → PageView + ViewContent fire on load (ViewContent only on `/catalog`)
5. DevTools Console: `typeof fbq` returns `"function"`
6. Submit contact form → Pixel Lead fires; `/capi/track` returns 200
7. `/thank-you` → one-shot Lead fires exactly once
8. Form fields POST with original `name=` values intact
9. Mobile viewport (DevTools device emulation) → hamburger opens nav, links close nav on click, Escape key closes nav

### After base.html changes

Run the functional smoke test against EVERY page, not just the one being rebuilt:
- `/`, `/about`, `/products`, `/catalog`, `/contact`, `/thank-you`, `/login`, `/admin/messages` (logged in)

Only after all pages pass: commit. Only after all pages pass on multiple commits: merge.

---

## Diagnostic Principles

When something looks wrong, follow these rules before sending Claude Code back for a "fix" or rolling back to an earlier commit.

### Evidence before theories
- "It looks the same" is a feeling. `<section class="X">` in DevTools Elements is evidence. Lead with evidence.
- Screenshot the rendered DOM (Elements panel) before describing a problem.
- Run `git diff` and `Select-String` on the actual file before assuming a tool failed.

### When the browser shows markup that doesn't exist on disk
The bug is NOT browser cache. Browser cache styles existing markup; it cannot invent HTML class names. Three real possibilities, in order of likelihood:

1. **Ghost Flask process** — old `flask run` instance still bound to port 5000 serving a stale template snapshot from memory. Most common on Windows because Ctrl+C doesn't always kill the debug reloader child. Check with `Get-Process python`.
2. **Wrong template file resolved** — Flask is rendering a different `home.html` than the one being edited. Check with `Get-ChildItem -Recurse -Filter "*.html"`.
3. **Unsaved editor buffer** — file modified in VS Code but never saved to disk. Check with `Select-String` from PowerShell.

The browser is not lying. The server is.

### Save-then-verify
After editing any protected file, before claiming the edit is done:
1. Ctrl+S in editor (watch the dirty-state indicator clear).
2. `Select-String -Path <file> -Pattern "<expected>"` from PowerShell.
3. Only after the terminal confirms the content is on disk: proceed.

The terminal is the source of truth, not the editor view.

### Don't redo before diagnosing
If Claude Code's output looks wrong, the first move is `git status` + `git diff --stat` + `Select-String`, NOT "try again." Asking Claude Code to redo the change without first identifying what's actually on disk layers changes on top of unresolved bugs and makes the diff unreadable.

---

## Routes Reference

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/` | GET | — | Home page |
| `/about` | GET | — | About page |
| `/products` | GET | — | Products page |
| `/catalog` | GET | — | Catalog + PDF download |
| `/contact` | GET/POST | — | Contact form |
| `/thank-you` | GET | — | Success page |
| `/login` | GET/POST | — | Admin login |
| `/logout` | POST | Session | Admin logout |
| `/admin/messages` | GET | Session | Message inbox |
| `/admin/email-test` | GET | Session | Test SMTP config |
| `/capi/track` | POST | — | Browser → Meta CAPI relay |
| `/robots.txt` | GET | — | SEO |
| `/sitemap.xml` | GET | — | SEO |

---

## Environment Variables (.env)

```
FLASK_SECRET              — Flask session secret key
ADMIN_USER                — Admin username
ADMIN_PASSWORD_HASH       — pbkdf2:sha256 hash of admin password
RECAPTCHA_SITE_KEY        — Google reCAPTCHA v3 site key
RECAPTCHA_SECRET_KEY      — Google reCAPTCHA v3 secret
META_PIXEL_ID             — Facebook/Meta Pixel ID
META_CAPI_TOKEN           — Meta Conversions API access token
META_GRAPH_VERSION        — Meta Graph API version (e.g. v20.0)
META_TEST_EVENT_CODE      — (optional) Meta test event code for debugging
FACEBOOK_URL              — Facebook page URL
WHATSAPP_NUMBER           — WhatsApp number in E.164 (e.g. 9647802280589)
WHATSAPP_MESSAGE          — Default WhatsApp message (Arabic)
FLASK_ENV                 — "development" or "production"
SQLITE_PATH               — (optional) Override DB path (used on Render.com)
EMAIL_HOST / EMAIL_PORT / EMAIL_USER / EMAIL_PASS / EMAIL_TO — SMTP config
```

Never commit `.env`. It is in `.gitignore`.

---

## Database

SQLite table `messages`:
```sql
id, name, phone, email, subject, message, created_at, ip
```
- Auto-created on first request via `init_db()` in app.py.
- Missing columns are added automatically (backward-compatible migration).
- Admin inbox paginates 20 rows per page.

---

## Running Locally

```powershell
# Activate venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run dev server
flask run
# or
python app.py
```

App runs at http://127.0.0.1:5000 in development mode.

After a Ctrl+C, verify Flask actually died:
```powershell
Get-Process python | Format-Table Id, StartTime
```
If processes remain, `Get-Process python | Stop-Process -Force` before restarting.

---

## Deployment

- Platform: Render.com (or any Gunicorn-compatible host)
- Production command: `gunicorn app:app`
- Set `FLASK_ENV=production` in env vars on host
- Canonical URL enforced: https://www.azmsupply.com (redirects non-www and HTTP)

---

## Language & Locale

- Site language: **Arabic (RTL)**
- All templates use `dir="rtl"` and `lang="ar"`
- Fonts: Changa (headings), Tajawal (body) — both Google Fonts, Arabic-capable
- Phone numbers: Iraq format (075x/077x/078x/079x), normalized to E.164 (964XXXXXXXXX) for CAPI
- Do not change text direction or font family without testing Arabic rendering

---

## Pending Pages

### `/clients` — clients page (currently a stub)

The `/clients` page is currently a stub ("coming soon" message).

When real client names are ready:

- Replace the stub section in `templates/clients.html` with the full client
  logos grid + gallery design from the Stitch export (see `frontend-rebuild`
  branch history or Stitch source).
- Prioritize repeat buyers — they're the highest-trust signals.
- Categorize each as "جهة حكومية" or "شركة مقاولات".
- Get explicit permission from each client before listing them (a WhatsApp
  message asking is enough; save the confirmation).
- Add real photos to `/static/images/clients/` for any logos used.
- Wire the nav/footer عملاؤنا placeholders (`href="#"` → `url_for('clients')`)
  once the page is real — this requires editing the otherwise-final base.html.