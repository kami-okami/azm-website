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
- **Pixel JS init** lives in `templates/base.html` inside a clearly marked `=== META Pixel` script block. Never delete or move it.
- **CAPI browser endpoint** is the `/capi/track` route in `app.py` (see the === BEGIN CAPI RELAY ROUTE === block in app.py). Never remove it.
- **Server-side Lead event** fires inside the `/contact` POST handler in `app.py` (see the === BEGIN SERVER-SIDE LEAD EVENT === block in app.py).
- **Thank-you Lead dedup** — `templates/thank_you.html` fires a one-shot Lead event using a server-generated `event_id` stored in the session. The dedup logic must stay intact.
- All CAPI helper functions in `app.py`: `_sha256`, `_normalize_phone_for_capi`, `_extract_fbp_fbc_from_request`, `_send_to_capi`.
- The `META_PIXEL_ID` and `META_CAPI_TOKEN` come from `.env` — never hardcode them.

### Contact Form
- The `<form>` in `templates/contact.html` must POST to `/contact` and keep all `name="..."` field attributes unchanged.
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

## Safe to Edit (Frontend Work)

| What | Where |
|------|-------|
| All visual styles | `static/style.css` |
| Page structure & content | `templates/home.html`, `about.html`, `products.html`, `catalog.html` |
| Header/footer HTML | `templates/base.html` — edit HTML structure, leave all `<script>` blocks alone |
| Product images | `static/img/products/` — swap freely |
| Hero images | `static/img/hero/` — keep the srcset filenames or update both HTML and files together |
| Fonts | Change Google Fonts import in base.html `<head>` |

---

## Frontend Rebuild Workflow

- All rebuild work happens on the `frontend-rebuild` branch.
- `main` stays untouched until the rebuild is smoke-tested and merged.
- Commit per page. Minimum two commits per page: one after Stitch
  integration, one after Impeccable polish.
- Never deploy `frontend-rebuild`. Local test only until merge.

---

## Before Any Rebuild Edit

Before editing any template or stylesheet during the rebuild, echo the
full protected list back (Pixel script block, CAPI helpers, CAPI relay
route, server-side Lead event, thank-you dedup, form `name=` attributes,
CSRF token, reCAPTCHA widget, security headers). If you cannot list it
from memory, re-read this file before proceeding.

---

## Smoke Test After Each Rebuilt Page

1. `flask run`
2. Page renders correctly
3. Meta Pixel Helper → PageView + ViewContent fire on load
4. Submit contact form → Pixel Lead fires; `/capi/track` returns 200
5. `/thank-you` → one-shot Lead fires exactly once
6. Form fields POST with original `name=` values intact

Only after this passes: commit. Only after all pages pass: merge.

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
