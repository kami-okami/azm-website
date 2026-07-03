# TODO — azm_secure_site

## Product images (products page rebuild)

The products page (`templates/products.html`, frontend-rebuild) now ships
7 real-photo cards from `static/img/products/` (all `.jpg`) and reuses the
home hero image for the products-page hero.

- [x] `static/img/products/track-pads.jpg` — لباد جنزير للمعدات الثقيلة (track pads / heavy-equipment category) — added 2026-07-03
- [x] `أسنان دلاء الحفارات` (bucket teeth), `قطع غيار المحركات` (engine parts),
      `رؤوس ومعدات حفر الأرضيات` (drilling picks) — 3 new cards added 2026-07-03
      using photos that were sitting unused in the repo.
- [ ] Dedicated products-hero photo instead of reusing the home hero image.
      Deferred by choice (2026-07-03) — not blocking, revisit when a real
      products-specific photo is available.

### Notes
- The Stitch design originally referenced 5 images under `static/images/products/`
  (`hero.jpg`, `bridge-bearings.jpg`, `expansion-joints.jpg`, `milling-bits.jpg`,
  `track-pads.jpg`). The project convention is `static/img/products/`, and real
  matching photos already exist, so they were wired up instead of creating
  broken placeholders:
  - hero → `img/hero/hero-1280.{webp,png}`
  - bridge bearings → `img/products/elastomeric-bearings.jpg`
  - expansion joints → `img/products/expansion-joints.jpg`
  - milling bits → `img/products/road-rehab.jpg`
- 2026-07-03: the 3 bridge/road photos above were originally oversized PNGs
  (1.8–2.3MB each at 1184–1344px wide) despite displaying at ~540px max in a
  card — re-encoded to ~1000px JPEGs (quality 82) for the mobile-data-first
  requirement in PRODUCT.md. `ground-drilling-picks.png` (904KB) was the same
  issue and got the same treatment → `ground-drilling-picks.jpg`.

- In Render dashboard → your service → Environment tab, confirm:
  1. FLASK_ENV=production (NOT development)
  2. RECAPTCHA_ALLOWED_HOSTS includes azmsupply.com and www.azmsupply.com
     but does NOT include localhost or 127.0.0.1
  3. EMAIL_* vars are all set with the production App Password
  4. No plaintext ADMIN_PASSWORD, only ADMIN_PASSWORD_HASH

  CLEANUP — not urgent:
- Audit @app.context_processor in app.py (around line 227). If a
  context processor for whatsapp_number / whatsapp_text_encoded /
  facebook_url exists, those don't need to be passed manually in
  every render_template call. ~8 redundant lines to remove.

LESSON LEARNED — workflow:
- Always tell Claude Code "this is a plain CSS codebase, not Tailwind"
  in prompts, even if the source HTML uses Tailwind classes. Don't
  rely on Claude Code to infer the project's CSS system.
- Always read the full diff before approving, not just the summary.
  Claude Code may make undisclosed adaptations that match its assumptions.