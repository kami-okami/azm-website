# TODO — azm_secure_site

## Missing product images (products page rebuild)

The products page (`templates/products.html`, frontend-rebuild) reuses
existing real photos from `static/img/products/` for 3 of the 4 cards and
the project hero image for the hero. **One image is still missing** and
currently renders a gray placeholder (`.product-card__img` background):

- [ ] `static/img/products/track-pads.jpg` — لباد جنزير للمعدات الثقيلة (track pads / heavy-equipment category)

### Notes
- The Stitch design originally referenced 5 images under `static/images/products/`
  (`hero.jpg`, `bridge-bearings.jpg`, `expansion-joints.jpg`, `milling-bits.jpg`,
  `track-pads.jpg`). The project convention is `static/img/products/`, and real
  matching photos already exist, so they were wired up instead of creating
  broken placeholders:
  - hero → `img/hero/hero-1280.{webp,png}`
  - bridge bearings → `img/products/elastomeric-bearings.png`
  - expansion joints → `img/products/expansion-joints.png`
  - milling bits → `img/products/road-rehab.png`
- Consider adding a dedicated products-hero photo instead of reusing the home hero.
