import os
import re
import sqlite3
from datetime import date

import shutil

import time
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.header import Header
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g, send_from_directory, Response, make_response
)
from dotenv import load_dotenv
import requests
from werkzeug.security import check_password_hash
import secrets

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'dev_secret_change_me')

# --- Session hardening ---
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
# When deploying behind HTTPS, also set:
if os.getenv("FLASK_ENV") == "production":
    app.config['SESSION_COOKIE_SECURE'] = True

# Use /data/messages.db on Render (via env), fallback to local messages.db in dev
DB_PATH = os.environ.get(
    "SQLITE_PATH",
    os.path.join(os.path.dirname(__file__), "messages.db")
)

# One-time copy on first boot
if os.environ.get("SQLITE_PATH") and not os.path.exists(DB_PATH):
    local_db = os.path.join(os.path.dirname(__file__), "messages.db")
    if os.path.exists(local_db):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        shutil.copyfile(local_db, DB_PATH)

# --- Env / Social ---
FACEBOOK_URL = (os.getenv("FACEBOOK_URL", "").strip() or None)
WHATSAPP_NUMBER = (os.getenv("WHATSAPP_NUMBER", "").strip() or "").lstrip('+') or None
WHATSAPP_MESSAGE = os.getenv("WHATSAPP_MESSAGE", "مرحباً، أود الاستفسار عن المنتجات.")
COMPANY_NAME = "عزم لتجارة قطع الغيار ومستلزمات الطرق والجسور"

# --- Auth ---
ADMIN_USER = (os.getenv("ADMIN_USER", "admin") or "").strip()
ADMIN_PASSWORD = (os.getenv("ADMIN_PASSWORD", "") or "").strip()
ADMIN_PASSWORD_HASH = (os.getenv("ADMIN_PASSWORD_HASH", "") or "").strip()

# --- reCAPTCHA ---
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "")

# --- Optional Email (SMTP) ---
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587") or 587)
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")

# --- Rate limits ---
RATE_WINDOW_SEC = 60
RATE_MAX_POSTS = 3     # contact form
LOGIN_WINDOW_SEC = 600 # 10 minutes
LOGIN_MAX_POSTS = 8    # login attempts
_rate_bucket = {}      # { ip: [timestamps] }
_login_bucket = {}     # { ip: [timestamps] }

# ---------------- DB ----------------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def teardown_db(_e):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            email TEXT,
            subject TEXT,
            message TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            ip TEXT
        );
    """)
    db.commit()

def migrate_schema():
    db = get_db()
    cols = {r["name"] for r in db.execute("PRAGMA table_info(messages)").fetchall()}
    if "email" not in cols:
        db.execute("ALTER TABLE messages ADD COLUMN email TEXT;")
    if "subject" not in cols:
        db.execute("ALTER TABLE messages ADD COLUMN subject TEXT;")
    if "ip" not in cols:
        db.execute("ALTER TABLE messages ADD COLUMN ip TEXT;")
    if "created_at" not in cols:
        db.execute("ALTER TABLE messages ADD COLUMN created_at DATETIME;")
    cols = {r["name"] for r in db.execute("PRAGMA table_info(messages)").fetchall()}
    if "created_at" in cols:
        if "ts" in cols:
            db.execute("UPDATE messages SET created_at = COALESCE(created_at, ts, CURRENT_TIMESTAMP) WHERE created_at IS NULL;")
        else:
            db.execute("UPDATE messages SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP) WHERE created_at IS NULL;")
    db.commit()

@app.before_request
def before_any():
    init_db()
    migrate_schema()

# --------------- Security helpers ---------------
def _rate(ip, bucket, window, max_posts):
    now = time.time()
    items = bucket.setdefault(ip, [])
    bucket[ip] = [t for t in items if now - t <= window]
    if len(bucket[ip]) >= max_posts:
        return True
    bucket[ip].append(now)
    return False

def rate_limited_contact(ip): return _rate(ip, _rate_bucket, RATE_WINDOW_SEC, RATE_MAX_POSTS)
def rate_limited_login(ip):   return _rate(ip, _login_bucket, LOGIN_WINDOW_SEC, LOGIN_MAX_POSTS)

def check_admin_password(provided: str) -> bool:
    """Prefer hash; fallback to plaintext if set."""
    if ADMIN_PASSWORD_HASH:
        try:
            return bool(provided) and check_password_hash(ADMIN_PASSWORD_HASH, provided)
        except Exception:
            return False
    if ADMIN_PASSWORD:
        return provided == ADMIN_PASSWORD
    return False

# CSRF (simple, per-session token)
def get_csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = secrets.token_urlsafe(24)
        session["_csrf"] = tok
    return tok

def validate_csrf(token_from_form):
    return token_from_form and session.get("_csrf") and secrets.compare_digest(token_from_form, session["_csrf"])

@app.context_processor
def inject_globals():
    return dict(csrf_token=get_csrf_token())

# NEW: make facebook_url / whatsapp_number / whatsapp_text_encoded available everywhere
@app.context_processor
def inject_social_globals():
    return dict(
        facebook_url=FACEBOOK_URL,
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe='')
    )

# Set strong headers (CSP, etc.)
@app.after_request
def set_security_headers(resp):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/ https://www.recaptcha.net/recaptcha/; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://www.google.com/recaptcha/ https://www.gstatic.com/recaptcha/; "
        "frame-src https://www.google.com/recaptcha/ https://recaptcha.google.com/ https://www.recaptcha.net/;"
    )
    resp.headers.setdefault("Content-Security-Policy", csp)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
    if request.path.startswith("/admin"):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp

# --------------- Validation ---------------
IRAQ_ALLOWED_PREFIXES = {"75", "77", "78", "79"}
DENY_PHONES = {"07802280589", "07740818896", "07518232611"}

def normalize_iraq_phone(raw: str):
    if not raw:
        return None
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("00964"):
        digits = digits[5:]
    elif digits.startswith("964"):
        digits = digits[3:]
    if digits.startswith("0"):
        digits = digits[1:]
    if len(digits) != 10 or not digits.startswith("7"):
        return None
    if digits[:2] not in IRAQ_ALLOWED_PREFIXES:
        return None
    return "0" + digits

def verify_recaptcha(token):
    if not RECAPTCHA_SECRET_KEY or not token:
        return False
    try:
        resp = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                "secret": RECAPTCHA_SECRET_KEY,
                "response": token,
                "remoteip": request.headers.get('X-Forwarded-For', request.remote_addr or '')
            },
            timeout=5
        )
        data = resp.json()
        if not data.get("success"):
            app.logger.warning("RECAPTCHA_FAIL: %s", data)
            return False
        host = data.get("hostname", "")
        if host not in {"azmsupply.com", "www.azmsupply.com"}:
            app.logger.warning("RECAPTCHA_HOST_MISMATCH: %r", host)
            return False
        return True
    except Exception as e:
        app.logger.warning("RECAPTCHA_VERIFY_ERROR: %s", e)
        return False

def send_email_notification(payload):
    if not (EMAIL_HOST and EMAIL_USER and EMAIL_PASS and EMAIL_TO):
        app.logger.warning("SMTP_CONFIG_MISSING host=%r user=%r to=%r", EMAIL_HOST, EMAIL_USER, EMAIL_TO)
        return False
    body = (
        f"اسم المرسل: {payload.get('name')}\n"
        f"الهاتف: {payload.get('phone')}\n"
        f"البريد: {payload.get('email')}\n"
        f"الموضوع: {payload.get('subject')}\n\n"
        f"الرسالة:\n{payload.get('message')}\n\n"
        f"الوقت: {payload.get('created_at','')}\n"
        f"IP: {payload.get('ip','')}\n"
    )
    msg = MIMEText(body, _charset='utf-8')
    msg['Subject'] = Header("[Azm Supply] رسالة جديدة من الموقع", 'utf-8')
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_TO

    use_ssl_env = os.getenv("EMAIL_USE_SSL", "").lower() in ("1", "true", "yes")
    use_tls_env = os.getenv("EMAIL_USE_TLS", "").lower() in ("1", "true", "yes")
    use_ssl = use_ssl_env or EMAIL_PORT == 465
    use_tls = (use_tls_env or EMAIL_PORT == 587) and not use_ssl

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT, timeout=20) as s:
                s.login(EMAIL_USER, EMAIL_PASS)
                s.sendmail(EMAIL_USER, [EMAIL_TO], msg.as_string())
        else:
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=20) as s:
                if use_tls:
                    s.starttls()
                s.login(EMAIL_USER, EMAIL_PASS)
                s.sendmail(EMAIL_USER, [EMAIL_TO], msg.as_string())
        app.logger.info("SMTP_OK to=%s via %s:%s ssl=%s tls=%s", EMAIL_TO, EMAIL_HOST, EMAIL_PORT, use_ssl, use_tls)
        return True
    except Exception as e:
        app.logger.exception("SMTP_ERROR to=%s via %s:%s ssl=%s tls=%s err=%s", EMAIL_TO, EMAIL_HOST, EMAIL_PORT, use_ssl, use_tls, e)
        return False

def table_columns():
    db = get_db()
    rows = db.execute("PRAGMA table_info(messages)").fetchall()
    return {r["name"]: {"notnull": r["notnull"], "dflt": r["dflt_value"]} for r in rows}

def insert_message_row(payload):
    db = get_db()
    cols = table_columns()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    values = {}
    for key in ("name", "phone", "email", "subject", "message", "ip"):
        if key in cols:
            values[key] = payload.get(key)
    if "ts" in cols:
        values["ts"] = now
    if "created_at" in cols and cols["created_at"]["notnull"] and not cols["created_at"]["dflt"]:
        values["created_at"] = now
    col_names = ", ".join(values.keys())
    placeholders = ", ".join(["?"] * len(values))
    db.execute(f"INSERT INTO messages({col_names}) VALUES ({placeholders})", tuple(values.values()))
    db.commit()

def normalize_dt_str(s):
    if not s:
        return "-"
    s = str(s)
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%H:%M:%S %Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).strftime("%Y-%m-%d %H:%M")
        except Exception:
            pass
    return s

def is_logged_in():
    return bool(session.get('logged_in'))

# --------------- Routes ---------------
@app.route('/')
def home():
    return render_template(
        'home.html',
        title="الرئيسية",
        company=COMPANY_NAME,
        active_page='home',
        facebook_url=FACEBOOK_URL,
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''),
        meta_description="عزم لتجارة قطع الغيار ومستلزمات الطرق والجسور في العراق — مفاصل تمدد للجسور، مساند ارتكاز مطاطية، وقطع غيار معدات ثقيلة مع استشارة فنية وشحن سريع."
    )

@app.route('/about')
def about():
    return render_template(
        'about.html',
        title="من نحن",
        company=COMPANY_NAME,
        active_page='about',
        facebook_url=FACEBOOK_URL,
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''),
        meta_description="عن عزم: مورد موثوق لقطع غيار المعدات الثقيلة وحلول الطرق والجسور في العراق، نلتزم بالمواصفات الفنية والدعم الفني الواضح لضمان جودة التنفيذ."
    )

@app.route('/products')
def products():
    return render_template(
        'products.html',
        title="المنتجات",
        company=COMPANY_NAME,
        active_page='products',
        facebook_url=FACEBOOK_URL,
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''),
        meta_description="المنتجات: مساند ارتكاز مطاطية، مفاصل تمدد للجسور، أسنان قشط وحفر، أسنان شفلات وحفارات، ومستلزمات إعادة تأهيل الطرق — توريد سريع داخل العراق."
    )

@app.route('/catalog')
def catalog():
    return render_template(
        'catalog.html',
        title="الكتالوج",
        company=COMPANY_NAME,
        active_page='catalog',
        facebook_url=FACEBOOK_URL,
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe='')
    )

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # CSRF
        if not validate_csrf(request.form.get("_csrf")):
            flash("انتهت صلاحية الجلسة. الرجاء المحاولة مجدداً.", "error")
            return redirect(url_for('contact'))

        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
        if rate_limited_contact(ip):
            flash("الرجاء المحاولة لاحقاً (عدد كبير من المحاولات).", "error")
            return redirect(url_for('contact'))

        if not verify_recaptcha(request.form.get('g-recaptcha-response', '')):
            flash("تحقق reCAPTCHA فشل. الرجاء المحاولة مرة أخرى.", "error")
            return redirect(url_for('contact'))

        name = (request.form.get('name') or '').strip()
        phone_raw = (request.form.get('phone') or '').strip()
        email = (request.form.get('email') or '').strip()
        subject = (request.form.get('subject') or '').strip()
        message = (request.form.get('message') or '').strip()

        if not name or not phone_raw or not message:
            flash("الاسم، الهاتف، والرسالة حقول مطلوبة.", "error")
            return redirect(url_for('contact'))

        phone = normalize_iraq_phone(phone_raw)
        if not phone:
            flash("رقم الهاتف غير صالح. أدخل رقم عراقي صحيح يبدأ بـ 075/077/078/079 (مثال: 07802280589 أو +9647802280589).", "error")
            return redirect(url_for('contact'))

        # Block specific numbers
        if phone in DENY_PHONES:
            flash("يرجى إدخال رقم هاتف مختلف.", "error")
            return redirect(url_for('contact'))

        payload = {"name": name, "phone": phone, "email": email,
                   "subject": subject, "message": message, "ip": ip}
        insert_message_row(payload)

        try:
            payload["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            ok = send_email_notification(payload)
            if not ok:
                app.logger.warning("CONTACT_EMAIL_SEND_FAILED ip=%s phone=%s", ip, phone)
        except Exception:
            app.logger.exception("CONTACT_EMAIL_UNHANDLED")
        return redirect(url_for('thank_you'))

    # GET
    return render_template(
        'contact.html',
        title="تواصل معنا",
        company=COMPANY_NAME,
        active_page='contact',
        recaptcha_site_key=RECAPTCHA_SITE_KEY,
        facebook_url=FACEBOX_URL if False else FACEBOOK_URL,  # keep exact functionality
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''),
        meta_description="تواصل معنا لطلب عرض سعر أو استشارة فنية حول مساند الارتكاز، مفاصل التمدد، وقطع غيار المعدات الثقيلة — الرد سريع داخل العراق."
    )

@app.route('/thank-you')
def thank_you():
    return render_template('thank_you.html', title="شكراً لتواصلكم",
                           company=COMPANY_NAME, active_page=None,
                           facebook_url=FACEBOOK_URL, whatsapp_number=WHATSAPP_NUMBER,
                           whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # CSRF + rate-limit
        if not validate_csrf(request.form.get("_csrf")):
            flash("انتهت صلاحية الجلسة. الرجاء المحاولة مجدداً.", "error")
            return redirect(url_for('login'))
        ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
        if rate_limited_login(ip):
            flash("محاولات تسجيل كثيرة. الرجاء الانتظار قليلاً.", "error")
            return redirect(url_for('login'))

        user = (request.form.get('username') or '').strip()
        pw = request.form.get('password') or ''

        ok = False
        if ADMIN_PASSWORD_HASH and pw:
            try:
                ok = check_password_hash(ADMIN_PASSWORD_HASH, pw)
            except Exception:
                ok = False
        if not ok and ADMIN_PASSWORD:
            ok = (pw == ADMIN_PASSWORD)

        app.logger.info(
            "LOGIN_DEBUG user=%r len_pw=%d env_user=%r hash_set=%s ok=%s",
            user, len(pw), ADMIN_USER, bool(ADMIN_PASSWORD_HASH), ok
        )

        if user == ADMIN_USER and ok:
            session['logged_in'] = True
            session.permanent = True
            flash("تم تسجيل الدخول بنجاح.", "success")
            return redirect(url_for('admin_messages'))

        flash("بيانات الدخول غير صحيحة.", "error")
        return redirect(url_for('login'))

    return render_template('login.html', title="تسجيل الدخول", company=COMPANY_NAME,
                           active_page=None, facebook_url=FACEBOOK_URL,
                           whatsapp_number=WHATSAPP_NUMBER,
                           whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''))

@app.route('/logout', methods=['POST'])
def logout():
    if not validate_csrf(request.form.get("_csrf")):
        flash("انتهت صلاحية الجلسة. الرجاء المحاولة مجدداً.", "error")
        return redirect(url_for('home'))
    session.clear()
    flash("تم تسجيل الخروج.", "success")
    return redirect(url_for('home'))

@app.route('/admin/messages')
def admin_messages():
    if not is_logged_in():
        return redirect(url_for('home'))

    page = max(int(request.args.get('page', 1)), 1)
    per_page = 20
    offset = (page - 1) * per_page

    db = get_db()
    cols = table_columns()
    order_col = "created_at" if "created_at" in cols else ("ts" if "ts" in cols else "id")

    raw = db.execute(
        f"SELECT * FROM messages ORDER BY {order_col} DESC LIMIT ? OFFSET ?",
        (per_page, offset)
    ).fetchall()

    rows = []
    for r in raw:
        d = dict(r)
        when = d.get("created_at") or d.get("ts")
        d["display_time"] = normalize_dt_str(when)
        rows.append(d)

    total = db.execute("SELECT COUNT(*) AS c FROM messages").fetchone()['c']
    has_next = offset + per_page < total

    resp = make_response(render_template('admin_messages.html',
                           title="رسائل العملاء", company=COMPANY_NAME,
                           active_page=None, messages=rows, page=page, has_next=has_next,
                           facebook_url=FACEBOOK_URL, whatsapp_number=WHATSAPP_NUMBER,
                           whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe='')))

    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp

# --- Simple admin-only test endpoint ---
@app.route('/admin/email-test')
def admin_email_test():
    if not is_logged_in():
        return redirect(url_for('home'))
    payload = {
        "name": "اختبار",
        "phone": "07900000000",
        "email": "test@example.com",
        "subject": "اختبار البريد",
        "message": "رسالة اختبار من لوحة الإدارة.",
        "ip": request.headers.get('X-Forwarded-For', request.remote_addr or ''),
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
    }
    ok = send_email_notification(payload)
    return ("OK" if ok else "FAIL (check logs)"), (200 if ok else 500)

# --- robots & sitemap ---
@app.route('/robots.txt')
def robots():
    lines = [
        "User-agent: *",
        "Allow: /",
        "Disallow: /login",
        "Disallow: /admin/",
        f"Sitemap: {request.url_root.rstrip('/')}/sitemap.xml",
    ]
    return Response("\n".join(lines), mimetype="text/plain; charset=utf-8")

@app.route('/sitemap.xml')
def sitemap():
    today = date.today().isoformat()
    urls = [
        ('home','daily'),
        ('about','weekly'),
        ('products','weekly'),
        ('catalog','weekly'),   # ← new
        ('contact','monthly'),
    ]
    base = request.url_root.rstrip('/')
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for endpoint, freq in urls:
        loc = f"{base}{url_for(endpoint)}"
        out.append(
            f"<url><loc>{loc}</loc><changefreq>{freq}</changefreq><lastmod>{today}</lastmod></url>"
        )
    out.append("</urlset>")
    return Response("\n".join(out), mimetype="application/xml; charset=utf-8")


# --- Icon routes at root (fix mobile/Google 404s) ---
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')

@app.route('/favicon-32x32.png')
def favicon32():
    return send_from_directory(app.static_folder, 'favicon-32x32.png', mimetype='image/png')

@app.route('/favicon-16x16.png')
def favicon16():
    return send_from_directory(app.static_folder, 'favicon-16x16.png', mimetype='image/png')

@app.route('/apple-touch-icon.png')
def apple_touch():
    return send_from_directory(app.static_folder, 'apple-touch-icon.png', mimetype='image/png')

@app.route('/android-chrome-192x192.png')
def android_192():
    return send_from_directory(app.static_folder, 'android-chrome-192x192.png', mimetype='image/png')

@app.route('/android-chrome-512x512.png')
def android_512():
    return send_from_directory(app.static_folder, 'android-chrome-512x512.png', mimetype='image/png')

# Long-cache these icons so browsers/Google keep them
@app.after_request
def cache_icons(resp):
    if request.path in (
        '/favicon.ico',
        '/favicon-32x32.png',
        '/favicon-16x16.png',
        '/apple-touch-icon.png',
        '/android-chrome-192x192.png',
        '/android-chrome-512x512.png',
    ):
        resp.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
