import os
import re
import sqlite3
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

# One-time copy on first boot: if deploying to Render and /data/messages.db
# doesn't exist yet but a local messages.db exists in the repo, copy it so
# your old messages appear in production immediately.
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

# --- Auth (strip to avoid hidden spaces/newlines) ---
ADMIN_USER = (os.getenv("ADMIN_USER", "admin") or "").strip()
ADMIN_PASSWORD = (os.getenv("ADMIN_PASSWORD", "") or "").strip()  # plaintext fallback (optional)
ADMIN_PASSWORD_HASH = (os.getenv("ADMIN_PASSWORD_HASH", "") or "").strip()  # preferred

# --- reCAPTCHA (prod keys set in env) ---
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY", "")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY", "")

# --- Optional Email (SMTP) ---
EMAIL_HOST = os.getenv("EMAIL_HOST", "")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587") or 587)
EMAIL_USER = os.getenv("EMAIL_USER", "")
EMAIL_PASS = os.getenv("EMAIL_PASS", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")  # where to notify on new contact

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
    # Backfill created_at (prefer legacy ts if exists)
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
DENY_PHONES = {"07802280589", "07740818896", "07518232611"}  # blocked numbers (normalized national format)

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
    # now we expect 10 digits starting with 7xxxxxxxxx
    if len(digits) != 10 or not digits.startswith("7"):
        return None
    # check first TWO digits (operator code): 75/77/78/79
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
        return
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
    msg['Subject'] = Header("📥 رسالة جديدة من الموقع", 'utf-8')
    msg['From'] = EMAIL_USER
    msg['To'] = EMAIL_TO
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as s:
            s.starttls()
            s.login(EMAIL_USER, EMAIL_PASS)
            s.sendmail(EMAIL_USER, [EMAIL_TO], msg.as_string())
    except Exception:
        pass

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
        meta_description="عزم لتجارة قطع الغيار ومستلزمات الطرق والجسور — نوفر مفاصل تمدد، مساند ارتكاز، وقطع غيار محركات لمشاريع الطرق والجسور في العراق بجودة عالية وخدمة سريعة."
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
        meta_description="تعرف على شركة عزم لتجارة قطع الغيار ومستلزمات الطرق والجسور — رؤيتنا، قيمنا، وخبراتنا في دعم مشاريع البنية التحتية في العراق."
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
        meta_description="اكتشف مجموعة منتجات عزم: مفاصل تمدد، مساند ارتكاز، قطع غيار المحركات، ولوازم إعادة تأهيل الطرق والجسور بجودة موثوقة."
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

        # Block specific numbers (normalized national format)
        if phone in DENY_PHONES:
            flash("يرجى إدخال رقم هاتف مختلف.", "error")
            return redirect(url_for('contact'))

        payload = {"name": name, "phone": phone, "email": email,
                   "subject": subject, "message": message, "ip": ip}
        insert_message_row(payload)

        try:
            payload["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M")
            send_email_notification(payload)
        except Exception:
            pass

        return redirect(url_for('thank_you'))

    # GET: render with page-specific meta description
    return render_template(
        'contact.html',
        title="تواصل معنا",
        company=COMPANY_NAME,
        active_page='contact',
        recaptcha_site_key=RECAPTCHA_SITE_KEY,
        facebook_url=FACEBOOK_URL,
        whatsapp_number=WHATSAPP_NUMBER,
        whatsapp_text_encoded=requests.utils.quote(WHATSAPP_MESSAGE, safe=''),
        meta_description="تواصل مع عزم للحصول على عروض أسعار واستشارات حول مفاصل التمدد، مساند الارتكاز، وقطع الغيار لمشاريع الطرق والجسور في العراق."
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

        # Evaluate password validity (hash preferred, plaintext fallback)
        ok = False
        if ADMIN_PASSWORD_HASH and pw:
            try:
                ok = check_password_hash(ADMIN_PASSWORD_HASH, pw)
            except Exception:
                ok = False
        if not ok and ADMIN_PASSWORD:
            ok = (pw == ADMIN_PASSWORD)

        # Debug line: visible in Render logs
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
    # CSRF
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

    # Extra safety (already set in after_request, but here too)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp

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
    urls = [('home','daily'),('about','weekly'),('products','weekly'),('contact','monthly')]
    base = request.url_root.rstrip('/')
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for endpoint, freq in urls:
        out.append(f"<url><loc>{base}{url_for(endpoint)}</loc><changefreq>{freq}</changefreq></url>")
    out.append("</urlset>")
    return Response("\n".join(out), mimetype="application/xml; charset=utf-8")

# --- Favicon helper ---
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/x-icon')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
