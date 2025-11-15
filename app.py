#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EMI SUPER BOT - app.py completo con:
- persistente su data.json
- upload immagini/video
- generazione immagini (Pillow) e "video" (GIF animate)
- admin + premium + free 30 giorni rule
- webhook skeleton per Gumroad e Stripe
- commenti in italiano
"""

import os
import time
import secrets
import json
from datetime import datetime
from functools import wraps
from hashlib import sha1
from hmac import new as hmac_new
from pathlib import Path

from flask import (
    Flask, request, jsonify, session, render_template,
    redirect, url_for, send_from_directory, flash
)

# librerie opzionali (installa Pillow e stripe se vuoi)
try:
    from PIL import Image, ImageDraw, ImageFont
except Exception:
    Image = None

try:
    import stripe
except Exception:
    stripe = None

import bcrypt

# ---------------------------
# Config / ENV
# ---------------------------
DATA_FILE = Path("data.json")
STATIC_UPLOADS = Path("static/uploads")
STATIC_GENERATED = Path("static/generated")

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
FLASK_SECRET = os.getenv("FLASK_SECRET", secrets.token_urlsafe(32))
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD", None)
BUY_LINK = os.getenv("BUY_LINK", "https://your-gumroad-or-pay-link.example")
GUMROAD_SECRET = os.getenv("GUMROAD_SECRET", "")
PORT = int(os.getenv("PORT", "10000"))
DEBUG = os.getenv("DEBUG", "0") == "1"

# Stripe (opzionale)
STRIPE_SECRET = os.getenv("STRIPE_SECRET", "")
if stripe and STRIPE_SECRET:
    stripe.api_key = STRIPE_SECRET

# Assicurati che le cartelle esistano
STATIC_UPLOADS.mkdir(parents=True, exist_ok=True)
STATIC_GENERATED.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = FLASK_SECRET

# ---------------------------
# Data persistence (data.json)
# ---------------------------
def load_data():
    if not DATA_FILE.exists():
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_data(DATA):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(DATA, f, indent=2, ensure_ascii=False)

# carica dati e strutture
DATA = load_data()
USERS = DATA.get("users", {})
VALID_PREMIUM_CODES = set(DATA.get("valid_codes", []))
USED_PREMIUM_CODES = set(DATA.get("used_codes", []))

# ---------------------------
# Defaults / constants
# ---------------------------
FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "20"))
HISTORY_FREE = int(os.getenv("HISTORY_FREE", "8"))
HISTORY_PREMIUM = int(os.getenv("HISTORY_PREMIUM", "40"))
NON_PREMIUM_RETENTION_DAYS = int(os.getenv("NON_PREMIUM_RETENTION_DAYS", "30"))

# ---------------------------
# Helpers
# ---------------------------
def now_ymd():
    return datetime.utcnow().strftime("%Y-%m-%d")

def ensure_user_entry(uname):
    """Garantisce che USERS[uname] esista con campi minimi."""
    if uname not in USERS:
        USERS[uname] = {
            "password_hash": None,
            "premium": False,
            "is_admin": False,
            "created_at": now_ymd(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        DATA["users"] = USERS
        save_data(DATA)

def reset_daily_if_needed(u):
    today = now_ymd()
    dc = u.setdefault("daily_count", {"date": today, "count": 0})
    if dc.get("date") != today:
        dc["date"] = today
        dc["count"] = 0

def increment_daily(u):
    reset_daily_if_needed(u)
    u["daily_count"]["count"] += 1
    DATA["users"] = USERS
    save_data(DATA)
    return u["daily_count"]["count"]

def user_message_count(u):
    reset_daily_if_needed(u)
    return u["daily_count"]["count"]

def verify_gumroad_signature(payload_bytes, sig_header):
    if not GUMROAD_SECRET:
        return True
    if not sig_header:
        return False
    computed = hmac_new(GUMROAD_SECRET.encode(), payload_bytes, sha1).hexdigest()
    return computed == sig_header

def cleanup_history(username):
    """Rimuove messaggi > retention per utenti NON premium."""
    user = USERS.get(username)
    if not user:
        return
    if user.get("premium"):
        return
    cutoff = time.time() - (NON_PREMIUM_RETENTION_DAYS * 24 * 3600)
    if "history" in user:
        newhist = [m for m in user["history"] if m.get("ts", 0) >= cutoff]
        if len(newhist) != len(user["history"]):
            user["history"] = newhist
            DATA["users"] = USERS
            save_data(DATA)

# ---------------------------
# Utilities per file upload / generation
# ---------------------------
def secure_filename(name: str) -> str:
    # semplice "secure" filename: rimuove slash e spazi
    return "".join(c for c in name if c.isalnum() or c in ("-", "_", ".")).strip() or "file"

def save_uploaded_file(file_storage, dest_folder: Path):
    fname = secure_filename(file_storage.filename)
    unique = f"{int(time.time())}_{secrets.token_hex(4)}_{fname}"
    path = dest_folder / unique
    file_storage.save(path)
    return str(path)

def generate_image(prompt_text: str, out_folder: Path, width=512, height=512):
    """Genera una immagine semplice con Pillow (placeholder)."""
    if Image is None:
        raise RuntimeError("Pillow non installata")
    img = Image.new("RGB", (width, height), color=(102, 102, 255))
    d = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    lines = []
    # spezza prompt in più righe
    p = prompt_text.strip()
    max_len = 24
    for i in range(0, len(p), max_len):
        lines.append(p[i:i+max_len])
    y = 20
    for line in lines[:10]:
        d.text((16, y), line, fill=(255, 255, 255), font=font)
        y += 14
    filename = f"img_{int(time.time())}_{secrets.token_hex(4)}.png"
    out_path = out_folder / filename
    img.save(out_path)
    return str(out_path)

def generate_gif_as_video(prompt_text: str, out_folder: Path, frames=6, width=640, height=360):
    """Genera una GIF animata come 'video' placeholder."""
    if Image is None:
        raise RuntimeError("Pillow non installata")
    imgs = []
    for i in range(frames):
        img = Image.new("RGB", (width, height), color=(int(30 + i*30)%255, 80+i*10, 140+i*15))
        d = ImageDraw.Draw(img)
        text = f"{prompt_text[:28]}... frame {i+1}"
        try:
            font = ImageFont.load_default()
        except Exception:
            font = None
        d.text((20, 20), text, fill=(255,255,255), font=font)
        imgs.append(img)
    filename = f"vid_{int(time.time())}_{secrets.token_hex(4)}.gif"
    out_path = out_folder / filename
    imgs[0].save(out_path, save_all=True, append_images=imgs[1:], duration=300, loop=0)
    return str(out_path)

# ---------------------------
# Initialize minimal admin user if missing
# ---------------------------
if "admin" not in USERS:
    pw = "sB5Zj_@=ymQ!QGmd"
    USERS["admin"] = {
        "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode() if isinstance(bcrypt.hashpw(b"", bcrypt.gensalt()), bytes) else bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
        "premium": True,
        "is_admin": True,
        "created_at": now_ymd(),
        "history": [],
        "daily_count": {"date": now_ymd(), "count": 0}
    }
    DATA["users"] = USERS
    save_data(DATA)

# ensure password_hash bytes consistency on load
for k,v in list(USERS.items()):
    ph = v.get("password_hash")
    if isinstance(ph, str):
        try:
            USERS[k]["password_hash"] = ph.encode()
        except Exception:
            pass

# ---------------------------
# Decorators
# ---------------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uname = session.get("username")
        if not uname:
            return redirect(url_for("login", next=request.path))
        u = USERS.get(uname)
        if u and u.get("is_admin"):
            return f(*args, **kwargs)
        supplied = request.args.get("admin_pw") or request.form.get("admin_pw") or request.headers.get("X-Admin-Pw")
        if ADMIN_PASSWORD_ENV and supplied == ADMIN_PASSWORD_ENV:
            return f(*args, **kwargs)
        return "Admin access required", 403
    return wrapped

# ---------------------------
# Routes: static access for uploaded/generated
# ---------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(STATIC_UPLOADS, filename)

@app.route("/generated/<path:filename>")
def generated_file(filename):
    return send_from_directory(STATIC_GENERATED, filename)

# ---------------------------
# Routes: Auth
# ---------------------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = (request.form.get("password") or "")
        if not uname or not pw:
            flash("Username and password required")
            return redirect(url_for("register"))
        if uname in USERS:
            flash("Username exists")
            return redirect(url_for("register"))
        USERS[uname] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
            "premium": False,
            "is_admin": False,
            "created_at": now_ymd(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        DATA["users"] = USERS
        save_data(DATA)
        session["username"] = uname
        return redirect(url_for("home"))
    return render_template("auth.html", title="Register", button="Create account", extra=None)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = (request.form.get("password") or "")
        if not uname or not pw:
            return "Username and password required", 400
        u = USERS.get(uname)
        if not u:
            return "Invalid credentials", 400
        ph = u.get("password_hash")
        if isinstance(ph, str):
            ph = ph.encode()
        if ph and bcrypt.checkpw(pw.encode(), ph):
            session["username"] = uname
            return redirect(url_for("home"))
        return "Invalid credentials", 400
    return render_template("auth.html", title="Login", button="Login", extra=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------
# Home & Chat endpoints
# ---------------------------
@app.route("/")
@login_required
def home():
    uname = session.get("username")
    u = USERS.get(uname)
    if not u:
        # dovremmo avere utente ma in caso crealo
        ensure_user_entry(uname)
        u = USERS.get(uname)
    plan = "premium" if u.get("premium") else "free"
    used = user_message_count(u)
    history = [{"role": m["role"], "content": m["content"]} for m in u.get("history", [])[-(HISTORY_PREMIUM*2):]]
    return render_template("home.html", username=uname, plan=plan, premium=u.get("premium"),
                           created_at=u.get("created_at"), buy_link=BUY_LINK, history=history,
                           free_limit=FREE_DAILY_LIMIT, used_today=used)

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    uname = session.get("username")
    u = USERS.get(uname)
    if not u:
        return jsonify({"error": "User not found"}), 400

    # pulizia automatica per non-premium
    cleanup_history(uname)

    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400

    if not u.get("premium"):
        count = increment_daily(u)
        if count > FREE_DAILY_LIMIT:
            return jsonify({"error": "Free daily limit reached. Upgrade to premium."}), 429

    # costruisci contesto
    max_pairs = HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE
    recent = u.get("history", [])[-(max_pairs*2):]
    ctx = [{"role":"system", "content":"Sei EMI SUPER BOT. Rispondi nella stessa lingua dell'utente."}]
    for m in recent:
        ctx.append({"role": m["role"], "content": m["content"]})
    ctx.append({"role": "user", "content": message})

    # chiamata al modello (qui stub: usa Groq client o altro)
    try:
        # ESEMPIO: sostituisci con chiamata reale a Groq / OpenAI
        # resp = client.chat.completions.create(model="llama-3.1-8b-instant", messages=ctx)
        # ai_text = resp.choices[0].message.content
        ai_text = f"[Simulated reply to: {message[:200]}]"  # placeholder
    except Exception as exc:
        return jsonify({"error": f"Model API error: {str(exc)}"}), 500

    # salva cronologia (user + bot)
    ts = time.time()
    u.setdefault("history", []).append({"role":"user","content": message, "ts": ts})
    u.setdefault("history", []).append({"role":"bot","content": ai_text, "ts": ts})
    # trim
    max_items = (HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE) * 2
    if len(u["history"]) > max_items:
        u["history"] = u["history"][-max_items:]
    DATA["users"] = USERS
    save_data(DATA)

    return jsonify({"reply": ai_text})

# ---------------------------
# Uploads & generation endpoints
# ---------------------------
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    f = request.files["file"]
    if f.filename == "":
        return jsonify({"error": "No selected file"}), 400
    path = save_uploaded_file(f, STATIC_UPLOADS)
    return jsonify({"ok": True, "path": path})

@app.route("/generate/image", methods=["POST"])
@login_required
def gen_image():
    uname = session.get("username")
    u = USERS.get(uname)
    if not u:
        return jsonify({"error": "user not found"}), 400

    prompt = (request.form.get("prompt") or request.json and request.json.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt required"}), 400

    # controllo limiti / daily cost se vuoi
    # qui generiamo un'immagine placeholder
    try:
        out = generate_image(prompt, STATIC_GENERATED)
    except Exception as e:
        return jsonify({"error": f"Generation error: {str(e)}"}), 500

    # salva riferimento nella cronologia
    ts = time.time()
    u.setdefault("history", []).append({"role":"user","content": f"[image request] {prompt}", "ts": ts})
    u.setdefault("history", []).append({"role":"bot","content": f"[image generated] {out}", "ts": ts})
    DATA["users"] = USERS
    save_data(DATA)

    # ritorna percorso pubblico
    return jsonify({"ok": True, "url": url_for("generated_file", filename=os.path.basename(out), _external=True)})

@app.route("/generate/video", methods=["POST"])
@login_required
def gen_video():
    uname = session.get("username")
    u = USERS.get(uname)
    if not u:
        return jsonify({"error": "user not found"}), 400
    prompt = (request.form.get("prompt") or request.json and request.json.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt required"}), 400
    try:
        out = generate_gif_as_video(prompt, STATIC_GENERATED)
    except Exception as e:
        return jsonify({"error": f"Generation error: {str(e)}"}), 500

    ts = time.time()
    u.setdefault("history", []).append({"role":"user","content": f"[video request] {prompt}", "ts": ts})
    u.setdefault("history", []).append({"role":"bot","content": f"[video generated] {out}", "ts": ts})
    DATA["users"] = USERS
    save_data(DATA)

    return jsonify({"ok": True, "url": url_for("generated_file", filename=os.path.basename(out), _external=True)})

# ---------------------------
# Account actions
# ---------------------------
@app.route("/upgrade", methods=["POST"])
@login_required
def upgrade():
    uname = session.get("username")
    code = (request.form.get("code") or "").strip()
    if not code:
        return "No code provided", 400
    if code in USED_PREMIUM_CODES:
        return "Code already used", 400
    if code not in VALID_PREMIUM_CODES:
        return "Invalid code", 400
    USED_PREMIUM_CODES.add(code)
    USERS[uname]["premium"] = True
    # salva
    DATA["users"] = USERS
    DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
    DATA["used_codes"] = list(USED_PREMIUM_CODES)
    save_data(DATA)
    return redirect(url_for("home"))

@app.route("/clear_history", methods=["POST"])
@login_required
def clear_history_route():
    uname = session.get("username")
    USERS[uname]["history"] = []
    DATA["users"] = USERS
    save_data(DATA)
    return redirect(url_for("home"))

# ---------------------------
# Admin routes
# ---------------------------
@app.route("/admin")
@admin_required
def admin():
    uv = []
    for username, data in USERS.items():
        uv.append({
            "username": username,
            "premium": data.get("premium"),
            "is_admin": data.get("is_admin"),
            "created_at": data.get("created_at")
        })
    return render_template("admin.html", users=uv, codes=sorted(list(VALID_PREMIUM_CODES)), used=USED_PREMIUM_CODES)

@app.route("/admin/make_premium", methods=["POST"])
@admin_required
def make_premium():
    username = request.form.get("username")
    if username in USERS:
        USERS[username]["premium"] = True
        DATA["users"] = USERS
        save_data(DATA)
    return redirect(url_for("admin"))

@app.route("/admin/remove_premium", methods=["POST"])
@admin_required
def remove_premium():
    username = request.form.get("username")
    if username in USERS:
        USERS[username]["premium"] = False
        DATA["users"] = USERS
        save_data(DATA)
    return redirect(url_for("admin"))

@app.route("/admin/generate_codes", methods=["POST"])
@admin_required
def admin_generate_codes():
    n = int(request.form.get("n", "3"))
    n = max(1, min(n, 200))
    created = []
    for _ in range(n):
        code = secrets.token_hex(6)
        VALID_PREMIUM_CODES.add(code)
        created.append(code)
    DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
    save_data(DATA)
    return jsonify({"created": created})

@app.route("/admin/create_user", methods=["POST"])
@admin_required
def admin_create_user():
    uname = (request.form.get("username") or "").strip()
    pw = (request.form.get("password") or "").strip()
    is_admin = bool(request.form.get("is_admin"))
    if not uname or not pw:
        return "username and password required", 400
    if uname in USERS:
        return "exists", 400
    USERS[uname] = {
        "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
        "premium": False,
        "is_admin": is_admin,
        "created_at": now_ymd(),
        "history": [],
        "daily_count": {"date": now_ymd(), "count": 0}
    }
    DATA["users"] = USERS
    save_data(DATA)
    return redirect(url_for("admin"))

@app.route("/admin/toggle_premium/<username>", methods=["POST"])
@admin_required
def admin_toggle_premium(username):
    if username not in USERS:
        return "no user", 400
    USERS[username]["premium"] = not USERS[username].get("premium", False)
    DATA["users"] = USERS
    save_data(DATA)
    return redirect(url_for("admin"))

@app.route("/admin/delete_user/<username>", methods=["POST"])
@admin_required
def admin_delete_user(username):
    if username in USERS:
        del USERS[username]
        DATA["users"] = USERS
        save_data(DATA)
    return redirect(url_for("admin"))

# ---------------------------
# Admin API: codes
# ---------------------------
@app.route("/admin/codes", methods=["GET"])
@admin_required
def admin_codes():
    return jsonify({"valid": list(VALID_PREMIUM_CODES), "used": list(USED_PREMIUM_CODES)})

@app.route("/admin/revoke_code", methods=["POST"])
@admin_required
def admin_revoke_code():
    code = request.form.get("code")
    if code in VALID_PREMIUM_CODES:
        VALID_PREMIUM_CODES.remove(code)
        DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
        save_data(DATA)
    return redirect(url_for("admin"))

# ---------------------------
# Webhooks
# ---------------------------
@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    payload = request.get_data()
    sig = request.headers.get("X-Gumroad-Signature") or request.headers.get("x-gumroad-signature")
    if GUMROAD_SECRET:
        if not verify_gumroad_signature(payload, sig):
            return "invalid signature", 403
    data = request.form.to_dict() or request.get_json(silent=True) or {}
    # demo: genera un codice e salvalo
    code = secrets.token_hex(6)
    VALID_PREMIUM_CODES.add(code)
    DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
    save_data(DATA)
    return jsonify({"ok": True, "code": code})

@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    if stripe is None or not STRIPE_SECRET:
        return "stripe not configured", 400
    payload = request.get_data()
    sig_header = request.headers.get("Stripe-Signature")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_SECRET)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    # process checkout.session.completed
    if event["type"] == "checkout.session.completed":
        session_obj = event["data"]["object"]
        # qui puoi creare user premium basandoti su metadata o email
        # esempio: session_obj["metadata"].get("username")
        username = session_obj.get("metadata", {}).get("username")
        if username and username in USERS:
            USERS[username]["premium"] = True
            DATA["users"] = USERS
            save_data(DATA)
    return jsonify({"ok": True})

# ---------------------------
# Health
# ---------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time()})

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    print("EMI SUPER BOT starting. Set GROQ_API_KEY / STRIPE_SECRET in env if needed.")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
