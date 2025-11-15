# app.py - EMI SUPER BOT (VERSIONE SENZA ERRORI)
import os
import time
import secrets
import json
from datetime import datetime
from functools import wraps
from hashlib import sha1
from hmac import new as hmac_new

from flask import (
    Flask, request, jsonify, session, render_template,
    redirect, url_for, flash
)
import bcrypt

# Groq API (opzionale)
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except Exception:
    Groq = None
    GROQ_AVAILABLE = False

# ---------------------------
# CONFIG
# ---------------------------
DATA_FILE = "data.json"
STATIC_UPLOADS = "static/uploads"
STATIC_GENERATED = "static/generated"

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")
FLASK_SECRET = os.getenv("FLASK_SECRET", secrets.token_urlsafe(32))
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD", None)
BUY_LINK = os.getenv("BUY_LINK", "https://micheleguerra.gumroad.com/")
GUMROAD_SECRET = os.getenv("GUMROAD_SECRET", None)
PORT = int(os.getenv("PORT", "10000"))
DEBUG = os.getenv("DEBUG", "0") == "1"

# App init
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = FLASK_SECRET

# Inizializza client Groq solo se disponibile
client = None
if GROQ_AVAILABLE and GROQ_API_KEY:
    try:
        client = Groq(api_key=GROQ_API_KEY)
    except Exception as e:
        app.logger.error(f"Groq init error: {e}")
        client = None

os.makedirs(STATIC_UPLOADS, exist_ok=True)
os.makedirs(STATIC_GENERATED, exist_ok=True)

# ---------------------------
# Persistence
# ---------------------------
def load_data():
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "valid_codes": [], "used_codes": []}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Assicura che tutte le chiavi esistano
            if "users" not in data:
                data["users"] = {}
            if "valid_codes" not in data:
                data["valid_codes"] = []
            if "used_codes" not in data:
                data["used_codes"] = []
            return data
    except Exception as e:
        app.logger.error(f"load_data error: {e}")
        return {"users": {}, "valid_codes": [], "used_codes": []}

def save_data():
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(DATA, f, indent=2, ensure_ascii=False)
    except Exception as e:
        app.logger.error(f"save_data error: {e}")

DATA = load_data()
USERS = DATA.get("users", {})
VALID_PREMIUM_CODES = set(DATA.get("valid_codes", []))
USED_PREMIUM_CODES = set(DATA.get("used_codes", []))

FREE_DAILY_LIMIT = int(os.getenv("FREE_DAILY_LIMIT", "20"))
HISTORY_FREE = int(os.getenv("HISTORY_FREE", "8"))
HISTORY_PREMIUM = int(os.getenv("HISTORY_PREMIUM", "40"))

# ---------------------------
# Utility
# ---------------------------
def now_ymd():
    return datetime.utcnow().strftime("%Y-%m-%d")

def reset_daily_if_needed(u):
    if not u:
        return
    today = now_ymd()
    if "daily_count" not in u:
        u["daily_count"] = {"date": today, "count": 0}
    dc = u["daily_count"]
    if dc.get("date") != today:
        dc["date"] = today
        dc["count"] = 0

def increment_daily(u):
    if not u:
        return 0
    reset_daily_if_needed(u)
    u["daily_count"]["count"] += 1
    return u["daily_count"]["count"]

def user_message_count(u):
    if not u:
        return 0
    reset_daily_if_needed(u)
    return u["daily_count"].get("count", 0)

def persist_users_and_codes():
    try:
        DATA["users"] = USERS
        DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
        DATA["used_codes"] = list(USED_PREMIUM_CODES)
        save_data()
    except Exception as e:
        app.logger.error(f"persist error: {e}")

def get_preferred_lang():
    al = request.headers.get("Accept-Language", "")
    if not al:
        return "it"  # Default italiano
    try:
        lang = al.split(",")[0].split("-")[0].lower()
        return lang if lang else "it"
    except:
        return "it"

# ---------------------------
# Decorators
# ---------------------------
def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("welcome"))
        return f(*args, **kwargs)
    return wrapped

def admin_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uname = session.get("username")
        if not uname:
            return redirect(url_for("welcome"))
        u = USERS.get(uname)
        if u and u.get("is_admin"):
            return f(*args, **kwargs)
        supplied = request.args.get("admin_pw") or request.form.get("admin_pw") or request.headers.get("X-Admin-Pw")
        if ADMIN_PASSWORD_ENV and supplied == ADMIN_PASSWORD_ENV:
            return f(*args, **kwargs)
        return "Admin access required", 403
    return wrapped

# ---------------------------
# Initial demo users
# ---------------------------
def ensure_demo_users():
    changed = False
    if "admin" not in USERS:
        pw = "sB5Zj_@=ymQ!QGmd"
        USERS["admin"] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
            "premium": True,
            "is_admin": True,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        changed = True
    if "utente1" not in USERS:
        pw = "efKgOaM^H0Uiq*"
        USERS["utente1"] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
            "premium": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        changed = True
    if "premiumtester" not in USERS:
        pw = "CtBVZ2)i!j4AosyT"
        USERS["premiumtester"] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
            "premium": True,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        changed = True
    if changed:
        persist_users_and_codes()

ensure_demo_users()

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def welcome():
    session.setdefault("lang", get_preferred_lang())
    # Crea un template welcome.html semplice se non esiste
    try:
        return render_template("welcome.html", lang=session.get("lang", "it"))
    except:
        # Fallback HTML se il template non esiste
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>EMI SUPER BOT</title></head>
        <body>
            <h1>Benvenuto a EMI SUPER BOT</h1>
            <form action="/login" method="get"><button>Login</button></form>
            <form action="/register" method="get"><button>Registrati</button></form>
            <form action="/guest" method="post"><button>Entra come Ospite</button></form>
        </body>
        </html>
        '''

@app.route("/guest", methods=["POST"])
def guest():
    try:
        uname = "guest_" + secrets.token_hex(4)
        session["username"] = uname
        session["is_guest"] = True
        session.setdefault("lang", get_preferred_lang())
        return redirect(url_for("home"))
    except Exception as e:
        app.logger.error(f"Guest error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        try:
            uname = (request.form.get("username") or "").strip()
            pw = (request.form.get("password") or "")

            if not uname or not pw:
                flash("Username e password richiesti")
                return redirect(url_for("register"))

            if uname in USERS:
                flash("Username già esistente")
                return redirect(url_for("register"))

            # Crea nuovo utente con struttura completa
            USERS[uname] = {
                "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
                "premium": False,
                "is_admin": False,
                "created_at": datetime.utcnow().isoformat(),
                "history": [],
                "daily_count": {"date": now_ymd(), "count": 0}
            }
            persist_users_and_codes()

            session["username"] = uname
            session["is_guest"] = False
            return redirect(url_for("home"))
        except Exception as e:
            app.logger.error(f"Register error: {e}")
            return jsonify({"error": f"Errore registrazione: {str(e)}"}), 500

    # GET - mostra form o fallback HTML
    try:
        return render_template("auth.html", title="Registrazione", button="Crea account")
    except:
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Registrazione</title></head>
        <body>
            <h1>Registrazione</h1>
            <form method="post">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Crea account</button>
            </form>
            <a href="/">Torna indietro</a>
        </body>
        </html>
        '''

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        try:
            uname = (request.form.get("username") or "").strip()
            pw = (request.form.get("password") or "")

            if not uname or not pw:
                flash("Username e password richiesti")
                return redirect(url_for("login"))

            u = USERS.get(uname)
            if not u:
                flash("Credenziali non valide")
                return redirect(url_for("login"))

            ph = u.get("password_hash")
            if isinstance(ph, str):
                ph = ph.encode()

            if ph and bcrypt.checkpw(pw.encode(), ph):
                session["username"] = uname
                session["is_guest"] = False
                return redirect(url_for("home"))

            flash("Credenziali non valide")
            return redirect(url_for("login"))
        except Exception as e:
            app.logger.error(f"Login error: {e}")
            return jsonify({"error": f"Errore login: {str(e)}"}), 500

    # GET - mostra form o fallback HTML
    try:
        return render_template("auth.html", title="Login", button="Accedi")
    except:
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body>
            <h1>Login</h1>
            <form method="post">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                <button type="submit">Accedi</button>
            </form>
            <a href="/">Torna indietro</a>
        </body>
        </html>
        '''

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("welcome"))

@app.route("/home")
@login_required
def home():
    try:
        uname = session.get("username")
        is_guest = session.get("is_guest", False)
        u = USERS.get(uname) if not is_guest else None
        
        plan = "premium" if (u and u.get("premium")) else "free"
        used = user_message_count(u) if u else 0
        history = []
        
        if u and "history" in u:
            max_items = HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE
            history = [{"role": m.get("role", "user"), "content": m.get("content", "")} 
                       for m in u.get("history", [])[-(max_items*2):]]
        
        # Fallback HTML se template non esiste
        try:
            return render_template("home.html",
                                   username=(uname if not is_guest else "Ospite"),
                                   plan=plan,
                                   premium=(u.get("premium") if u else False),
                                   created_at=(u.get("created_at") if u else ""),
                                   buy_link=BUY_LINK,
                                   history=history,
                                   free_limit=FREE_DAILY_LIMIT,
                                   used_today=used,
                                   lang=session.get("lang", "it"),
                                   is_guest=is_guest)
        except Exception as template_error:
            app.logger.error(f"Template error: {template_error}")
            # HTML fallback semplice
            history_html = "".join([f"<p><b>{h['role']}:</b> {h['content']}</p>" for h in history])
            return f'''
            <!DOCTYPE html>
            <html>
            <head><title>EMI SUPER BOT - Home</title></head>
            <body>
                <h1>Ciao {uname}!</h1>
                <p>Piano: {plan} | Messaggi oggi: {used}/{FREE_DAILY_LIMIT}</p>
                <form action="/chat" method="post">
                    <textarea name="message" placeholder="Scrivi un messaggio..." required></textarea><br>
                    <button type="submit">Invia</button>
                </form>
                <h2>Cronologia:</h2>
                {history_html}
                <a href="/logout">Logout</a>
            </body>
            </html>
            '''
    except Exception as e:
        app.logger.error(f"Home error: {e}")
        return jsonify({"error": f"Errore caricamento home: {str(e)}"}), 500

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    try:
        uname = session.get("username")
        is_guest = session.get("is_guest", False)
        u = USERS.get(uname) if not is_guest else None

        data = request.get_json() or {}
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify({"error": "Messaggio vuoto"}), 400

        # Controllo limite giornaliero per utenti free
        if (not is_guest) and u and (not u.get("premium")):
            count = increment_daily(u)
            if count > FREE_DAILY_LIMIT:
                return jsonify({"error": "Limite giornaliero raggiunto. Passa a premium."}), 429

        # Prepara cronologia
        max_pairs = HISTORY_PREMIUM if (u and u.get("premium")) else HISTORY_FREE
        recent = (u.get("history", []) if u else [])[-(max_pairs*2):]
        ctx = [{"role": "system", "content": "Sei EMI SUPER BOT. Rispondi nella stessa lingua dell'utente in modo amichevole e professionale."}]
        
        for m in recent:
            if m.get("role") and m.get("content"):
                ctx.append({"role": m["role"], "content": m["content"]})
        ctx.append({"role": "user", "content": message})

        # Chiamata al modello
        model = "llama-3.1-70b-versatile" if (u and u.get("premium")) else "llama-3.1-8b-instant"
        ai_text = None
        
        if client:
            try:
                resp = client.chat.completions.create(
                    model=model, 
                    messages=ctx, 
                    max_tokens=1024,
                    temperature=0.7
                )
                ai_text = resp.choices[0].message.content
            except Exception as exc:
                app.logger.error(f"Model API error: {exc}")
                ai_text = "Mi dispiace, si è verificato un errore con il modello AI. Riprova più tardi."
        else:
            ai_text = f"Ciao! Ho ricevuto il tuo messaggio: '{message[:100]}'. (Nota: API Groq non configurata, questa è una risposta simulata)"

        # Salva cronologia (non per ospiti)
        if not is_guest and u:
            now_ts = time.time()
            if "history" not in u:
                u["history"] = []
            
            u["history"].append({"role": "user", "content": message, "ts": now_ts})
            u["history"].append({"role": "assistant", "content": ai_text, "ts": time.time()})
            
            max_items = (HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE) * 2
            if len(u["history"]) > max_items:
                u["history"] = u["history"][-max_items:]
            persist_users_and_codes()

        return jsonify({"reply": ai_text})
    
    except Exception as e:
        app.logger.error(f"Chat error: {e}")
        return jsonify({"error": f"Errore durante la chat: {str(e)}"}), 500

# Upload
ALLOWED_IMG = {"png", "jpg", "jpeg", "gif", "svg", "webp"}
ALLOWED_VIDEO = {"mp4", "webm", "mov", "ogg"}

def allowed_file(filename, allowed_set):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_set

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    try:
        if "file" not in request.files:
            return jsonify({"error": "Nessun file"}), 400
        
        f = request.files["file"]
        if f.filename == "":
            return jsonify({"error": "File non selezionato"}), 400
        
        filename = f.filename
        ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
        
        if allowed_file(filename, ALLOWED_IMG.union(ALLOWED_VIDEO)):
            safe_name = secrets.token_hex(8) + "." + ext
            dest = os.path.join(STATIC_UPLOADS, safe_name)
            f.save(dest)
            url = url_for("static", filename=f"uploads/{safe_name}", _external=True)
            
            uname = session.get("username")
            is_guest = session.get("is_guest", False)
            if not is_guest:
                u = USERS.get(uname)
                if u:
                    if "history" not in u:
                        u["history"] = []
                    u["history"].append({
                        "role": "user", 
                        "content": f"[file caricato] {url}", 
                        "ts": time.time()
                    })
                    persist_users_and_codes()
            
            return jsonify({"ok": True, "url": url})
        else:
            return jsonify({"error": "Tipo di file non consentito"}), 400
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/generate-image", methods=["POST"])
@login_required
def generate_image():
    try:
        data = request.get_json() or {}
        prompt = (data.get("prompt") or "abstract").strip()[:200]
        color = data.get("color") or ("#" + secrets.token_hex(3))
        
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024">
  <rect width="100%" height="100%" fill="{color}"/>
  <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle"
    font-family="Arial" font-size="48" fill="#ffffff">{prompt[:40]}</text>
</svg>'''
        
        fname = f"gen_{int(time.time())}_{secrets.token_hex(4)}.svg"
        path = os.path.join(STATIC_GENERATED, fname)
        with open(path, "w", encoding="utf-8") as f:
            f.write(svg)
        
        url = url_for("static", filename=f"generated/{fname}", _external=True)
        
        uname = session.get("username")
        if not session.get("is_guest", False):
            u = USERS.get(uname)
            if u:
                if "history" not in u:
                    u["history"] = []
                u["history"].append({
                    "role": "assistant", 
                    "content": f"[immagine generata] {url}", 
                    "ts": time.time()
                })
                persist_users_and_codes()
        
        return jsonify({"ok": True, "url": url})
    except Exception as e:
        app.logger.error(f"Generate image error: {e}")
        return jsonify({"error": str(e)}), 500

# Admin routes
@app.route("/admin")
@admin_required
def admin():
    try:
        uv = {}
        for k, v in USERS.items():
            uv[k] = {
                "premium": v.get("premium", False), 
                "is_admin": v.get("is_admin", False), 
                "created_at": v.get("created_at", "N/A")
            }
        
        try:
            return render_template("admin.html", 
                                   users=uv, 
                                   codes=sorted(list(VALID_PREMIUM_CODES)), 
                                   used=USED_PREMIUM_CODES)
        except:
            # Fallback HTML
            users_html = "".join([f"<li>{k}: Premium={v['premium']}, Admin={v['is_admin']}</li>" for k, v in uv.items()])
            codes_html = "".join([f"<li>{c}</li>" for c in sorted(list(VALID_PREMIUM_CODES))])
            return f'''
            <!DOCTYPE html>
            <html>
            <head><title>Admin Panel</title></head>
            <body>
                <h1>Admin Panel</h1>
                <h2>Utenti:</h2>
                <ul>{users_html}</ul>
                <h2>Codici Premium:</h2>
                <ul>{codes_html}</ul>
                <form action="/admin/generate_codes" method="post">
                    <input type="number" name="n" value="3" min="1" max="200">
                    <button>Genera Codici</button>
                </form>
                <a href="/home">Home</a>
            </body>
            </html>
            '''
    except Exception as e:
        app.logger.error(f"Admin error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/generate_codes", methods=["POST"])
@admin_required
def admin_generate_codes():
    try:
        n = int(request.form.get("n", "3"))
        n = max(1, min(n, 200))
        created = []
        for _ in range(n):
            code = secrets.token_hex(6)
            VALID_PREMIUM_CODES.add(code)
            created.append(code)
        persist_users_and_codes()
        return jsonify({"created": created})
    except Exception as e:
        app.logger.error(f"Generate codes error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/toggle_premium/<username>", methods=["POST"])
@admin_required
def admin_toggle_premium(username):
    try:
        if username not in USERS:
            return "Utente non trovato", 400
        USERS[username]["premium"] = not USERS[username].get("premium", False)
        persist_users_and_codes()
        return redirect(url_for("admin"))
    except Exception as e:
        app.logger.error(f"Toggle premium error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/delete_user/<username>", methods=["POST"])
@admin_required
def admin_delete_user(username):
    try:
        if username in USERS:
            del USERS[username]
            persist_users_and_codes()
        return redirect(url_for("admin"))
    except Exception as e:
        app.logger.error(f"Delete user error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/revoke_code", methods=["POST"])
@admin_required
def admin_revoke_code():
    try:
        code = request.form.get("code")
        if code in VALID_PREMIUM_CODES:
            VALID_PREMIUM_CODES.remove(code)
            persist_users_and_codes()
        return redirect(url_for("admin"))
    except Exception as e:
        app.logger.error(f"Revoke code error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/upgrade", methods=["POST"])
@login_required
def upgrade():
    try:
        uname = session.get("username")
        code = (request.form.get("code") or "").strip()
        
        if not code:
            flash("Nessun codice fornito")
            return redirect(url_for("home"))
        
        if code in USED_PREMIUM_CODES:
            flash("Codice già utilizzato")
            return redirect(url_for("home"))
        
        if code not in VALID_PREMIUM_CODES:
            flash("Codice non valido")
            return redirect(url_for("home"))
        
        USED_PREMIUM_CODES.add(code)
        u = USERS.get(uname)
        if u:
            u["premium"] = True
            persist_users_and_codes()
            flash("Aggiornato a premium! Grazie!")
        
        return redirect(url_for("home"))
    except Exception as e:
        app.logger.error(f"Upgrade error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    try:
        payload = request.get_data()
        sig = request.headers.get("X-Gumroad-Signature") or request.headers.get("x-gumroad-signature")
        
        if GUMROAD_SECRET:
            computed = hmac_new(GUMROAD_SECRET.encode(), payload, sha1).hexdigest()
            if computed != sig:
                return "Firma non valida", 403
        
        code = secrets.token_hex(6)
        VALID_PREMIUM_CODES.add(code)
        persist_users_and_codes()
        return jsonify({"ok": True, "code": code})
    except Exception as e:
        app.logger.error(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time(), "groq": client is not None})

@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Errore interno del server:")
    return jsonify({"error": "Errore interno del server", "details": str(e)}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Pagina non trovata"}), 404

@app.errorhandler(Exception)
def handle_exception(e):
    app.logger.exception("Eccezione non gestita:")
    return jsonify({"error": "Si è verificato un errore", "details": str(e)}), 500

if __name__ == "__main__":
    try:
        persist_users_and_codes()
        print(f"✅ Server avviato su http://0.0.0.0:{PORT}")
        print(f"✅ Groq API: {'Configurata' if client else 'Non disponibile'}")
        print(f"✅ Utenti demo: admin, utente1, premiumtester")
        app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
    except Exception as e:
        print(f"❌ Errore avvio: {e}")
