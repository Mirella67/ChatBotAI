"""
app.py — EMI SUPER BOT (Premium Top)
Single-file Flask app with:
- Register / Login / Guest
- bcrypt password hashes persisted in data.json
- Admin panel (create users, generate/revoke premium codes)
- Premium: permanent history; Free: daily message limit + 30-day retention
- Guest: no persisted history
- Upload images/videos to static/uploads, generated media in static/generated
- Webhook skeleton for Gumroad
- Simple placeholder media-generation endpoint (replace with real API calls)
- Inline templates via render_template_string to avoid missing TemplateNotFound
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
from werkzeug.utils import secure_filename

from flask import (
    Flask, request, jsonify, session, render_template_string,
    redirect, url_for, send_from_directory
)
import bcrypt

# If you use Groq / OpenAI, import their client and configure below.
# from groq import Groq
# client = Groq(api_key=os.getenv("GROQ_API_KEY", ""))

# ---------------------------
# Configuration / ENV
# ---------------------------
DATA_FILE = "data.json"
UPLOAD_FOLDER = Path("static/uploads")
GENERATED_FOLDER = Path("static/generated")
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp", "mp4", "mov", "webm", "avi"}

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")
FLASK_SECRET = os.getenv("FLASK_SECRET", None) or secrets.token_urlsafe(32)
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD", None)  # optional quick admin pass
BUY_LINK = os.getenv("BUY_LINK", "https://micheleguerra.gumroad.com/l/superchatbot")
GUMROAD_SECRET = os.getenv("GUMROAD_SECRET", None)
PORT = int(os.getenv("PORT", "10000"))
DEBUG = os.getenv("DEBUG", "0") == "1"

FREE_DAILY_LIMIT = 20            # free messages per day
HISTORY_FREE = 8                 # last pairs used for context for free
HISTORY_PREMIUM = 40             # for premium users
GUEST_PREFIX = "__guest__"

# create folders if missing
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
GENERATED_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = FLASK_SECRET

# ---------------------------
# Persistence (data.json)
# ---------------------------

def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_data_atomic(data):
    # ensure password_hash are strings for json
    d = {
        "users": {},
        "valid_codes": list(data.get("valid_codes", [])),
        "used_codes": list(data.get("used_codes", []))
    }
    users = data.get("users", {})
    for uname, u in users.items():
        copy_u = dict(u)
        ph = copy_u.get("password_hash")
        if isinstance(ph, (bytes, bytearray)):
            copy_u["password_hash"] = ph.decode("utf-8", errors="ignore")
        # else if string, leave as is
        d["users"][uname] = copy_u

    # write atomically
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    os.replace(tmp, DATA_FILE)

# load or initialize
_DATA = load_data()
USERS = {}
VALID_PREMIUM_CODES = set()
USED_PREMIUM_CODES = set()

# Rehydrate
if _DATA:
    # users -> ensure password_hash bytes
    for k, v in _DATA.get("users", {}).items():
        user_copy = dict(v)
        ph = user_copy.get("password_hash")
        if isinstance(ph, str):
            user_copy["password_hash"] = ph.encode("utf-8")
        USERS[k] = user_copy
    VALID_PREMIUM_CODES = set(_DATA.get("valid_codes", []))
    USED_PREMIUM_CODES = set(_DATA.get("used_codes", []))
else:
    # seed default users if empty
    USERS = {}
    # initial accounts (for demo). On first run these will be created and saved.
    USERS["admin"] = {
        "password_hash": bcrypt.hashpw(b"sB5Zj_@=ymQ!QGmd", bcrypt.gensalt()),
        "premium": True,
        "is_admin": True,
        "created_at": datetime.utcnow().isoformat(),
        "history": [],
        "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
    }
    USERS["utente1"] = {
        "password_hash": bcrypt.hashpw(b"efKgOaM^H0Uiq*", bcrypt.gensalt()),
        "premium": False,
        "is_admin": False,
        "created_at": datetime.utcnow().isoformat(),
        "history": [],
        "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
    }
    USERS["premiumtester"] = {
        "password_hash": bcrypt.hashpw(b"CtBVZ2)i!j4AosyT", bcrypt.gensalt()),
        "premium": True,
        "is_admin": False,
        "created_at": datetime.utcnow().isoformat(),
        "history": [],
        "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
    }
    # save initial
    save_data_atomic({"users": USERS, "valid_codes": list(VALID_PREMIUM_CODES), "used_codes": list(USED_PREMIUM_CODES)})

def persist_state():
    save_data_atomic({"users": USERS, "valid_codes": list(VALID_PREMIUM_CODES), "used_codes": list(USED_PREMIUM_CODES)})

# ---------------------------
# Helpers
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
        # guests not allowed
        if uname.startswith(GUEST_PREFIX):
            return "Admin access required", 403
        u = USERS.get(uname)
        if u and u.get("is_admin"):
            return f(*args, **kwargs)
        # fallback to ADMIN_PASSWORD_ENV
        supplied = request.args.get("admin_pw") or request.form.get("admin_pw") or request.headers.get("X-Admin-Pw")
        if ADMIN_PASSWORD_ENV and supplied == ADMIN_PASSWORD_ENV:
            return f(*args, **kwargs)
        return "Admin access required", 403
    return wrapped

def now_ymd():
    return datetime.utcnow().strftime("%Y-%m-%d")

def reset_daily_if_needed(u):
    today = now_ymd()
    dc = u.setdefault("daily_count", {"date": today, "count": 0})
    if dc.get("date") != today:
        dc["date"] = today
        dc["count"] = 0

def increment_daily(u):
    reset_daily_if_needed(u)
    u["daily_count"]["count"] += 1
    persist_state()
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

def cleanup_history_for_user(username):
    """Remove messages older than 30 days for non-premium users"""
    user = USERS.get(username)
    if not user:
        return
    if user.get("premium"):
        return
    cutoff = time.time() - (30 * 24 * 60 * 60)
    h = user.get("history", [])
    newh = [m for m in h if m.get("ts", 0) >= cutoff]
    if len(newh) != len(h):
        user["history"] = newh
        persist_state()

def guess_language_from_request():
    # basic guess using Accept-Language header; return language code (like 'en', 'it', 'es')
    al = request.accept_languages
    if not al:
        return "en"
    lang = al.best or "en"
    # take first two letters
    return lang.split("-")[0]

def is_allowed_file(filename):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in ALLOWED_EXT

# ---------------------------
# Inline templates (simple)
# ---------------------------

BASE_HTML = """
<!doctype html>
<html lang="{{ lang or 'en' }}">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>EMI SUPER BOT — Premium</title>
  <style>
    body{font-family:Inter, system-ui, Arial; margin:0; background:#0b1220; color:#e6eef8}
    header{display:flex;justify-content:space-between;padding:12px 20px;background:rgba(255,255,255,0.02)}
    .container{max-width:1100px;margin:20px auto;padding:16px}
    .panel{background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); border-radius:12px;padding:16px;}
    .row{display:flex;gap:16px}
    .col-3{width:320px}
    .col-flex{flex:1}
    .chat-window{height:520px; display:flex; flex-direction:column}
    .messages{flex:1; overflow:auto; padding:12px; display:flex; flex-direction:column; gap:8px}
    .bubble{max-width:72%; padding:10px 12px; border-radius:12px}
    .bubble.bot{align-self:flex-start; background:rgba(255,255,255,0.04)}
    .bubble.user{align-self:flex-end; background:linear-gradient(90deg,#0ea5a4,#06b6d4)}
    .controls{display:flex;gap:8px;padding:12px;border-top:1px solid rgba(255,255,255,0.02)}
    textarea{flex:1; min-height:56px; border-radius:8px; background:transparent; color:inherit; border:1px solid rgba(255,255,255,0.04); padding:8px}
    button{background:#10b981;border:none;color:#012018;padding:10px 14px;border-radius:8px;font-weight:700}
    .small{font-size:12px;color:#94a3b8}
    form.inline{display:flex;gap:8px;align-items:center}
    a.link{color:#9be7d6}
    @media(max-width:900px){.row{flex-direction:column}.col-3{width:100%}}
  </style>
</head>
<body>
<header>
  <div class="brand">EMI SUPER BOT — Premium Top</div>
  <div>
    {% if username %}
      <span class="small">Hello, <strong>{{ username }}</strong></span>
      &nbsp;&nbsp;
      <a class="link" href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a class="link" href="{{ url_for('welcome') }}">Welcome</a> &nbsp;
    {% endif %}
  </div>
</header>
<div class="container">
  {% block content %}{% endblock %}
</div>
</body>
</html>
"""

WELCOME_HTML = """
{% extends base %}
{% block content %}
<div style="max-width:720px;margin:0 auto" class="panel">
  <h2>Welcome to EMI SUPER BOT</h2>
  <p class="small">Choose an option to start</p>
  <div style="display:flex;gap:8px;margin-top:12px">
    <a href="{{ url_for('login') }}"><button>Login</button></a>
    <a href="{{ url_for('register') }}"><button>Register</button></a>
    <form method="post" action="{{ url_for('guest') }}">
      <button type="submit">Enter as Guest</button>
    </form>
  </div>
  <p class="small" style="margin-top:12px">If you are browsing from {{ country or 'your country' }}, we'll show the app in your language (if available).</p>
</div>
{% endblock %}
"""

AUTH_HTML = """
{% extends base %}
{% block content %}
<div class="panel" style="max-width:520px;margin:0 auto">
  <h2>{{ title }}</h2>
  <form method="post">
    <div style="margin-bottom:8px"><label>Username<br><input name="username" required style="width:100%;padding:8px;border-radius:6px"></label></div>
    <div style="margin-bottom:8px"><label>Password<br><input name="password" type="password" required style="width:100%;padding:8px;border-radius:6px"></label></div>
    {% if extra %}<div style="margin-bottom:8px">{{ extra }}</div>{% endif %}
    <div><button type="submit">{{ button }}</button></div>
  </form>
  <div class="small" style="margin-top:8px">Note: demo in-memory + JSON persistence. Use a DB in production.</div>
</div>
{% endblock %}
"""

HOME_HTML = """
{% extends base %}
{% block content %}
<div class="row">
  <div class="col-flex panel">
    <div class="chat-window">
      <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:8px">
        <div><strong>EMI SUPER BOT</strong><div class="small">Intelligent assistant</div></div>
        <div><span class="small">Plan: <strong>{{ plan|upper }}</strong></span></div>
      </div>

      <div class="messages" id="messages">
        {% for m in history %}
          <div class="bubble {{ 'user' if m.role=='user' else 'bot' }}">{{ m.content }}</div>
        {% endfor %}
      </div>

      <div class="controls">
        <textarea id="prompt" placeholder="Type something..."></textarea>
        <button id="sendBtn">Send</button>
      </div>
      <div class="small" style="padding:8px 12px">Free daily limit: {{ free_limit }} — Used today: {{ used_today }}</div>

      <div style="margin-top:12px">
        <form id="uploadForm" enctype="multipart/form-data">
          <input type="file" name="file" id="fileInput">
          <button type="button" id="uploadBtn">Upload</button>
          <button type="button" id="genBtn">Generate image/video (placeholder)</button>
        </form>
        <div id="uploadResult" class="small"></div>
      </div>
    </div>
  </div>

  <div class="col-3 panel">
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div><strong>{{ username or 'Guest' }}</strong><div class="small">Account</div></div>
        <div style="width:44px;height:44px;border-radius:999px;background:#0284c7;display:flex;align-items:center;justify-content:center">U</div>
      </div>
    </div>

    <div style="margin-bottom:12px"><strong>Account</strong>
      <div class="small">Type: <strong>{{ plan }}</strong></div>
      <div class="small">Created: {{ created_at }}</div>
      <div style="margin-top:8px">
        {% if not premium %}
        <form action="{{ url_for('upgrade') }}" method="post" class="inline">
          <input name="code" placeholder="Premium code">
          <button type="submit">Use code</button>
        </form>
        <div style="margin-top:8px">
          <button onclick="window.open('{{ buy_link }}','_blank')">Buy Premium</button>
        </div>
        {% else %}
        <div class="small">You're Premium — thanks! 💎</div>
        {% endif %}
      </div>
    </div>

    <div><strong>Actions</strong>
      <div style="margin-top:8px">
        <form action="{{ url_for('clear_history') }}" method="post"><button type="submit">Clear history</button></form>
      </div>
    </div>

    <div style="margin-top:12px"><strong>Admin</strong>
      <div class="small">Go to <a href="{{ url_for('admin') }}">Admin Panel</a> (protected)</div>
    </div>
  </div>
</div>

<script>
const sendBtn = document.getElementById('sendBtn');
const prompt = document.getElementById('prompt');
const messagesEl = document.getElementById('messages');

function appendMessage(text, who){
  const d = document.createElement('div');
  d.className = 'bubble ' + (who==='user'?'user':'bot');
  d.textContent = text;
  messagesEl.appendChild(d);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

sendBtn.addEventListener('click', async ()=>{
  const txt = prompt.value.trim();
  if(!txt) return;
  appendMessage(txt,'user');
  prompt.value = '';
  const typing = document.createElement('div');
  typing.className = 'bubble bot';
  typing.textContent = 'EMI is typing…';
  messagesEl.appendChild(typing);
  messagesEl.scrollTop = messagesEl.scrollHeight;

  const res = await fetch('/chat', {
    method:'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({message: txt})
  });
  const data = await res.json();
  messagesEl.removeChild(typing);
  if(data.error){
    appendMessage("Error: "+data.error,'bot');
  } else {
    appendMessage(data.reply,'bot');
  }
});

// upload
document.getElementById('uploadBtn').addEventListener('click', async ()=>{
  const fi = document.getElementById('fileInput');
  if(!fi.files.length){ alert('Choose a file'); return; }
  const fd = new FormData();
  fd.append('file', fi.files[0]);
  const r = await fetch('/upload', { method:'POST', body: fd });
  const j = await r.json();
  document.getElementById('uploadResult').textContent = j.message || JSON.stringify(j);
});

// generate placeholder
document.getElementById('genBtn').addEventListener('click', async ()=>{
  const r = await fetch('/generate_media', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({type:'image', prompt:'a colorful abstract emoji-style icon'})});
  const j = await r.json();
  if(j.url){
    const el = document.createElement('div');
    el.innerHTML = '<a href="'+j.url+'" target="_blank">Open generated media</a>';
    document.getElementById('uploadResult').appendChild(el);
  } else {
    document.getElementById('uploadResult').textContent = JSON.stringify(j);
  }
});
</script>
{% endblock %}
"""

ADMIN_HTML = """
{% extends base %}
{% block content %}
<div class="panel">
  <h2>Admin Panel</h2>

  <div style="margin-top:12px">
    <h3>Users</h3>
    <table style="width:100%;border-collapse:collapse">
      <tr><th>Name</th><th>Premium</th><th>Admin</th><th>Created</th><th>Actions</th></tr>
      {% for u in users %}
      <tr>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ u.username }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ 'YES' if u.premium else 'NO' }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ 'YES' if u.is_admin else 'NO' }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ u.created_at }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">
          <form style="display:inline" action="{{ url_for('admin_toggle_premium', username=u.username) }}" method="post"><button type="submit">Toggle Premium</button></form>
          <form style="display:inline" action="{{ url_for('admin_delete_user', username=u.username) }}" method="post"><button type="submit">Delete</button></form>
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div style="margin-top:12px">
    <h3>Generate Premium Codes</h3>
    <form method="post" action="{{ url_for('admin_generate_codes') }}">
      <input name="n" type="number" value="3" min="1" max="200">
      <button type="submit">Generate</button>
    </form>
    <div style="margin-top:8px"><strong>Valid codes</strong>
      <div style="background:#061220;padding:8px;border-radius:6px;max-height:160px;overflow:auto">
        {% for c in codes %}
          <div>{{ c }} {% if c in used %}<span class="small"> (USED)</span>{% endif %}</div>
        {% endfor %}
      </div>
    </div>
  </div>

  <div style="margin-top:12px">
    <h3>Create user</h3>
    <form method="post" action="{{ url_for('admin_create_user') }}">
      <input name="username" placeholder="username" required>
      <input name="password" placeholder="password" required>
      <label><input type="checkbox" name="is_admin"> is admin</label>
      <button type="submit">Create</button>
    </form>
  </div>
</div>
{% endblock %}
"""

# ---------------------------
# Routes: Welcome / Guest / Auth
# ---------------------------

@app.route("/welcome", methods=["GET"])
def welcome():
    # Set guessed language
    lang = guess_language_from_request()
    country = request.accept_languages.best or ""
    return render_template_string(WELCOME_HTML, base=BASE_HTML, lang=lang, country=country, username=session.get("username"))

@app.route("/guest", methods=["POST"])
def guest():
    # create temporary session for guest (no persisted history)
    token = GUEST_PREFIX + secrets.token_hex(8)
    session["username"] = token
    session["guest"] = True
    # no persisted user record created
    return redirect(url_for("home"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        uname = (request.form.get("username") or "").strip()
        pw = (request.form.get("password") or "")
        if not uname or not pw:
            return "Username and password required", 400
        if uname in USERS:
            return "Username already exists", 400
        USERS[uname] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()),
            "premium": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        persist_state()
        session["username"] = uname
        session.pop("guest", None)
        return redirect(url_for("home"))
    # GET
    lang = guess_language_from_request()
    return render_template_string(AUTH_HTML, base=BASE_HTML, title="Register", button="Create account", extra=None, lang=lang, username=None)

@app.route("/login", methods=["GET", "POST"])
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
            ph = ph.encode("utf-8")
        if ph and bcrypt.checkpw(pw.encode(), ph):
            session["username"] = uname
            session.pop("guest", None)
            return redirect(url_for("home"))
        return "Invalid credentials", 400
    # GET
    lang = guess_language_from_request()
    return render_template_string(AUTH_HTML, base=BASE_HTML, title="Login", button="Login", extra=None, lang=lang, username=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("welcome"))

# ---------------------------
# Home & Chat
# ---------------------------
@app.route("/")
@login_required
def index():
    return redirect(url_for("home"))

@app.route("/home")
@login_required
def home():
    uname = session.get("username")
    u = USERS.get(uname) if not (uname and uname.startswith(GUEST_PREFIX)) else None
    plan = "premium" if (u and u.get("premium")) else "guest" if (uname and uname.startswith(GUEST_PREFIX)) else "free"
    used = user_message_count(u) if u else 0
    history = []
    if u:
        history = [{"role": m["role"], "content": m["content"]} for m in u.get("history", [])[-(HISTORY_PREMIUM*2):]]
    return render_template_string(HOME_HTML, base=BASE_HTML, username=uname, plan=plan, premium=(u.get("premium") if u else False),
                                  created_at=(u.get("created_at") if u else ""), history=history,
                                  free_limit=FREE_DAILY_LIMIT, used_today=used, buy_link=BUY_LINK)

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    uname = session.get("username")
    # guest can chat (no persistence)
    is_guest = uname.startswith(GUEST_PREFIX) if uname else False
    u = USERS.get(uname) if not is_guest else None
    if not is_guest and not u:
        return jsonify({"error": "User not found"}), 400

    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400

    # enforce free daily limit for non-premium non-guest users
    if not is_guest:
        if not u.get("premium"):
            count = increment_daily(u)
            if count > FREE_DAILY_LIMIT:
                return jsonify({"error": "Free daily limit reached. Upgrade to premium."}), 429

    # cleanup old history for non-premium
    if not is_guest and not u.get("premium"):
        cleanup_history_for_user(uname)

    # prepare history (last N messages)
    max_pairs = HISTORY_PREMIUM if (u and u.get("premium")) else HISTORY_FREE
    recent = u.get("history", [])[-(max_pairs*2):] if u else []
    ctx = [{"role":"system", "content":"You are EMI SUPER BOT. Reply in the user's language."}]
    for m in recent:
        ctx.append({"role": m["role"], "content": m["content"]})
    ctx.append({"role":"user","content": message})

    # choose model: placeholder strings — replace with actual client calls
    model = "llama-3.1-70b" if (u and u.get("premium")) else "llama-3.1-8b-instant"

    # --- CALL THE MODEL API HERE ---
    # Replace this block with a real model call (Groq / OpenAI / other)
    try:
        # Placeholder reply (simulate model)
        ai_text = f"[SIMULATED {model} REPLY] I received: {message}"
        # If you integrate a real client, set ai_text to API response.
    except Exception as exc:
        return jsonify({"error": f"Model API error: {str(exc)}"}), 500

    # store history (unless guest)
    timestamp = time.time()
    if not is_guest:
        u.setdefault("history", []).append({"role":"user","content": message, "ts": timestamp})
        u.setdefault("history", []).append({"role":"bot","content": ai_text, "ts": timestamp + 0.001})
        # trim
        max_items = (HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE) * 2
        if len(u["history"]) > max_items:
            u["history"] = u["history"][-max_items:]
        persist_state()

    return jsonify({"reply": ai_text})

# ---------------------------
# Uploads & Media generation
# ---------------------------
@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    if not is_allowed_file(file.filename):
        return jsonify({"error": "File type not allowed"}), 400
    filename = secure_filename(file.filename)
    save_to = UPLOAD_FOLDER / filename
    # ensure unique by adding random suffix if exists
    if save_to.exists():
        filename = f"{secrets.token_hex(4)}_{filename}"
        save_to = UPLOAD_FOLDER / filename
    file.save(save_to)
    url = url_for("static", filename=f"uploads/{filename}", _external=True)
    return jsonify({"ok": True, "message": "Uploaded", "url": url})

@app.route("/generate_media", methods=["POST"])
@login_required
def generate_media():
    """
    Placeholder generation endpoint.
    body JSON: { "type": "image"|"video", "prompt": "..." }
    Replace with real model API call.
    """
    body = request.get_json() or {}
    typ = body.get("type", "image")
    prompt = body.get("prompt", "abstract icon")
    # Here you would call Groq / OpenAI image API and save the result to GENERATED_FOLDER
    # For now: create a tiny placeholder file to simulate
    fname = f"gen_{int(time.time())}_{secrets.token_hex(4)}.txt"
    path = GENERATED_FOLDER / fname
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Generated {typ} for prompt: {prompt}\n(This is a placeholder. Replace with real generated file.)")
    url = url_for("static", filename=f"generated/{fname}", _external=True)
    return jsonify({"ok": True, "url": url, "prompt": prompt})

# ---------------------------
# Account actions
# ---------------------------
@app.route("/upgrade", methods=["POST"])
@login_required
def upgrade():
    uname = session.get("username")
    if uname.startswith(GUEST_PREFIX):
        return "Guests cannot upgrade — register first", 400
    code = (request.form.get("code") or "").strip()
    if not code:
        return "No code provided", 400
    if code in USED_PREMIUM_CODES:
        return "Code already used", 400
    if code not in VALID_PREMIUM_CODES:
        return "Invalid code", 400
    USED_PREMIUM_CODES.add(code)
    USERS[uname]["premium"] = True
    persist_state()
    return redirect(url_for("home"))

@app.route("/clear_history", methods=["POST"])
@login_required
def clear_history():
    uname = session.get("username")
    if uname.startswith(GUEST_PREFIX):
        return redirect(url_for("home"))
    USERS[uname]["history"] = []
    persist_state()
    return redirect(url_for("home"))

# ---------------------------
# Admin routes
# ---------------------------
@app.route("/admin")
@admin_required
def admin():
    uv = []
    for username, data in USERS.items():
        uv.append(type("U", (), {
            "username": username,
            "premium": data.get("premium"),
            "is_admin": data.get("is_admin"),
            "created_at": data.get("created_at")
        }))
    return render_template_string(ADMIN_HTML, base=BASE_HTML, users=uv, codes=sorted(list(VALID_PREMIUM_CODES)), used=USED_PREMIUM_CODES, username=session.get("username"))

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
    persist_state()
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
        "created_at": datetime.utcnow().isoformat(),
        "history": [],
        "daily_count": {"date": now_ymd(), "count": 0}
    }
    persist_state()
    return redirect(url_for("admin"))

@app.route("/admin/toggle_premium/<username>", methods=["POST"])
@admin_required
def admin_toggle_premium(username):
    if username not in USERS:
        return "no user", 400
    USERS[username]["premium"] = not USERS[username].get("premium", False)
    persist_state()
    return redirect(url_for("admin"))

@app.route("/admin/delete_user/<username>", methods=["POST"])
@admin_required
def admin_delete_user(username):
    if username in USERS:
        del USERS[username]
        persist_state()
    return redirect(url_for("admin"))

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
        persist_state()
    return redirect(url_for("admin"))

# ---------------------------
# Webhook: Gumroad skeleton
# ---------------------------
@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    payload = request.get_data()
    sig = request.headers.get("X-Gumroad-Signature") or request.headers.get("x-gumroad-signature")
    if GUMROAD_SECRET:
        if not verify_gumroad_signature(payload, sig):
            return "invalid signature", 403
    data = request.form.to_dict() or request.get_json(silent=True) or {}
    # create code per purchase (demo). In production, email the buyer
    code = secrets.token_hex(6)
    VALID_PREMIUM_CODES.add(code)
    persist_state()
    return jsonify({"ok": True, "code": code})

# ---------------------------
# Health
# ---------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time()})

# ---------------------------
# Static file helpers (if you want to serve uploaded/generated directly)
# ---------------------------
@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=False)

@app.route("/generated/<path:filename>")
def generated_file(filename):
    return send_from_directory(GENERATED_FOLDER, filename, as_attachment=False)

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    print("EMI SUPER BOT starting. Set GROQ_API_KEY in env before production.")
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
