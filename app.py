"""
app.py — EMI SUPER BOT (full single-file)
Features included:
- Register / Login / Logout
- Passwords hashed with bcrypt
- Admin panel (create users, generate/revoke premium codes, toggle premium)
- Premium codes (admin / webhook)
- Persistent storage in data.json (users, codes, history)
- Non-premium chat history auto-pruned after 30 days; premium kept forever
- Chat endpoints (integrate with Groq client or other LLM)
- Upload endpoints for images & videos (static/uploads)
- "Generate" endpoints for images & videos (stubs you must replace with real model calls)
- Gumroad webhook skeleton + Stripe checkout skeleton
- Basic PWA meta & manifest links included in HTML templates
- Comments and instructions in Italian
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
    Flask, request, jsonify, session, render_template_string,
    redirect, url_for, send_from_directory, abort
)
import bcrypt
from werkzeug.utils import secure_filename

# Optional: install stripe if you want stripe support
try:
    import stripe
except Exception:
    stripe = None

# Optional: replace / integrate Groq / other model client here
try:
    from groq import Groq
except Exception:
    Groq = None

# ---------------------------
# CONFIG / ENV
# ---------------------------
DATA_FILE = "data.json"
UPLOAD_FOLDER = Path("static/uploads")
GENERATED_FOLDER = Path("static/generated")
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "webp", "gif"}
ALLOWED_VIDEO_EXT = {"mp4", "mov", "webm", "mkv"}

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "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")
FLASK_SECRET = os.getenv("FLASK_SECRET", secrets.token_urlsafe(32))
ADMIN_PASSWORD_ENV = os.getenv("ADMIN_PASSWORD", None)
BUY_LINK = os.getenv("BUY_LINK", "https://micheleguerra.gumroad.com/l/superchatbot")
GUMROAD_SECRET = os.getenv("GUMROAD_SECRET", None)
STRIPE_SECRET = os.getenv("STRIPE_SECRET", None)  # if provided, Stripe integration will work
STRIPE_PUBLISHABLE = os.getenv("STRIPE_PUBLISHABLE", None)
PORT = int(os.getenv("PORT", "10000"))
DEBUG = os.getenv("DEBUG", "0") == "1"

# create static folders if missing
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
GENERATED_FOLDER.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = FLASK_SECRET

# initialize stripe if available and secret is set
if stripe and STRIPE_SECRET:
    stripe.api_key = STRIPE_SECRET

# Groq client (if installed and key present)
client = Groq(api_key=GROQ_API_KEY) if (Groq and GROQ_API_KEY) else None

# ---------------------------
# Persistence helpers
# ---------------------------
def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_data(data):
    # write atomically
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, DATA_FILE)

DATA = load_data()

# initialize in-memory stores from DATA
USERS = DATA.get("users", {})
VALID_PREMIUM_CODES = set(DATA.get("valid_codes", []))
USED_PREMIUM_CODES = set(DATA.get("used_codes", []))

# ensure admin user exists (for first-run) - you can change password after
if "admin" not in USERS:
    pw = "sB5Zj_@=ymQ!QGmd"  # keep or change
    USERS["admin"] = {
        "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
        "premium": True,
        "is_admin": True,
        "created_at": datetime.utcnow().isoformat(),
        "history": [],
        "daily_count": {"date": datetime.utcnow().strftime("%Y-%m-%d"), "count": 0}
    }
    DATA["users"] = USERS
    save_data(DATA)

# ---------------------------
# Config / Limits
# ---------------------------
FREE_DAILY_LIMIT = 20
HISTORY_FREE = 8
HISTORY_PREMIUM = 40
NON_PREMIUM_RETENTION_SECONDS = 30 * 24 * 60 * 60  # 30 days

# ---------------------------
# Helpers / decorators
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
        # fallback to ADMIN_PASSWORD_ENV via form/query/header
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

# ---------------------------
# History cleanup for non-premium users (30 days)
# ---------------------------
def cleanup_history(username):
    user = USERS.get(username)
    if not user:
        return
    if user.get("premium"):
        return
    cutoff = time.time() - NON_PREMIUM_RETENTION_SECONDS
    if "history" in user:
        user["history"] = [msg for msg in user["history"] if msg.get("ts", 0) >= cutoff]
        DATA["users"] = USERS
        save_data(DATA)

# ---------------------------
# Model interaction stubs (replace with actual calls)
# ---------------------------
def call_model_chat(context_messages, premium=False):
    """
    Replace this with your actual LLM call (Groq/OpenAI/etc).
    context_messages is a list of dicts {role, content}.
    Return the assistant reply string.
    """
    # Example: if Groq client is available, call it. Otherwise fallback to a canned answer.
    if client:
        try:
            model = "llama-3.1-70b" if premium else "llama-3.1-8b-instant"
            resp = client.chat.completions.create(model=model, messages=context_messages)
            return resp.choices[0].message.content
        except Exception as e:
            return f"[Model error: {str(e)}]"
    # fallback canned reply
    last_user = next((m["content"] for m in reversed(context_messages) if m["role"]=="user"), "")
    return f"Echo (local stub): {last_user}"

def generate_image_from_prompt(prompt_text, username=None):
    """
    Stub for image generation. Replace with real generator.
    For now, create a simple SVG file or placeholder PNG.
    Returns relative path to static/generated file.
    """
    filename = f"img_{int(time.time())}_{secrets.token_hex(4)}.svg"
    path = GENERATED_FOLDER / filename
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512">
      <rect width="100%" height="100%" fill="#667eea"/>
      <text x="50%" y="50%" font-size="20" fill="#fff" dominant-baseline="middle" text-anchor="middle">EMI Image</text>
      <text x="50%" y="60%" font-size="12" fill="#fff" dominant-baseline="middle" text-anchor="middle">{prompt_text[:60]}</text>
    </svg>"""
    path.write_text(svg, encoding="utf-8")
    return f"/static/generated/{filename}"

def generate_video_from_prompt(prompt_text, username=None):
    """
    Stub for video generation. Replace with real generator.
    Creates a small placeholder text file renamed .mp4 (not a real video).
    Replace with real video generation pipeline.
    """
    filename = f"vid_{int(time.time())}_{secrets.token_hex(4)}.txt"
    path = GENERATED_FOLDER / filename
    path.write_text(f"Placeholder video for prompt: {prompt_text}\nGenerated at {datetime.utcnow().isoformat()}", encoding="utf-8")
    # return path under static/generated - consumer should handle placeholder
    return f"/static/generated/{filename}"

# ---------------------------
# TEMPLATE STRINGS (embedded, so no external templates required)
# ---------------------------
BASE_HTML = """
<!doctype html>
<html lang="it">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>EMI SUPER BOT — Premium</title>
  <link rel="manifest" href="/manifest.json">
  <meta name="theme-color" content="#667eea">
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
    .btn{padding:6px 10px;border-radius:6px;background:#3b82f6;color:#fff;border:none}
    @media(max-width:900px){.row{flex-direction:column}.col-3{width:100%}}
  </style>
</head>
<body>
<header>
  <div class="brand">EMI SUPER BOT — Premium Top</div>
  <div>
    {% if username %}
      <span class="small">Ciao, <strong>{{ username }}</strong></span>
      &nbsp;&nbsp;
      <a class="link" href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a class="link" href="{{ url_for('login') }}">Login</a> &nbsp;
      <a class="link" href="{{ url_for('register') }}">Register</a>
    {% endif %}
  </div>
</header>
<div class="container">
  {% block content %}{% endblock %}
</div>

<script>
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('/service-worker.js').catch(()=>console.log('sw registration failed'));
}
</script>
</body>
</html>
"""

HOME_HTML = """
{% extends base %}
{% block content %}
<div class="row">
  <div class="col-flex panel">
    <div style="display:flex;justify-content:space-between;align-items:center;padding-bottom:8px">
      <div><strong>EMI SUPER BOT</strong><div class="small">Assistente intelligente</div></div>
      <div><span class="small">Plan: <strong>{{ plan|upper }}</strong></span></div>
    </div>

    <div class="chat-window panel">
      <div class="messages" id="messages">
        {% for m in history %}
          <div class="bubble {{ 'user' if m.role=='user' else 'bot' }}">{{ m.content }}</div>
        {% endfor %}
      </div>

      <div class="controls">
        <textarea id="prompt" placeholder="Scrivi qualcosa..."></textarea>
        <button id="sendBtn">Invia</button>
      </div>

      <div style="display:flex;gap:8px;padding:8px">
        <form id="uploadForm" enctype="multipart/form-data">
          <input type="file" id="fileInput" name="file">
          <button type="button" id="uploadBtn" class="btn">Upload</button>
        </form>

        <form id="genImageForm">
          <input id="imgPrompt" placeholder="Prompt per immagine">
          <button type="button" id="genImageBtn" class="btn">Generate Image</button>
        </form>

        <form id="genVideoForm">
          <input id="vidPrompt" placeholder="Prompt per video">
          <button type="button" id="genVideoBtn" class="btn">Generate Video</button>
        </form>
      </div>

      <div class="small" style="padding:8px 12px">Limite giornaliero free: {{ free_limit }} — Usati oggi: {{ used_today }}</div>
    </div>
  </div>

  <div class="col-3 panel">
    <div style="margin-bottom:12px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div><strong>{{ username or 'Ospite' }}</strong><div class="small">Account</div></div>
        <div style="width:44px;height:44px;border-radius:999px;background:#0284c7;display:flex;align-items:center;justify-content:center">U</div>
      </div>
    </div>

    <div style="margin-bottom:12px"><strong>Account</strong>
      <div class="small">Tipo: <strong>{{ plan }}</strong></div>
      <div class="small">Creato: {{ created_at }}</div>
      <div style="margin-top:8px">
        {% if not premium %}
        <form action="{{ url_for('upgrade') }}" method="post" class="inline">
          <input name="code" placeholder="Codice premium">
          <button type="submit">Usa codice</button>
        </form>
        <div style="margin-top:8px">
          <button onclick="window.open('{{ buy_link }}','_blank')" class="btn">Compra Premium</button>
        </div>
        {% else %}
        <div class="small">Sei Premium — grazie! 💎</div>
        {% endif %}
      </div>
    </div>

    <div><strong>Azioni</strong>
      <div style="margin-top:8px">
        <form action="{{ url_for('clear_history') }}" method="post"><button type="submit" class="btn">Pulisci cronologia</button></form>
      </div>
    </div>

    <div style="margin-top:12px"><strong>Admin</strong>
      <div class="small">Vai a <a href="{{ url_for('admin') }}">Admin Panel</a> (protetto)</div>
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
  typing.textContent = 'EMI sta scrivendo…';
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
    appendMessage("Errore: "+data.error,'bot');
  } else {
    appendMessage(data.reply,'bot');
  }
});

// file upload
document.getElementById('uploadBtn').addEventListener('click', async ()=>{
  const input = document.getElementById('fileInput');
  if(!input.files.length) return alert('Select a file');
  const fd = new FormData();
  fd.append('file', input.files[0]);
  const res = await fetch('/upload', {method:'POST', body: fd});
  const data = await res.json();
  if(data.ok){
    appendMessage('Uploaded: ' + data.url, 'bot');
    // optionally show preview
  } else alert('Upload failed: ' + data.error);
});

// generate image
document.getElementById('genImageBtn').addEventListener('click', async ()=>{
  const p = document.getElementById('imgPrompt').value.trim();
  if(!p) return alert('Enter prompt');
  const res = await fetch('/generate/image', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({prompt:p})
  });
  const data = await res.json();
  if(data.ok){
    appendMessage('Image: ' + data.url, 'bot');
  } else appendMessage('Gen failed: '+(data.error||'unknown'),'bot');
});

// generate video
document.getElementById('genVideoBtn').addEventListener('click', async ()=>{
  const p = document.getElementById('vidPrompt').value.trim();
  if(!p) return alert('Enter prompt');
  const res = await fetch('/generate/video', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({prompt:p})
  });
  const data = await res.json();
  if(data.ok){
    appendMessage('Video: ' + data.url, 'bot');
  } else appendMessage('Gen failed: '+(data.error||'unknown'),'bot');
});
</script>
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
    <div><button type="submit" class="btn">{{ button }}</button></div>
  </form>
  <div class="small" style="margin-top:8px">Nota: demo in-memory + JSON persistence. Usa DB per produzione.</div>
</div>
{% endblock %}
"""

ADMIN_HTML = """
{% extends base %}
{% block content %}
<div class="panel">
  <h2>Admin Panel</h2>

  <h3>Users</h3>
  <table style="width:100%;border-collapse:collapse;">
    <tr><th>Username</th><th>Premium</th><th>Admin</th><th>Created</th><th>Actions</th></tr>
    {% for u in users %}
      <tr>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ u.username }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ 'YES' if u.premium else 'NO' }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ 'YES' if u.is_admin else 'NO' }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">{{ u.created_at }}</td>
        <td style="padding:6px;border-top:1px solid rgba(255,255,255,0.02)">
          {% if not u.premium %}
            <form method="post" action="/admin/make_premium" style="display:inline;">
              <input type="hidden" name="username" value="{{ u.username }}">
              <button class="btn">Make Premium</button>
            </form>
          {% else %}
            <form method="post" action="/admin/remove_premium" style="display:inline;">
              <input type="hidden" name="username" value="{{ u.username }}">
              <button class="btn" style="background:#c62828;">Remove Premium</button>
            </form>
          {% endif %}
          <form method="post" action="/admin/delete_user" style="display:inline;">
            <input type="hidden" name="username" value="{{ u.username }}">
            <button class="btn" style="background:#333;">Delete</button>
          </form>
        </td>
      </tr>
    {% endfor %}
  </table>

  <h3 style="margin-top:20px;">Generate Premium Codes</h3>
  <form method="post" action="/admin/generate_codes">
    <input name="n" type="number" value="3" min="1" max="200">
    <button class="btn">Generate</button>
  </form>

  <div style="margin-top:12px">
    <strong>Valid codes</strong>
    <div style="background:#061220;padding:8px;border-radius:6px;max-height:160px;overflow:auto">
      {% for c in codes %}
        <div>{{ c }} {% if c in used %}<span class="small"> (USED)</span>{% endif %}</div>
      {% endfor %}
    </div>
  </div>

  <h3 style="margin-top:20px;">Create user</h3>
  <form method="post" action="/admin/create_user">
    <input name="username" placeholder="username" required>
    <input name="password" placeholder="password" required>
    <label><input type="checkbox" name="is_admin"> is admin</label>
    <button class="btn">Create</button>
  </form>

</div>
{% endblock %}
"""

# ---------------------------
# Routes: auth
# ---------------------------
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
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
            "premium": False,
            "is_admin": False,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        DATA["users"] = USERS
        save_data(DATA)
        session["username"] = uname
        return redirect(url_for("home"))
    return render_template_string(AUTH_HTML, base=BASE_HTML, title="Register", button="Create account", extra=None, username=None)

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
        if bcrypt.checkpw(pw.encode(), u["password_hash"].encode() if isinstance(u["password_hash"], str) else u["password_hash"]):
            session["username"] = uname
            return redirect(url_for("home"))
        return "Invalid credentials", 400
    return render_template_string(AUTH_HTML, base=BASE_HTML, title="Login", button="Login", extra=None, username=None)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------------
# Home & chat endpoints
# ---------------------------
@app.route("/")
@login_required
def home():
    uname = session.get("username")
    u = USERS.get(uname, {})
    plan = "premium" if u.get("premium") else "free"
    used = user_message_count(u)
    history_list = u.get("history", [])[-(HISTORY_PREMIUM*2):] if u.get("history") else []
    # convert to objects with attributes for Jinja loops
    history = [{"role": item["role"], "content": item["content"]} for item in history_list]
    return render_template_string(
        HOME_HTML, base=BASE_HTML, username=uname, plan=plan, premium=u.get("premium"),
        created_at=u.get("created_at"), buy_link=BUY_LINK, history=history,
        free_limit=FREE_DAILY_LIMIT, used_today=used
    )

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    uname = session.get("username")
    u = USERS.get(uname)
    if not u:
        return jsonify({"error": "User not found"}), 400

    # cleanup old history automatically for non-premium
    cleanup_history(uname)

    data = request.get_json() or {}
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Empty message"}), 400

    # daily free limit
    if not u.get("premium"):
        count = increment_daily(u)
        if count > FREE_DAILY_LIMIT:
            return jsonify({"error": "Free daily limit reached. Upgrade to premium."}), 429

    # prepare context
    max_pairs = HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE
    recent = u.get("history", [])[-(max_pairs*2):] if u.get("history") else []
    ctx = [{"role":"system", "content":"Sei EMI SUPER BOT. Rispondi nella stessa lingua dell'utente."}]
    ctx.extend([{"role":m["role"], "content": m["content"]} for m in recent])
    ctx.append({"role":"user","content":message})

    # call the model (stub or real)
    try:
        ai_text = call_model_chat(ctx, premium=u.get("premium"))
    except Exception as exc:
        return jsonify({"error": f"Model API error: {str(exc)}"}), 500

    # store history (with ts)
    u.setdefault("history", []).append({"role":"user","content": message, "ts": time.time()})
    u.setdefault("history", []).append({"role":"bot","content": ai_text, "ts": time.time()})

    # trim by max items
    max_items = (HISTORY_PREMIUM if u.get("premium") else HISTORY_FREE) * 2
    if len(u["history"]) > max_items:
        u["history"] = u["history"][-max_items:]

    DATA["users"] = USERS
    save_data(DATA)

    return jsonify({"reply": ai_text})

# ---------------------------
# Upload endpoint
# ---------------------------
def allowed_file(filename, kind=None):
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if kind == "image":
        return ext in ALLOWED_IMAGE_EXT
    if kind == "video":
        return ext in ALLOWED_VIDEO_EXT
    # auto-check both
    return ext in ALLOWED_IMAGE_EXT.union(ALLOWED_VIDEO_EXT)

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"ok": False, "error": "No selected file"}), 400

    filename = secure_filename(file.filename)
    if not allowed_file(filename):
        return jsonify({"ok": False, "error": "File type not allowed"}), 400

    # save
    out_name = f"{int(time.time())}_{secrets.token_hex(6)}_{filename}"
    out_path = UPLOAD_FOLDER / out_name
    file.save(out_path)

    url = f"/static/uploads/{out_name}"
    return jsonify({"ok": True, "url": url})

# ---------------------------
# Generation endpoints (image/video)
# ---------------------------
@app.route("/generate/image", methods=["POST"])
@login_required
def generate_image():
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "Empty prompt"}), 400

    uname = session.get("username")
    u = USERS.get(uname)

    # check daily limits for non-premium if you want to charge generation separately
    # (omitted for brevity)

    try:
        url = generate_image_from_prompt(prompt, username=uname)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    # optionally store a reference in user history
    u.setdefault("history", []).append({"role":"user","content": f"[generated image prompt] {prompt}", "ts": time.time()})
    u.setdefault("history", []).append({"role":"bot","content": f"[image generated] {url}", "ts": time.time()})
    DATA["users"] = USERS
    save_data(DATA)

    return jsonify({"ok": True, "url": url})

@app.route("/generate/video", methods=["POST"])
@login_required
def generate_video():
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"ok": False, "error": "Empty prompt"}), 400

    uname = session.get("username")
    u = USERS.get(uname)

    try:
        url = generate_video_from_prompt(prompt, username=uname)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    u.setdefault("history", []).append({"role":"user","content": f"[generated video prompt] {prompt}", "ts": time.time()})
    u.setdefault("history", []).append({"role":"bot","content": f"[video generated] {url}", "ts": time.time()})
    DATA["users"] = USERS
    save_data(DATA)

    return jsonify({"ok": True, "url": url})

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
    DATA["users"] = USERS
    DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
    DATA["used_codes"] = list(USED_PREMIUM_CODES)
    save_data(DATA)
    return redirect(url_for("home"))

@app.route("/clear_history", methods=["POST"])
@login_required
def clear_history():
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

    return render_template_string(
        ADMIN_HTML,
        base=BASE_HTML,
        users=uv,
        codes=sorted(list(VALID_PREMIUM_CODES)),
        used=USED_PREMIUM_CODES
    )

@app.route("/admin/make_premium", methods=["POST"])
@admin_required
def make_premium():
    username = request.form.get("username")
    if not username:
        return redirect(url_for("admin"))
    if username in USERS:
        USERS[username]["premium"] = True
        DATA["users"] = USERS
        save_data(DATA)
    return redirect(url_for("admin"))

@app.route("/admin/remove_premium", methods=["POST"])
@admin_required
def remove_premium():
    username = request.form.get("username")
    if not username:
        return redirect(url_for("admin"))
    if username in USERS:
        USERS[username]["premium"] = False
        DATA["users"] = USERS
        save_data(DATA)
    return redirect(url_for("admin"))

@app.route("/admin/delete_user", methods=["POST"])
@admin_required
def admin_delete_user():
    username = request.form.get("username")
    if username in USERS:
        del USERS[username]
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
        "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
        "premium": False,
        "is_admin": is_admin,
        "created_at": datetime.utcnow().isoformat(),
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
# Webhook: Gumroad skeleton
# ---------------------------
@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    payload = request.get_data()
    sig = request.headers.get("X-Gumroad-Signature") or request.headers.get("x-gumroad-signature")
    if GUMROAD_SECRET:
        if not verify_gumroad_signature(payload, sig):
            return "invalid signature", 403
    # demo: create a premium code for each purchase
    code = secrets.token_hex(6)
    VALID_PREMIUM_CODES.add(code)
    DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
    save_data(DATA)
    return jsonify({"ok": True, "code": code})

# ---------------------------
# Stripe checkout skeleton (if stripe is configured)
# ---------------------------
@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    if not stripe:
        return jsonify({"error": "Stripe not available on server"}), 500
    # price_id must be configured on Stripe dashboard; replace below
    price_id = os.getenv("STRIPE_PRICE_ID")
    if not price_id:
        return jsonify({"error": "STRIPE_PRICE_ID not configured"}), 500
    domain = request.host_url.rstrip("/")
    try:
        session_obj = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='payment',
            success_url=domain + '/stripe-success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=domain + '/stripe-cancel',
        )
        return jsonify({"url": session_obj.url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/stripe-success")
def stripe_success():
    # in production verify session and map to user; here show success page
    return "<h1>Payment successful</h1><p>Contact admin to activate premium automatically or use webhook integration.</p>"

# ---------------------------
# Gumroad / Stripe webhook for issuing codes or activating premium
# (You must secure and verify payloads in production)
# ---------------------------
@app.route("/webhook/stripe", methods=["POST"])
def stripe_webhook():
    # skeleton: verify signature using stripe library and your endpoint secret
    # then generate code or mark user premium (you need to map email to username)
    return jsonify({"ok": True})

# ---------------------------
# Health
# ---------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "ts": time.time()})

# ---------------------------
# PWA manifest + service worker endpoints (simple)
# ---------------------------
@app.route("/manifest.json")
def manifest():
    mf = {
        "name": "EMI SUPER BOT",
        "short_name": "EMI",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0b1220",
        "theme_color": "#667eea",
        "icons": [
            {"src": "/static/icon-192.png", "sizes":"192x192", "type":"image/png"},
            {"src": "/static/icon-512.png", "sizes":"512x512", "type":"image/png"}
        ]
    }
    return jsonify(mf)

# very small service worker that does nothing critical; if you want offline cache extend it
@app.route("/service-worker.js")
def service_worker():
    js = """
self.addEventListener('install', function(e){ self.skipWaiting(); });
self.addEventListener('activate', function(e){ self.clients.claim(); });
self.addEventListener('fetch', function(e){ /* you can add caching logic here */ });
"""
    return app.response_class(js, mimetype="application/javascript")

# ---------------------------
# Static generated/download endpoints handled by Flask static folder
# ---------------------------

# ---------------------------
# Run
# ---------------------------
if __name__ == "__main__":
    print("EMI SUPER BOT starting. Fill env vars for GROQ/STRIPE if needed.")
    # ensure data persisted before start
    DATA["users"] = USERS
    DATA["valid_codes"] = list(VALID_PREMIUM_CODES)
    DATA["used_codes"] = list(USED_PREMIUM_CODES)
    save_data(DATA)
    app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
