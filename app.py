#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EMI SUPER BOT - Il bot più potente al mondo
Combina ChatGPT + Claude + Gemini + tutto il resto

INSTALLAZIONE:
pip install flask bcrypt groq

AVVIO:
python app.py

Account demo: admin / admin123
"""

import os
import time
import secrets
import json
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, session, redirect, url_for, render_template_string
import bcrypt

# Groq AI
try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False
    print("⚠️ Groq not installed. Run: pip install groq")

# ============================================
# CONFIGURAZIONE
# ============================================
DATA_FILE = "data.json"
GROQ_KEY = "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"
GUMROAD_LINK = "https://micheleguerra.gumroad.com/l/emi-premium"

# Crea cartelle
os.makedirs("static/uploads", exist_ok=True)
os.makedirs("static/generated", exist_ok=True)

# Flask app
app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# Groq client
groq_client = None
if HAS_GROQ and GROQ_KEY:
    try:
        groq_client = Groq(api_key=GROQ_KEY)
        print("✅ AI Engine: Active")
    except Exception as e:
        print(f"⚠️ AI Engine error: {e}")

# ============================================
# DATABASE FUNCTIONS
# ============================================
def load_db():
    """Carica database da file JSON"""
    if not os.path.exists(DATA_FILE):
        return {
            "users": {},
            "codes": [],
            "used_codes": []
        }
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {"users": {}, "codes": [], "used_codes": []}

def save_db():
    """Salva database su file JSON"""
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(DB, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ Errore salvataggio: {e}")
        return False

# Carica DB
DB = load_db()
USERS = DB.get("users", {})
CODES = set(DB.get("codes", []))
USED_CODES = set(DB.get("used_codes", []))

# ============================================
# UTILITY FUNCTIONS
# ============================================
def get_today():
    """Ritorna data corrente YYYY-MM-DD"""
    return datetime.utcnow().strftime("%Y-%m-%d")

def persist_db():
    """Salva tutto il database"""
    DB["users"] = USERS
    DB["codes"] = list(CODES)
    DB["used_codes"] = list(USED_CODES)
    save_db()

def login_required(f):
    """Decorator: richiede login"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    """Decorator: richiede admin"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        username = session.get("username")
        if not username:
            return redirect(url_for("index"))
        user = USERS.get(username, {})
        if not user.get("is_admin", False):
            return "Admin required", 403
        return f(*args, **kwargs)
    return wrapper

# ============================================
# CREA UTENTE DEMO
# ============================================
if "admin" not in USERS:
    USERS["admin"] = {
        "password": bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode(),
        "premium": True,
        "is_admin": True,
        "history": [],
        "daily": {"date": get_today(), "count": 0}
    }
    persist_db()
    print("✅ Utente demo creato: admin / admin123")

# ============================================
# HTML TEMPLATES (inline per semplicità)
# ============================================

INDEX_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>EMI SUPER BOT</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }
        h1 {
            font-size: 2.5rem;
            color: #667eea;
            text-align: center;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            text-align: center;
            margin-bottom: 30px;
        }
        .btn {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            text-decoration: none;
            display: block;
            text-align: center;
            transition: all 0.3s;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
        }
        .btn-secondary {
            background: #10a37f;
            color: white;
        }
        .btn-secondary:hover {
            background: #0d8c6d;
        }
        .btn-guest {
            background: transparent;
            color: #667eea;
            border: 2px solid #667eea;
        }
        .btn-guest:hover {
            background: #667eea;
            color: white;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🤖 EMI SUPER BOT</h1>
        <p>The most powerful AI in the world</p>
        <a href="/register" class="btn btn-secondary">✨ Create Account</a>
        <a href="/login" class="btn btn-primary">🔐 Login</a>
        <form action="/guest" method="post" style="margin: 0;">
            <button type="submit" class="btn btn-guest">👤 Guest Mode</button>
        </form>
    </div>
</body>
</html>
"""

AUTH_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{{title}} - EMI SUPER BOT</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }
        h1 {
            font-size: 2rem;
            color: #667eea;
            text-align: center;
            margin-bottom: 30px;
        }
        .error {
            background: #fee;
            color: #c33;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            text-align: center;
        }
        input {
            width: 100%;
            padding: 15px;
            margin: 10px 0;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 16px;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 15px;
            margin: 15px 0 10px;
            border: none;
            border-radius: 10px;
            background: #667eea;
            color: white;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
        }
        button:hover {
            background: #5568d3;
        }
        a {
            display: block;
            text-align: center;
            color: #667eea;
            text-decoration: none;
            margin-top: 15px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{title}}</h1>
        {% if error %}
        <div class="error">{{error}}</div>
        {% endif %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">{{button}}</button>
        </form>
        <a href="/">← Back</a>
    </div>
</body>
</html>
"""

CHAT_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>EMI SUPER BOT - Chat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: system-ui, -apple-system, sans-serif;
            background: #343541;
            color: #ececf1;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .header {
            background: #202123;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid #444;
        }
        .header h1 {
            font-size: 18px;
            font-weight: 600;
        }
        .header-right {
            display: flex;
            gap: 15px;
            align-items: center;
        }
        .badge {
            background: #10a37f;
            color: white;
            padding: 5px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge.free {
            background: #565869;
        }
        .btn-upgrade {
            background: #10a37f;
            color: white;
            padding: 8px 16px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
        }
        .btn-logout {
            background: transparent;
            color: #ececf1;
            padding: 8px 16px;
            border: 1px solid #565869;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
        }
        .chat-container {
            flex: 1;
            overflow-y: auto;
            padding: 20px;
        }
        .message {
            max-width: 800px;
            margin: 0 auto 20px;
            padding: 20px;
            border-radius: 12px;
            display: flex;
            gap: 15px;
        }
        .message.user {
            background: #343541;
        }
        .message.bot {
            background: #444654;
        }
        .avatar {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            flex-shrink: 0;
        }
        .content {
            flex: 1;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        .input-area {
            border-top: 1px solid #565869;
            padding: 20px;
            background: #343541;
        }
        .input-container {
            max-width: 800px;
            margin: 0 auto;
            display: flex;
            gap: 10px;
        }
        #messageInput {
            flex: 1;
            padding: 15px;
            border: 1px solid #565869;
            border-radius: 12px;
            background: #40414f;
            color: #ececf1;
            font-size: 16px;
            resize: none;
            min-height: 52px;
            max-height: 200px;
            font-family: inherit;
        }
        #messageInput:focus {
            outline: none;
            border-color: #8e8ea0;
        }
        #sendBtn {
            padding: 0 20px;
            border: none;
            border-radius: 12px;
            background: #19c37d;
            color: white;
            cursor: pointer;
            font-size: 18px;
        }
        #sendBtn:hover {
            background: #15a76a;
        }
        #sendBtn:disabled {
            background: #565869;
            cursor: not-allowed;
        }
        .loading {
            display: flex;
            gap: 5px;
        }
        .loading div {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #8e8ea0;
            animation: bounce 1.4s infinite ease-in-out both;
        }
        .loading div:nth-child(1) { animation-delay: -0.32s; }
        .loading div:nth-child(2) { animation-delay: -0.16s; }
        @keyframes bounce {
            0%, 80%, 100% { transform: scale(0); }
            40% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🤖 EMI SUPER BOT</h1>
        <div class="header-right">
            <span class="badge {% if premium %}{% else %}free{% endif %}">
                {% if premium %}PREMIUM{% else %}FREE{% endif %}
            </span>
            {% if not premium %}
            <button class="btn-upgrade" onclick="window.open('{{gumroad}}', '_blank')">
                ⭐ Upgrade
            </button>
            {% endif %}
            <button class="btn-logout" onclick="location.href='/logout'">
                Logout
            </button>
        </div>
    </div>
    
    <div class="chat-container" id="chatContainer">
        {% for msg in history %}
        <div class="message {{msg.role}}">
            <div class="avatar">{{  '👤' if msg.role == 'user' else '🤖' }}</div>
            <div class="content">{{msg.content}}</div>
        </div>
        {% endfor %}
    </div>
    
    <div class="input-area">
        <div class="input-container">
            <textarea id="messageInput" placeholder="Send a message..."></textarea>
            <button id="sendBtn">▲</button>
        </div>
    </div>
    
    <script>
        const chat = document.getElementById('chatContainer');
        const input = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        
        // Auto-resize textarea
        input.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = this.scrollHeight + 'px';
        });
        
        // Send on Enter
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        
        // Send button click
        sendBtn.addEventListener('click', sendMessage);
        
        async function sendMessage() {
            const message = input.value.trim();
            if (!message) return;
            
            sendBtn.disabled = true;
            input.disabled = true;
            
            addMessage('user', message);
            input.value = '';
            input.style.height = 'auto';
            
            const loadingId = showLoading();
            
            try {
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: message })
                });
                
                const data = await response.json();
                hideLoading(loadingId);
                
                if (data.error) {
                    addMessage('bot', '❌ ' + data.error);
                } else {
                    addMessage('bot', data.reply);
                }
            } catch (error) {
                hideLoading(loadingId);
                addMessage('bot', '❌ Connection error. Please try again.');
            }
            
            sendBtn.disabled = false;
            input.disabled = false;
            input.focus();
        }
        
        function addMessage(role, content) {
            const div = document.createElement('div');
            div.className = 'message ' + role;
            div.innerHTML = `
                <div class="avatar">${role === 'user' ? '👤' : '🤖'}</div>
                <div class="content">${escapeHtml(content)}</div>
            `;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
        }
        
        function showLoading() {
            const div = document.createElement('div');
            div.className = 'message bot';
            div.id = 'loading-' + Date.now();
            div.innerHTML = `
                <div class="avatar">🤖</div>
                <div class="loading">
                    <div></div><div></div><div></div>
                </div>
            `;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;
            return div.id;
        }
        
        function hideLoading(id) {
            const el = document.getElementById(id);
            if (el) el.remove();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Scroll to bottom on load
        chat.scrollTop = chat.scrollHeight;
    </script>
</body>
</html>
"""

# ============================================
# ROUTES
# ============================================

@app.route("/")
def index():
    """Homepage"""
    if "username" in session:
        return redirect(url_for("chat"))
    return render_template_string(INDEX_HTML)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Registrazione nuovo utente"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            return render_template_string(AUTH_HTML, 
                title="Register", 
                button="Create Account",
                error="Username and password required")
        
        if username in USERS:
            return render_template_string(AUTH_HTML,
                title="Register",
                button="Create Account",
                error="Username already exists")
        
        # Crea nuovo utente
        USERS[username] = {
            "password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
            "premium": False,
            "is_admin": False,
            "history": [],
            "daily": {"date": get_today(), "count": 0}
        }
        persist_db()
        
        session["username"] = username
        return redirect(url_for("chat"))
    
    return render_template_string(AUTH_HTML, 
        title="Register", 
        button="Create Account",
        error=None)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login utente"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            return render_template_string(AUTH_HTML,
                title="Login",
                button="Login",
                error="Username and password required")
        
        user = USERS.get(username)
        if not user:
            return render_template_string(AUTH_HTML,
                title="Login",
                button="Login",
                error="Invalid credentials")
        
        # Verifica password
        stored_pw = user.get("password", "")
        if isinstance(stored_pw, str):
            stored_pw = stored_pw.encode()
        
        if not bcrypt.checkpw(password.encode(), stored_pw):
            return render_template_string(AUTH_HTML,
                title="Login",
                button="Login",
                error="Invalid credentials")
        
        session["username"] = username
        return redirect(url_for("chat"))
    
    return render_template_string(AUTH_HTML,
        title="Login",
        button="Login",
        error=None)

@app.route("/guest", methods=["POST"])
def guest():
    """Modalità ospite"""
    session["username"] = "guest_" + secrets.token_hex(4)
    session["is_guest"] = True
    return redirect(url_for("chat"))

@app.route("/logout")
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for("index"))

@app.route("/chat")
@login_required
def chat():
    """Pagina chat principale"""
    username = session.get("username")
    is_guest = session.get("is_guest", False)
    
    if is_guest:
        user = {"premium": False, "history": []}
    else:
        user = USERS.get(username, {})
    
    history = user.get("history", [])[-20:]  # Ultime 20 righe
    
    return render_template_string(CHAT_HTML,
        premium=user.get("premium", False),
        history=history,
        gumroad=GUMROAD_LINK)

@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    """API per inviare messaggi"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request"}), 400
        
        message = data.get("message", "").strip()
        if not message:
            return jsonify({"error": "Empty message"}), 400
        
        username = session.get("username")
        is_guest = session.get("is_guest", False)
        
        # Get user
        if is_guest:
            user = {"premium": False, "history": []}
        else:
            user = USERS.get(username, {})
            if not user:
                return jsonify({"error": "User not found"}), 404
        
        # Check daily limit for free users
        if not user.get("premium", False) and not is_guest:
            daily = user.get("daily", {"date": get_today(), "count": 0})
            if daily.get("date") != get_today():
                daily = {"date": get_today(), "count": 0}
                user["daily"] = daily
            
            if daily.get("count", 0) >= 20:
                return jsonify({"error": "Daily limit reached. Upgrade to Premium for unlimited messages!"}), 429
            
            daily["count"] = daily.get("count", 0) + 1
        
        # Prepare context
        history = user.get("history", [])[-8:]
        
        # Build AI prompt
        now = datetime.utcnow()
        system_prompt = f"""You are EMI SUPER BOT, the world's most advanced AI assistant.

Current Date: {now.strftime("%A, %B %d, %Y")}
Current Time: {now.strftime("%H:%M")} UTC
Year: 2024

You combine the best features of ChatGPT, Claude, and Gemini.
You NEVER make mistakes and always provide perfectly accurate information.

IMPORTANT WORLD FACTS (2024-2025):
- US President: Donald Trump (inaugurated January 20, 2025)
- Italy PM: Giorgia Meloni
- France President: Emmanuel Macron
- UK PM: Rishi Sunak
- Major AI: ChatGPT, Claude, Gemini, EMI SUPER BOT

INSTRUCTIONS:
1. Always respond in the SAME LANGUAGE the user writes to you
2. Provide detailed, accurate, and well-structured responses
3. Use bullet points, numbering, and clear formatting
4. Be conversational yet professional
5. Never invent information - if unsure, say so"""
        
        messages = [{"role": "system", "content": system_prompt}]
        
        for h in history:
            messages.append({
                "role": h.get("role", "user"),
                "content": h.get("content", "")
            })
        
        messages.append({"role": "user", "content": message})
        
        # Call AI
        if groq_client:
            try:
                model = "llama-3.1-70b-versatile" if user.get("premium") else "llama-3.1-8b-instant"
                response = groq_client.chat.completions.create(
                    model=model,
                    messages=messages,
                    max_tokens=1024,
                    temperature=0.7
                )
                reply = response.choices[0].message.content
            except Exception as e:
                app.logger.error(f"Groq error: {e}")
                reply = "I apologize, but I'm experiencing a temporary issue. Please try again."
        else:
            # Fallback response
            reply = f"Hello! I received your message: \"{message[:100]}...\"\n\n(Note: Groq AI is not configured. Install with: pip install groq)"
        
        # Save to history (only for registered users)
        if not is_guest:
            user.setdefault("history", [])
            user["history"].append({"role": "user", "content": message})
            user["history"].append({"role": "bot", "content": reply})
            
            # Keep only last 40 messages
            if len(user["history"]) > 40:
                user["history"] = user["history"][-40:]
            
            persist_db()
        
        return jsonify({"reply": reply})
        
    except Exception as e:
        app.logger.error(f"Chat error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/upgrade", methods=["POST"])
@login_required
def api_upgrade():
    """Attiva codice premium"""
    try:
        data = request.get_json() or {}
        code = data.get("code", "").strip()
        
        if not code:
            return jsonify({"error": "No code provided"}), 400
        
        if code in USED_CODES:
            return jsonify({"error": "Code already used"}), 400
        
        if code not in CODES:
            return jsonify({"error": "Invalid code"}), 400
        
        username = session.get("username")
        if session.get("is_guest"):
            return jsonify({"error": "Guests cannot upgrade"}), 400
        
        user = USERS.get(username)
        if not user:
            return jsonify({"error": "User not found"}), 404
        
        # Attiva premium
        user["premium"] = True
        USED_CODES.add(code)
        persist_db()
        
        return jsonify({"success": True, "message": "Premium activated!"})
        
    except Exception as e:
        app.logger.error(f"Upgrade error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin")
@admin_required
def admin():
    """Pannello admin"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Admin Panel</title>
        <style>
            body { font-family: system-ui; padding: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; }
            h1 { color: #333; margin-bottom: 30px; }
            .section { margin: 30px 0; }
            button { padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 8px; cursor: pointer; margin: 5px; }
            button:hover { background: #5568d3; }
            table { width: 100%; border-collapse: collapse; margin: 20px 0; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #667eea; color: white; }
            .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
            .badge-premium { background: #ffd700; color: #000; }
            .badge-free { background: #ccc; color: #333; }
            input { padding: 8px; margin: 5px; border: 1px solid #ddd; border-radius: 4px; }
            code { background: #f0f0f0; padding: 4px 8px; border-radius: 4px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔧 Admin Panel</h1>
            
            <div class="section">
                <h2>Generate Premium Codes</h2>
                <input type="number" id="numCodes" value="5" min="1" max="100">
                <button onclick="generateCodes()">Generate Codes</button>
                <div id="codesResult"></div>
            </div>
            
            <div class="section">
                <h2>Users ({{total_users}})</h2>
                <table>
                    <tr>
                        <th>Username</th>
                        <th>Plan</th>
                        <th>Admin</th>
                        <th>Messages Today</th>
                        <th>Actions</th>
                    </tr>
                    {% for username, user in users.items() %}
                    <tr>
                        <td><strong>{{username}}</strong></td>
                        <td>
                            {% if user.premium %}
                            <span class="badge badge-premium">PREMIUM</span>
                            {% else %}
                            <span class="badge badge-free">FREE</span>
                            {% endif %}
                        </td>
                        <td>{% if user.is_admin %}✅{% else %}❌{% endif %}</td>
                        <td>{{user.daily.count if user.daily else 0}}</td>
                        <td>
                            <button onclick="togglePremium('{{username}}')">Toggle Premium</button>
                            <button onclick="deleteUser('{{username}}')">Delete</button>
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            <div class="section">
                <h2>Premium Codes</h2>
                <p><strong>Valid:</strong> {{valid_codes|length}} | <strong>Used:</strong> {{used_codes|length}}</p>
                <details>
                    <summary style="cursor: pointer; padding: 10px; background: #f0f0f0; border-radius: 4px;">
                        Show all codes ({{valid_codes|length}})
                    </summary>
                    <div style="margin-top: 10px;">
                        {% for code in valid_codes %}
                        <div style="padding: 8px; margin: 4px 0; background: #f9f9f9; border-radius: 4px;">
                            <code>{{code}}</code>
                            <button onclick="revokeCode('{{code}}')">Revoke</button>
                        </div>
                        {% endfor %}
                    </div>
                </details>
            </div>
            
            <a href="/chat"><button>← Back to Chat</button></a>
        </div>
        
        <script>
            async function generateCodes() {
                const n = document.getElementById('numCodes').value;
                const res = await fetch('/admin/generate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({count: parseInt(n)})
                });
                const data = await res.json();
                if (data.codes) {
                    document.getElementById('codesResult').innerHTML = 
                        '<h3>✅ Generated ' + data.codes.length + ' codes:</h3>' +
                        data.codes.map(c => '<div style="margin:5px 0"><code>' + c + '</code></div>').join('');
                }
            }
            
            async function togglePremium(username) {
                if (!confirm('Toggle premium for ' + username + '?')) return;
                const res = await fetch('/admin/toggle/' + username, {method: 'POST'});
                if (res.ok) location.reload();
            }
            
            async function deleteUser(username) {
                if (!confirm('Delete user ' + username + '? This cannot be undone!')) return;
                const res = await fetch('/admin/delete/' + username, {method: 'POST'});
                if (res.ok) location.reload();
            }
            
            async function revokeCode(code) {
                if (!confirm('Revoke code ' + code + '?')) return;
                const res = await fetch('/admin/revoke', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({code: code})
                });
                if (res.ok) location.reload();
            }
        </script>
    </body>
    </html>
    """
    
    return render_template_string(html,
        users=USERS,
        total_users=len(USERS),
        valid_codes=sorted(CODES),
        used_codes=USED_CODES)

@app.route("/admin/generate", methods=["POST"])
@admin_required
def admin_generate():
    """Genera codici premium"""
    try:
        data = request.get_json() or {}
        count = min(int(data.get("count", 5)), 100)
        
        new_codes = []
        for _ in range(count):
            code = secrets.token_hex(6)
            CODES.add(code)
            new_codes.append(code)
        
        persist_db()
        return jsonify({"success": True, "codes": new_codes})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/toggle/<username>", methods=["POST"])
@admin_required
def admin_toggle(username):
    """Toggle premium per utente"""
    if username not in USERS:
        return "User not found", 404
    USERS[username]["premium"] = not USERS[username].get("premium", False)
    persist_db()
    return "OK", 200

@app.route("/admin/delete/<username>", methods=["POST"])
@admin_required
def admin_delete(username):
    """Elimina utente"""
    if username in USERS:
        del USERS[username]
        persist_db()
    return "OK", 200

@app.route("/admin/revoke", methods=["POST"])
@admin_required
def admin_revoke():
    """Revoca codice premium"""
    data = request.get_json() or {}
    code = data.get("code")
    if code in CODES:
        CODES.remove(code)
        persist_db()
    return "OK", 200

@app.route("/webhook/gumroad", methods=["POST"])
def gumroad_webhook():
    """Webhook Gumroad per pagamenti automatici"""
    try:
        # Verifica firma (opzionale)
        # signature = request.headers.get("X-Gumroad-Signature")
        
        # Genera codice premium
        code = secrets.token_hex(6)
        CODES.add(code)
        persist_db()
        
        # In produzione: invia codice via email al cliente
        # email = request.form.get("email")
        # send_email(email, code)
        
        return jsonify({"success": True, "code": code}), 200
    except Exception as e:
        app.logger.error(f"Webhook error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    """Health check"""
    return jsonify({
        "status": "ok",
        "ai_engine": "active" if groq_client else "demo",
        "users": len(USERS),
        "codes": len(CODES)
    })

# ============================================
# ERROR HANDLERS
# ============================================
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Internal error:")
    return jsonify({"error": "Internal server error"}), 500

# ============================================
# MAIN
# ============================================
if __name__ == "__main__":
    print("")
    print("=" * 50)
    print("🚀 EMI SUPER BOT - Starting...")
    print("=" * 50)
    print(f"📍 URL: http://localhost:10000")
    print(f"🤖 AI Engine: {'✅ Active' if groq_client else '⚠️ Demo mode'}")
    print(f"👥 Users: {len(USERS)}")
    print(f"🎟️ Premium Codes: {len(CODES)}")
    print("")
    print("📝 Demo Account:")
    print("   Username: admin")
    print("   Password: admin123")
    print("")
    print("=" * 50)
    print("")
    
    # Avvia server
    app.run(
        host="0.0.0.0",
        port=10000,
        debug=False
    )
