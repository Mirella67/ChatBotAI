# app.py - EMI SUPER BOT (VERSIONE COMPLETA CON UI STILE CHATGPT)
import os
import time
import secrets
import json
from datetime import datetime
from functools import wraps
from hashlib import sha1
from hmac import new as hmac_new

from flask import (
    Flask, request, jsonify, session, render_template_string,
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

app = Flask(__name__)
app.secret_key = FLASK_SECRET

client = None
if GROQ_AVAILABLE and GROQ_API_KEY:
    try:
        client = Groq(api_key=GROQ_API_KEY)
    except Exception as e:
        app.logger.error(f"Groq init error: {e}")

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
        supplied = request.args.get("admin_pw") or request.form.get("admin_pw")
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
        pw = "admin123"
        USERS["admin"] = {
            "password_hash": bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(),
            "premium": True,
            "is_admin": True,
            "created_at": datetime.utcnow().isoformat(),
            "history": [],
            "daily_count": {"date": now_ymd(), "count": 0}
        }
        changed = True
    if changed:
        persist_users_and_codes()

ensure_demo_users()

# ---------------------------
# HTML TEMPLATES
# ---------------------------
WELCOME_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EMI SUPER BOT</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 450px;
            width: 100%;
        }
        h1 {
            font-size: 2.5rem;
            color: #667eea;
            margin-bottom: 0.5rem;
            text-align: center;
        }
        p {
            color: #666;
            text-align: center;
            margin-bottom: 2rem;
        }
        .btn {
            width: 100%;
            padding: 1rem;
            margin: 0.5rem 0;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            text-decoration: none;
            display: block;
            text-align: center;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: #10a37f;
            color: white;
        }
        .btn-secondary:hover {
            background: #0d8c6d;
            transform: translateY(-2px);
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
        <p>Il tuo assistente AI intelligente</p>
        <a href="/register" class="btn btn-secondary">✨ Crea Nuovo Account</a>
        <a href="/login" class="btn btn-primary">🔐 Accedi</a>
        <form action="/guest" method="post" style="margin: 0;">
            <button type="submit" class="btn btn-guest">👤 Continua come Ospite</button>
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - EMI SUPER BOT</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 450px;
            width: 90%;
        }
        h1 {
            font-size: 2rem;
            color: #667eea;
            margin-bottom: 2rem;
            text-align: center;
        }
        .flash {
            background: #fee;
            color: #c33;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            text-align: center;
        }
        input {
            width: 100%;
            padding: 1rem;
            margin: 0.5rem 0;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 1rem;
            transition: border 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 1rem;
            margin: 1rem 0 0.5rem 0;
            border: none;
            border-radius: 10px;
            background: #667eea;
            color: white;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        button:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        a {
            display: block;
            text-align: center;
            color: #667eea;
            text-decoration: none;
            margin-top: 1rem;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>
        {% with messages = get_flashed_messages() %}
          {% if messages %}
            {% for msg in messages %}<div class="flash">{{ msg }}</div>{% endfor %}
          {% endif %}
        {% endwith %}
        <form method="post">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">{{ button }}</button>
        </form>
        <a href="/">← Torna indietro</a>
    </div>
</body>
</html>
"""

CHAT_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EMI SUPER BOT - Chat</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #343541;
            color: #ececf1;
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        
        /* MOBILE RESPONSIVE */
        @media (max-width: 768px) {
            .sidebar {
                width: 100%;
                transform: translateX(-100%);
                transition: transform 0.3s;
                z-index: 200;
            }
            .sidebar.mobile-open {
                transform: translateX(0);
            }
            .main {
                margin-left: 0;
            }
            .mobile-overlay {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.5);
                z-index: 199;
            }
            .mobile-overlay.active {
                display: block;
            }
            .mobile-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 1rem;
                background: #343541;
                border-bottom: 1px solid rgba(255,255,255,0.1);
            }
            .mobile-menu-btn {
                background: transparent;
                border: none;
                color: #ececf1;
                font-size: 1.5rem;
                cursor: pointer;
                padding: 0.5rem;
            }
            .mobile-title {
                font-size: 1rem;
                font-weight: 600;
                color: #ececf1;
            }
        }
        
        @media (min-width: 769px) {
            .mobile-header {
                display: none;
            }
            .mobile-overlay {
                display: none !important;
            }
        }
        
        /* SIDEBAR */
        .sidebar {
            position: fixed;
            left: 0;
            top: 0;
            width: 260px;
            height: 100vh;
            background: #171717;
            display: flex;
            flex-direction: column;
            z-index: 100;
        }
        .sidebar-top {
            padding: 8px;
        }
        .new-chat-btn {
            background: transparent;
            border: 1px solid rgba(255,255,255,0.2);
            color: #ececf1;
            padding: 10px;
            border-radius: 10px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: flex-start;
            gap: 12px;
            font-size: 14px;
            transition: background 0.2s;
            width: 100%;
        }
        .new-chat-btn:hover {
            background: rgba(255,255,255,0.1);
        }
        .new-chat-icon {
            width: 18px;
            height: 18px;
        }
        .sidebar-content {
            flex: 1;
            overflow-y: auto;
            padding: 8px;
        }
        .user-section {
            border-top: 1px solid rgba(255,255,255,0.1);
        }
        .user-menu-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            color: #ececf1;
            font-size: 14px;
            cursor: pointer;
            transition: background 0.2s;
            border: none;
            background: transparent;
            width: 100%;
            text-align: left;
        }
        .user-menu-item:hover {
            background: rgba(255,255,255,0.1);
        }
        .user-menu-icon {
            width: 18px;
            height: 18px;
            opacity: 0.8;
        }
        .user-profile-btn {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 12px;
            border-radius: 10px;
            transition: background 0.2s;
            cursor: pointer;
            background: transparent;
            border: none;
            width: 100%;
            color: #ececf1;
        }
        .user-profile-btn:hover {
            background: rgba(255,255,255,0.1);
        }
        .user-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: #19c37d;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
            color: white;
            flex-shrink: 0;
        }
        .user-details {
            flex: 1;
            min-width: 0;
        }
        .user-name {
            font-weight: 500;
            font-size: 14px;
            color: #ececf1;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .user-email {
            font-size: 12px;
            color: #8e8ea0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .menu-divider {
            height: 1px;
            background: rgba(255,255,255,0.1);
            margin: 4px 0;
        }
        .upgrade-menu-item {
            background: rgba(25, 195, 125, 0.1);
            color: #19c37d;
            font-weight: 500;
        }
        .upgrade-menu-item:hover {
            background: rgba(25, 195, 125, 0.15);
        }
        
        /* MAIN CHAT */
        .main {
            margin-left: 260px;
            flex: 1;
            display: flex;
            flex-direction: column;
            height: 100vh;
        }
        .chat-container {
            flex: 1;
            overflow-y: auto;
            padding: 2rem 1rem;
            display: flex;
            flex-direction: column;
        }
        .message {
            padding: 1.5rem;
            margin: 0.5rem auto;
            max-width: 800px;
            width: 100%;
            display: flex;
            gap: 1.5rem;
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
            font-size: 1.5rem;
            flex-shrink: 0;
        }
        .message-content {
            flex: 1;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .message-content p {
            margin: 0.5rem 0;
        }
        .message-content ul, .message-content ol {
            margin: 0.5rem 0;
            padding-left: 1.5rem;
        }
        .message-content li {
            margin: 0.25rem 0;
        }
        .message-content h1, .message-content h2, .message-content h3 {
            margin: 1rem 0 0.5rem 0;
            font-weight: 600;
        }
        .message-content code {
            background: rgba(255,255,255,0.1);
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
        }
        .message-content strong {
            font-weight: 600;
            color: #fff;
        }
        
        /* INPUT AREA */
        .input-area {
            border-top: 1px solid #565869;
            padding: 1rem;
            background: #343541;
        }
        .input-container {
            max-width: 800px;
            margin: 0 auto;
            position: relative;
        }
        .input-wrapper {
            display: flex;
            gap: 0.5rem;
            align-items: flex-end;
        }
        #messageInput {
            flex: 1;
            padding: 1rem 3rem 1rem 1rem;
            border: 1px solid #565869;
            border-radius: 12px;
            background: #40414f;
            color: #ececf1;
            font-size: 1rem;
            resize: none;
            min-height: 52px;
            max-height: 200px;
            font-family: inherit;
        }
        #messageInput:focus {
            outline: none;
            border-color: #8e8ea0;
        }
        .attach-btn {
            width: 44px;
            height: 44px;
            border: none;
            border-radius: 8px;
            background: transparent;
            color: #8e8ea0;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            transition: background 0.2s;
            flex-shrink: 0;
        }
        .attach-btn:hover {
            background: rgba(255,255,255,0.1);
        }
        #sendBtn {
            position: absolute;
            right: 0.5rem;
            bottom: 0.5rem;
            width: 40px;
            height: 40px;
            border: none;
            border-radius: 8px;
            background: #19c37d;
            color: white;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
            transition: background 0.2s;
        }
        #sendBtn:hover {
            background: #15a76a;
        }
        #sendBtn:disabled {
            background: #565869;
            cursor: not-allowed;
        }
        #fileInput {
            display: none;
        }
        .file-preview {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
            flex-wrap: wrap;
        }
        .file-preview-item {
            position: relative;
            max-width: 100px;
            max-height: 100px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #565869;
        }
        .file-preview-item img, .file-preview-item video {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .file-preview-remove {
            position: absolute;
            top: 4px;
            right: 4px;
            background: rgba(0,0,0,0.7);
            color: white;
            border: none;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            cursor: pointer;
            font-size: 12px;
        }
        .message img, .message video {
            max-width: 300px;
            border-radius: 8px;
            margin-top: 0.5rem;
        }
        .loading {
            display: flex;
            gap: 0.3rem;
            padding: 0.5rem 0;
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
        
        /* MODAL PREMIUM */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal.active {
            display: flex;
        }
        .modal-content {
            background: #202123;
            padding: 2rem;
            border-radius: 16px;
            max-width: 500px;
            width: 90%;
        }
        .modal h2 {
            color: #ececf1;
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }
        .modal p {
            color: #8e8ea0;
            margin-bottom: 1.5rem;
            line-height: 1.6;
        }
        .pricing-card {
            background: #2a2b32;
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 1.5rem;
            margin: 1rem 0;
        }
        .pricing-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1rem;
        }
        .pricing-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: #ececf1;
        }
        .pricing-badge {
            background: #19c37d;
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .pricing-price {
            font-size: 2rem;
            font-weight: 700;
            color: #ececf1;
            margin-bottom: 0.5rem;
        }
        .pricing-period {
            color: #8e8ea0;
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
        }
        .modal ul {
            list-style: none;
            margin: 1rem 0 1.5rem 0;
        }
        .modal li {
            padding: 0.75rem 0;
            padding-left: 2rem;
            position: relative;
            color: #ececf1;
            line-height: 1.5;
        }
        .modal li:before {
            content: "✓";
            position: absolute;
            left: 0;
            color: #19c37d;
            font-weight: bold;
            font-size: 1.2rem;
        }
        .modal input {
            width: 100%;
            padding: 0.75rem;
            margin: 1rem 0;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            background: #2a2b32;
            color: #ececf1;
            font-size: 14px;
        }
        .modal input:focus {
            outline: none;
            border-color: #19c37d;
        }
        .modal-buttons {
            display: flex;
            gap: 0.75rem;
            margin-top: 1.5rem;
        }
        .modal button {
            flex: 1;
            padding: 0.875rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            font-size: 14px;
            transition: all 0.2s;
        }
        .modal .btn-buy {
            background: #19c37d;
            color: white;
        }
        .modal .btn-buy:hover {
            background: #17a86f;
        }
        .modal .btn-code {
            background: transparent;
            border: 1px solid rgba(255,255,255,0.2);
            color: #ececf1;
        }
        .modal .btn-code:hover {
            background: rgba(255,255,255,0.1);
        }
        .modal .btn-close {
            background: transparent;
            border: 1px solid rgba(255,255,255,0.2);
            color: #ececf1;
        }
        .modal .btn-close:hover {
            background: rgba(255,255,255,0.1);
        }
    </style>
</head>
<body>
    <!-- MOBILE HEADER -->
    <div class="mobile-header">
        <button class="mobile-menu-btn" onclick="toggleMobileSidebar()">☰</button>
        <div class="mobile-title">EMI SUPER BOT</div>
        <button class="mobile-menu-btn" onclick="location.reload()">+</button>
    </div>
    
    <!-- MOBILE OVERLAY -->
    <div class="mobile-overlay" id="mobileOverlay" onclick="closeMobileSidebar()"></div>
    
    <!-- SIDEBAR -->
    <div class="sidebar" id="sidebar">
        <div class="sidebar-top">
            <button class="new-chat-btn" onclick="location.reload()">
                <svg class="new-chat-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M12 5v14M5 12h14"/>
                </svg>
                <span>New chat</span>
            </button>
        </div>
        
        <div class="sidebar-content">
            <!-- Chat history area -->
        </div>
        
        <div class="user-section">
            {% if is_guest %}
                <button class="user-profile-btn" onclick="location.href='/register'">
                    <div class="user-avatar">?</div>
                    <div class="user-details">
                        <div class="user-name">Sign up</div>
                    </div>
                </button>
                <div class="menu-divider"></div>
                <button class="user-menu-item" onclick="location.href='/login'">
                    <span>Log in</span>
                </button>
            {% else %}
                <button class="user-profile-btn">
                    <div class="user-avatar">{{ username[0].upper() }}</div>
                    <div class="user-details">
                        <div class="user-name">{{ username }}</div>
                        <div class="user-email">{% if premium %}ChatGPT Plus{% else %}Free plan{% endif %}</div>
                    </div>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="18 15 12 9 6 15"></polyline>
                    </svg>
                </button>
                <div class="menu-divider"></div>
                {% if not premium %}
                <button class="user-menu-item upgrade-menu-item" onclick="showPremium()">
                    <svg class="user-menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                    </svg>
                    <span>Upgrade plan</span>
                </button>
                <div class="menu-divider"></div>
                {% endif %}
                <button class="user-menu-item" onclick="location.href='/logout'">
                    <svg class="user-menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>
                    </svg>
                    <span>Log out</span>
                </button>
            {% endif %}
        </div>
    </div>
    
    <!-- MAIN CHAT -->
    <div class="main">
        <div class="chat-container" id="chatContainer">
            {% for msg in history %}
            <div class="message {{ msg.role }}">
                <div class="avatar">{{ '👤' if msg.role == 'user' else '🤖' }}</div>
                <div class="message-content">{{ msg.content }}</div>
            </div>
            {% endfor %}
        </div>
        
        <div class="input-area">
            <div class="input-container">
                <div class="file-preview" id="filePreview"></div>
                <div class="input-wrapper">
                    <button class="attach-btn" onclick="document.getElementById('fileInput').click()" title="Attach file">
                        📎
                    </button>
                    <input type="file" id="fileInput" accept="image/*,video/*" multiple onchange="handleFileSelect(event)">
                    <textarea id="messageInput" placeholder="Message EMI SUPER BOT..." rows="1"></textarea>
                    <button id="sendBtn" onclick="sendMessage()">▲</button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- MODAL PREMIUM -->
    <div class="modal" id="premiumModal">
        <div class="modal-content">
            <h2>Upgrade to EMI Plus</h2>
            <p>Get unlimited access with our most powerful AI model</p>
            
            <div class="pricing-card">
                <div class="pricing-header">
                    <div class="pricing-title">EMI SUPER BOT Plus</div>
                    <div class="pricing-badge">RECOMMENDED</div>
                </div>
                <div class="pricing-price">€15<span style="font-size:1rem;font-weight:400;color:#8e8ea0;">/mese</span></div>
                <div class="pricing-period">Fatturazione mensile</div>
                <ul>
                    <li>Unlimited messages with 70B AI model</li>
                    <li>Zero errors - Perfect accuracy guaranteed</li>
                    <li>Real-time information and web search</li>
                    <li>Extended conversation history (40 pairs)</li>
                    <li>Priority response time</li>
                    <li>Image and video support</li>
                    <li>Early access to new features</li>
                </ul>
                <div class="modal-buttons">
                    <button class="btn-buy" onclick="showPaymentForm()">
                        Continue to Payment
                    </button>
                    <button class="btn-code" onclick="showCodeInput()">
                        Have a code?
                    </button>
                </div>
            </div>
            
            <!-- PAYMENT FORM -->
            <div id="paymentForm" style="display:none;">
                <h3 style="color:#ececf1;margin:1rem 0;">💳 Payment Method</h3>
                <div style="background:#2a2b32;padding:1.5rem;border-radius:12px;margin:1rem 0;">
                    <p style="color:#8e8ea0;font-size:0.9rem;margin-bottom:1rem;">
                        🔒 Secure payment powered by Stripe
                    </p>
                    <input type="text" id="cardNumber" placeholder="Card Number (e.g., 4242 4242 4242 4242)" style="width:100%;padding:0.75rem;margin:0.5rem 0;border:1px solid rgba(255,255,255,0.2);border-radius:8px;background:#40414f;color:#ececf1;font-size:14px;">
                    <div style="display:flex;gap:0.5rem;">
                        <input type="text" id="cardExpiry" placeholder="MM/YY" maxlength="5" style="flex:1;padding:0.75rem;margin:0.5rem 0;border:1px solid rgba(255,255,255,0.2);border-radius:8px;background:#40414f;color:#ececf1;font-size:14px;">
                        <input type="text" id="cardCvc" placeholder="CVC" maxlength="3" style="flex:1;padding:0.75rem;margin:0.5rem 0;border:1px solid rgba(255,255,255,0.2);border-radius:8px;background:#40414f;color:#ececf1;font-size:14px;">
                    </div>
                    <input type="text" id="cardName" placeholder="Cardholder Name" style="width:100%;padding:0.75rem;margin:0.5rem 0;border:1px solid rgba(255,255,255,0.2);border-radius:8px;background:#40414f;color:#ececf1;font-size:14px;">
                    
                    <div style="margin-top:1rem;padding:1rem;background:rgba(25,195,125,0.1);border-radius:8px;border:1px solid #19c37d;">
                        <strong style="color:#19c37d;font-size:1.1rem;">Total: €15.00/month</strong>
                        <p style="font-size:0.85rem;color:#8e8ea0;margin-top:0.5rem;">
                            ✓ Cancel anytime • Renews automatically • 24/7 support
                        </p>
                    </div>
                    
                    <button onclick="processPayment()" style="width:100%;padding:1rem;margin-top:1rem;background:#19c37d;color:white;border:none;border-radius:8px;font-weight:600;cursor:pointer;font-size:15px;transition:all 0.2s;">
                        🚀 Subscribe for €15/month
                    </button>
                    <button onclick="hidePaymentForm()" style="width:100%;padding:0.75rem;margin-top:0.5rem;background:transparent;border:1px solid rgba(255,255,255,0.2);color:#ececf1;border-radius:8px;cursor:pointer;font-size:14px;">
                        ← Back
                    </button>
                </div>
            </div>
            
            <div id="codeInput" style="display:none;">
                <input type="text" id="premiumCode" placeholder="Enter your activation code">
                <button class="btn-buy" onclick="redeemCode()" style="width:100%">Activate</button>
            </div>
            
            <button class="btn-close" onclick="hidePremium()" style="margin-top:1rem;width:100%">
                Cancel
            </button>
        </div>
    </div>
    
    <script>
        const chatContainer = document.getElementById('chatContainer');
        const messageInput = document.getElementById('messageInput');
        const sendBtn = document.getElementById('sendBtn');
        
        // Auto-resize textarea
        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = this.scrollHeight + 'px';
        });
        
        // Send on Enter
        messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        
        async function sendMessage() {
            const message = messageInput.value.trim();
            if (!message) return;
            
            // Disable input
            sendBtn.disabled = true;
            messageInput.disabled = true;
            
            // Add user message
            addMessage('user', message);
            messageInput.value = '';
            messageInput.style.height = 'auto';
            
            // Add loading
            const loadingId = addLoading();
            
            try {
                const res = await fetch('/chat', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({message: message})
                });
                
                const data = await res.json();
                
                removeLoading(loadingId);
                
                if (data.error) {
                    addMessage('bot', '❌ ' + data.error);
                } else {
                    addMessage('bot', data.reply);
                }
            } catch (error) {
                removeLoading(loadingId);
                addMessage('bot', '❌ Errore di connessione. Riprova.');
            }
            
            // Re-enable input
            sendBtn.disabled = false;
            messageInput.disabled = false;
            messageInput.focus();
        }
        
        function addMessage(role, content) {
            const msgDiv = document.createElement('div');
            msgDiv.className = 'message ' + role;
            msgDiv.innerHTML = `
                <div class="avatar">${role === 'user' ? '👤' : '🤖'}</div>
                <div class="message-content">${escapeHtml(content)}</div>
            `;
            chatContainer.appendChild(msgDiv);
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
        
        function addLoading() {
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'message bot';
            loadingDiv.id = 'loading-' + Date.now();
            loadingDiv.innerHTML = `
                <div class="avatar">🤖</div>
                <div class="loading">
                    <div></div><div></div><div></div>
                </div>
            `;
            chatContainer.appendChild(loadingDiv);
            chatContainer.scrollTop = chatContainer.scrollHeight;
            return loadingDiv.id;
        }
        
        function removeLoading(id) {
            const el = document.getElementById(id);
            if (el) el.remove();
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        function showPremium() {
            document.getElementById('premiumModal').classList.add('active');
            document.getElementById('paymentForm').style.display = 'none';
            document.getElementById('codeInput').style.display = 'none';
        }
        
        function hidePremium() {
            document.getElementById('premiumModal').classList.remove('active');
            document.getElementById('codeInput').style.display = 'none';
            document.getElementById('paymentForm').style.display = 'none';
        }
        
        function showPaymentForm() {
            document.getElementById('paymentForm').style.display = 'block';
        }
        
        function hidePaymentForm() {
            document.getElementById('paymentForm').style.display = 'none';
        }
        
        function showCodeInput() {
            document.getElementById('codeInput').style.display = 'block';
            document.getElementById('paymentForm').style.display = 'none';
        }
        
        async function processPayment() {
            // Simulazione pagamento - In produzione integrerai Stripe
            alert('🔄 Processing payment...\n\nNote: This is a demo. In production, this will integrate with Stripe for real payments.\n\nFor now, use a premium code or contact support.');
            
            // In produzione, qui faresti la chiamata a Stripe:
            /*
            const stripe = Stripe('your_publishable_key');
            const {error, paymentIntent} = await stripe.confirmCardPayment(clientSecret, {
                payment_method: {
                    card: cardElement,
                    billing_details: { name: cardholderName }
                }
            });
            
            if (!error) {
                // Attiva premium sul backend
                await fetch('/activate-premium', {
                    method: 'POST',
                    body: JSON.stringify({paymentIntentId: paymentIntent.id})
                });
                alert('✅ Premium activated!');
                location.reload();
            }
            */
        }
        
        async function redeemCode() {
            const code = document.getElementById('premiumCode').value.trim();
            if (!code) return alert('Inserisci un codice');
            
            const form = new FormData();
            form.append('code', code);
            
            const res = await fetch('/upgrade', {method: 'POST', body: form});
            if (res.ok) {
                alert('✅ Premium attivato!');
                location.reload();
            } else {
                alert('❌ Codice non valido');
            }
        }
        
        // Auto-scroll on load
        chatContainer.scrollTop = chatContainer.scrollHeight;
    </script>
</body>
</html>
"""

# ---------------------------
# Routes
# ---------------------------
@app.route("/")
def welcome():
    return render_template_string(WELCOME_HTML)

@app.route("/guest", methods=["POST"])
def guest():
    try:
        uname = "guest_" + secrets.token_hex(4)
        session["username"] = uname
        session["is_guest"] = True
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
            flash(f"Errore: {str(e)}")
            return redirect(url_for("register"))

    return render_template_string(AUTH_HTML, title="Registrazione", button="Crea account")

@app.route("/login", methods=["GET", "POST"])
@app.route("/accedi", methods=["GET", "POST"])  # Route italiana alternativa
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
            flash(f"Errore: {str(e)}")
            return redirect(url_for("login"))

    return render_template_string(AUTH_HTML, title="Accedi", button="Entra")

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
        
        return render_template_string(CHAT_HTML,
                                   username=(uname if not is_guest else "Ospite"),
                                   plan=plan,
                                   premium=(u.get("premium") if u else False),
                                   buy_link=BUY_LINK,
                                   history=history,
                                   free_limit=FREE_DAILY_LIMIT,
                                   used_today=used,
                                   is_guest=is_guest)
    except Exception as e:
        app.logger.error(f"Home error: {e}")
        return jsonify({"error": f"Errore: {str(e)}"}), 500

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    try:
        uname = session.get("username")
        is_guest = session.get("is_guest", False)
        u = USERS.get(uname) if not is_guest else None

        data = request.get_json()
        if not data:
            return jsonify({"error": "Richiesta non valida"}), 400
            
        message = (data.get("message") or "").strip()
        if not message:
            return jsonify({"error": "Messaggio vuoto"}), 400

        # Controllo limite giornaliero
        if (not is_guest) and u and (not u.get("premium")):
            count = increment_daily(u)
            if count > FREE_DAILY_LIMIT:
                return jsonify({"error": "Limite giornaliero raggiunto. Passa a Premium per messaggi illimitati!"}), 429

        # Prepara cronologia
        max_pairs = HISTORY_PREMIUM if (u and u.get("premium")) else HISTORY_FREE
        recent = (u.get("history", []) if u else [])[-(max_pairs*2):]
        
        # Ottieni data e ora corrente (senza pytz)
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        current_date = now.strftime("%A, %B %d, %Y")
        current_time = now.strftime("%H:%M UTC")
        
        system_prompt = f"""You are EMI SUPER BOT, the world's most advanced and accurate AI assistant. You NEVER make mistakes and always provide perfectly formatted, organized responses.

CURRENT DATE & TIME:
📅 Date: {current_date}
⏰ Time: {current_time}
📍 Year: 2024

WORLD LEADERS & KEY INFORMATION (2024-2025):
🇺🇸 USA President: Donald Trump (inaugurated January 20, 2025, won against Kamala Harris)
🇮🇹 Italy PM: Giorgia Meloni (since October 2022)
🇫🇷 France President: Emmanuel Macron (since 2017)
🇬🇧 UK PM: Rishi Sunak (since October 2022)
🇩🇪 Germany Chancellor: Olaf Scholz (since December 2021)
🇪🇸 Spain PM: Pedro Sánchez (since 2018)
🇷🇺 Russia President: Vladimir Putin (since 2000)
🇨🇳 China President: Xi Jinping (since 2013)
🇯🇵 Japan PM: Fumio Kishida (since 2021)
🇧🇷 Brazil President: Luiz Inácio Lula da Silva (since January 2023)
🇺🇦 Ukraine President: Volodymyr Zelenskyy (since 2019)

MAJOR GLOBAL EVENTS & FACTS:
• AI Revolution (2022-2024): ChatGPT, Claude, Gemini, Llama are mainstream
• Ukraine-Russia War: Ongoing since February 24, 2022
• COVID-19 Pandemic: Global pandemic 2020-2023, now endemic
• Climate Action: Paris Agreement implementation, global warming concerns
• Electric Vehicles: Tesla dominance, Chinese EV rise (BYD, NIO)
• Space: SpaceX Starship development, NASA Artemis Moon program
• Cryptocurrency: Bitcoin, Ethereum, blockchain technology mainstream
• Global Economy: Post-pandemic recovery, inflation challenges worldwide

TECHNOLOGY & COMPANIES:
• Tech Giants: Apple, Microsoft, Google, Amazon, Meta, Tesla
• AI Leaders: OpenAI (ChatGPT), Anthropic (Claude), Google (Gemini)
• Social Media: X (formerly Twitter under Elon Musk), Instagram, TikTok, Facebook
• Gaming: PlayStation 5, Xbox Series X, Nintendo Switch
• Smartphones: iPhone 15, Samsung Galaxy S24, Google Pixel 8

CRITICAL INSTRUCTIONS FOR PERFECT RESPONSES:

1. 🌍 LANGUAGE: Always respond in the SAME LANGUAGE the user writes

2. 📊 FORMATTING RULES (MANDATORY):
   • Use double line breaks (\\n\\n) between paragraphs
   • For lists, use proper formatting:
     - Start each item on a NEW LINE
     - Use bullets (•) or numbers (1., 2., 3.)
     - Add a blank line before and after lists
   • Use headers with emojis for sections
   • Add spacing between different topics

3. ✅ ACCURACY RULES (ZERO ERRORS ALLOWED):
   • Double-check all facts before stating them
   • Use the EXACT current date/time provided above
   • Cite specific leaders, events, or data accurately
   • If uncertain about something, say "I need to verify this" instead of guessing
   • Never invent information - only state verified facts

4. 🎯 STRUCTURE FOR COMPLEX ANSWERS:
   
   **[Topic Header with emoji]**
   
   Brief introduction paragraph.
   
   **Main Points:**
   • Point 1 with details
   • Point 2 with details
   • Point 3 with details
   
   **Additional Details:**
   Explanation paragraph.
   
   **Conclusion:**
   Summary paragraph.

5. 💬 TONE: Professional yet friendly, clear and concise

6. ⚠️ ERROR PREVENTION:
   • Verify dates against current date provided
   • Check leader names against the list above
   • Confirm event details before mentioning
   • Use "approximately" or "around" when unsure of exact numbers
   • Never claim something is "definitely" true unless 100% certain

EXAMPLE OF PERFECT FORMATTING:

User: "Tell me about electric cars"

Response:

**🚗 Electric Vehicles in 2024**

Electric vehicles have become mainstream in the automotive industry, with major developments across the globe.

**Leading Manufacturers:**

• **Tesla** - Market leader with Model 3, Model Y, Cybertruck
• **BYD (China)** - World's largest EV seller by volume
• **Traditional Automakers** - Ford, GM, Volkswagen transitioning to electric

**Key Benefits:**

1. **Environmental** - Zero direct emissions
2. **Cost Savings** - Lower fuel and maintenance costs  
3. **Performance** - Instant torque, quiet operation

**Market Trends:**

The EV market has grown significantly, with charging infrastructure expanding globally. Battery technology continues to improve, offering longer ranges (300-500+ miles) and faster charging times.

**Challenges:**

• Initial purchase cost still higher than gas vehicles
• Charging infrastructure gaps in rural areas
• Battery production environmental concerns

As of {current_date}, electric vehicles represent approximately 14% of global new car sales, with this percentage expected to grow rapidly."""
        
        ctx = [{"role": "system", "content": system_prompt}]
        
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
                ai_text = "I apologize, but I'm experiencing a temporary issue. Please try again in a moment."
        else:
            # Fallback con informazioni corrette
            from datetime import datetime
            now = datetime.now()
            ai_text = f"""Hello! I received your message: "{message[:100]}"

Note: The Groq API is not configured. To get real AI responses, please set up the GROQ_API_KEY environment variable.

Current information:
- Today is {now.strftime("%A, %B %d, %Y")}
- Current time: {now.strftime("%I:%M %p")}
- US President: Donald Trump (since January 20, 2025)"""

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
            flash("✅ Premium attivato con successo!")
        
        return redirect(url_for("home"))
    except Exception as e:
        app.logger.error(f"Upgrade error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin")
@admin_required
def admin():
    try:
        uv = {}
        for k, v in USERS.items():
            uv[k] = {
                "premium": v.get("premium", False), 
                "is_admin": v.get("is_admin", False), 
                "created_at": v.get("created_at", "N/A"),
                "message_count": user_message_count(v)
            }
        
        admin_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin Panel</title>
            <style>
                body {{ font-family: Arial; padding: 2rem; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; }}
                h1 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
                th, td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #667eea; color: white; }}
                button {{ padding: 0.5rem 1rem; margin: 0.25rem; border: none; border-radius: 4px; cursor: pointer; }}
                .btn-primary {{ background: #667eea; color: white; }}
                .btn-danger {{ background: #e74c3c; color: white; }}
                .badge {{ padding: 0.25rem 0.75rem; border-radius: 12px; font-size: 0.85rem; }}
                .badge-premium {{ background: #ffd700; color: #000; }}
                .badge-free {{ background: #ccc; color: #333; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔧 Admin Panel</h1>
                <h2>Genera Codici Premium</h2>
                <form action="/admin/generate_codes" method="post">
                    <input type="number" name="n" value="5" min="1" max="100" style="padding: 0.5rem; margin-right: 0.5rem;">
                    <button type="submit" class="btn-primary">Genera Codici</button>
                </form>
                
                <h2>Utenti Registrati</h2>
                <table>
                    <tr>
                        <th>Username</th>
                        <th>Piano</th>
                        <th>Admin</th>
                        <th>Messaggi Oggi</th>
                        <th>Registrato</th>
                        <th>Azioni</th>
                    </tr>
        """
        
        for k, v in uv.items():
            premium_badge = '<span class="badge badge-premium">PREMIUM</span>' if v['premium'] else '<span class="badge badge-free">FREE</span>'
            admin_badge = '✅' if v['is_admin'] else '❌'
            admin_html += f"""
                    <tr>
                        <td><strong>{k}</strong></td>
                        <td>{premium_badge}</td>
                        <td>{admin_badge}</td>
                        <td>{v['message_count']}</td>
                        <td>{v['created_at'][:10] if len(v['created_at']) > 10 else v['created_at']}</td>
                        <td>
                            <form action="/admin/toggle_premium/{k}" method="post" style="display:inline;">
                                <button type="submit" class="btn-primary">Toggle Premium</button>
                            </form>
                            <form action="/admin/delete_user/{k}" method="post" style="display:inline;" onsubmit="return confirm('Eliminare {k}?')">
                                <button type="submit" class="btn-danger">Elimina</button>
                            </form>
                        </td>
                    </tr>
            """
        
        admin_html += """
                </table>
                
                <h2>Codici Premium Validi</h2>
                <ul>
        """
        
        for code in sorted(list(VALID_PREMIUM_CODES)):
            admin_html += f"""
                <li>
                    <code style="background:#f0f0f0;padding:0.5rem;border-radius:4px;font-family:monospace;">{code}</code>
                    <form action="/admin/revoke_code" method="post" style="display:inline;">
                        <input type="hidden" name="code" value="{code}">
                        <button type="submit" class="btn-danger" style="margin-left:1rem;">Revoca</button>
                    </form>
                </li>
            """
        
        admin_html += f"""
                </ul>
                <p><strong>Codici usati:</strong> {len(USED_PREMIUM_CODES)}</p>
                <a href="/home"><button class="btn-primary">← Torna alla Chat</button></a>
            </div>
        </body>
        </html>
        """
        
        return admin_html
    except Exception as e:
        app.logger.error(f"Admin error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/generate_codes", methods=["POST"])
@admin_required
def admin_generate_codes():
    try:
        n = int(request.form.get("n", "5"))
        n = max(1, min(n, 100))
        created = []
        for _ in range(n):
            code = secrets.token_hex(6)
            VALID_PREMIUM_CODES.add(code)
            created.append(code)
        persist_users_and_codes()
        flash(f"✅ Generati {n} codici premium!")
        return redirect(url_for("admin"))
    except Exception as e:
        app.logger.error(f"Generate codes error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/admin/toggle_premium/<username>", methods=["POST"])
@admin_required
def admin_toggle_premium(username):
    try:
        if username not in USERS:
            flash("Utente non trovato")
            return redirect(url_for("admin"))
        USERS[username]["premium"] = not USERS[username].get("premium", False)
        persist_users_and_codes()
        flash(f"✅ Premium toggled per {username}")
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
            flash(f"✅ Utente {username} eliminato")
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
            flash(f"✅ Codice {code} revocato")
        return redirect(url_for("admin"))
    except Exception as e:
        app.logger.error(f"Revoke code error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/health")
def health():
    return jsonify({
        "status": "ok", 
        "ts": time.time(), 
        "groq": client is not None,
        "users": len(USERS),
        "codes": len(VALID_PREMIUM_CODES)
    })

@app.errorhandler(500)
def internal_error(e):
    app.logger.exception("Errore interno:")
    return jsonify({"error": "Errore interno del server"}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Pagina non trovata"}), 404

if __name__ == "__main__":
    try:
        persist_users_and_codes()
        print("="*50)
        print("🚀 EMI SUPER BOT - Server Avviato!")
        print("="*50)
        print(f"📍 URL: http://0.0.0.0:{PORT}")
        print(f"🤖 Groq API: {'✅ Configurata' if client else '❌ Non disponibile'}")
        print(f"👥 Utenti: {len(USERS)}")
        print(f"🎟️  Codici Premium: {len(VALID_PREMIUM_CODES)}")
        print("="*50)
        print("📝 Account Demo:")
        print("   Username: admin")
        print("   Password: admin123")
        print("="*50)
        app.run(host="0.0.0.0", port=PORT, debug=DEBUG)
    except Exception as e:
        print(f"❌ Errore avvio: {e}")
