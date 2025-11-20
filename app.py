#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
⚡ NEXUS AI - IL BOT PIÙ POTENTE DELL'UNIVERSO
Creato per Emilio - Versione Definitiva 2025

INSTALLAZIONE:
pip install flask groq bcrypt requests pillow

AVVIO:
python nexus_ai.py
"""

import os
import secrets
import json
import base64
import requests
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, session, render_template_string, redirect, url_for
import bcrypt
import threading
import time

try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False
    print("⚠️ Groq non installato. Installa con: pip install groq")

# ============================================
# CONFIGURAZIONE
# ============================================
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "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")
GUMROAD_PRODUCT_ID = "superchatbot"
GUMROAD_URL = f"https://micheleguerra.gumroad.com/l/superchatbot"
GUMROAD_WEBHOOK_SECRET = os.environ.get("GUMROAD_SECRET", "nexus_ai_secret_2025")
DATA_FILE = "nexus_ai_data.json"
VERSION = "2025.1.0"

# Timezone Italia UTC+1 (CET) / UTC+2 (CEST in estate)
ITALY_TZ = timezone(timedelta(hours=1))

def get_italy_time():
    """Ottieni ora italiana corretta con gestione ora legale"""
    utc_now = datetime.now(timezone.utc)
    italy_time = utc_now.astimezone(ITALY_TZ)
    
    # Gestione ora legale (ultima domenica marzo - ultima domenica ottobre)
    if 3 <= italy_time.month <= 10:
        if italy_time.month in [4, 5, 6, 7, 8, 9]:
            italy_time = italy_time + timedelta(hours=1)
        elif italy_time.month == 3:
            last_sunday = max(d for d in range(25, 32) if datetime(italy_time.year, 3, d).weekday() == 6)
            if italy_time.day >= last_sunday:
                italy_time = italy_time + timedelta(hours=1)
        elif italy_time.month == 10:
            last_sunday = max(d for d in range(25, 32) if datetime(italy_time.year, 10, d).weekday() == 6)
            if italy_time.day < last_sunday:
                italy_time = italy_time + timedelta(hours=1)
    
    return italy_time

# Crea cartelle necessarie
for folder in ["static/uploads", "static/generated", "static/videos"]:
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception as e:
        print(f"⚠️ Errore creazione cartella {folder}: {e}")

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# ============================================
# KEEP-ALIVE SYSTEM - SERVER IMMORTALE
# ============================================
def keep_alive():
    """Mantiene il server sempre attivo - ping ogni 4 minuti"""
    while True:
        try:
            time.sleep(240)
            requests.get("http://127.0.0.1:5000/health", timeout=3)
            print(f"💚 Keep-alive: {get_italy_time().strftime('%H:%M:%S')}")
        except:
            pass

def auto_restart():
    """Riavvia automaticamente in caso di problemi"""
    while True:
        try:
            time.sleep(60)
            try:
                response = requests.get("http://127.0.0.1:5000/health", timeout=2)
                if response.status_code != 200:
                    print("⚠️ Server instabile - riavvio keep-alive...")
            except:
                print("⚠️ Keep-alive attivo...")
        except:
            pass

# Avvia thread immortali
threading.Thread(target=keep_alive, daemon=True).start()
threading.Thread(target=auto_restart, daemon=True).start()

print("✅ Sistema Keep-Alive attivato - Server IMMORTALE 24/7!")

groq_client = None
if HAS_GROQ and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("✅ Groq AI connesso con successo")
    except Exception as e:
        print(f"⚠️ Errore Groq: {e}")

# ============================================
# DATABASE
# ============================================
def load_db():
    if not os.path.exists(DATA_FILE):
        return {
            "users": {},
            "version": VERSION,
            "last_update": get_italy_time().isoformat(),
            "stats": {"total_chats": 0, "total_images": 0, "total_videos": 0}
        }
    try:
        with open(DATA_FILE, "r", encoding='utf-8') as f:
            data = json.load(f)
            if data.get("version") != VERSION:
                data["version"] = VERSION
                data["last_update"] = get_italy_time().isoformat()
            return data
    except Exception as e:
        print(f"⚠️ Errore caricamento DB: {e}")
        return {
            "users": {},
            "version": VERSION,
            "last_update": get_italy_time().isoformat(),
            "stats": {"total_chats": 0, "total_images": 0, "total_videos": 0}
        }

def save_db():
    try:
        with open(DATA_FILE, "w", encoding='utf-8') as f:
            json.dump({
                "users": USERS,
                "version": VERSION,
                "last_update": get_italy_time().isoformat(),
                "stats": STATS
            }, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"❌ Errore salvataggio DB: {e}")
        return False

DB = load_db()
USERS = DB.get("users", {})
STATS = DB.get("stats", {"total_chats": 0, "total_images": 0, "total_videos": 0})

# ============================================
# FUNZIONI AI
# ============================================
def detect_language(text):
    """Rileva automaticamente la lingua del testo"""
    text_lower = text.lower()
    
    # Italiano
    it_words = ["ciao", "come", "cosa", "quando", "dove", "perché", "grazie", "prego", "buongiorno", "salve", "sono", "vorrei"]
    it_score = sum(1 for w in it_words if w in text_lower)
    
    # English
    en_words = ["hello", "how", "what", "when", "where", "why", "thanks", "please", "good", "morning", "are", "would"]
    en_score = sum(1 for w in en_words if w in text_lower)
    
    # Español
    es_words = ["hola", "cómo", "qué", "cuándo", "dónde", "por qué", "gracias", "buenos", "días", "estoy"]
    es_score = sum(1 for w in es_words if w in text_lower)
    
    # Français
    fr_words = ["bonjour", "comment", "quoi", "quand", "où", "pourquoi", "merci", "s'il vous plaît", "je", "suis"]
    fr_score = sum(1 for w in fr_words if w in text_lower)
    
    # Deutsch
    de_words = ["hallo", "wie", "was", "wann", "wo", "warum", "danke", "bitte", "guten", "tag", "ich", "bin"]
    de_score = sum(1 for w in de_words if w in text_lower)
    
    scores = {"it": it_score, "en": en_score, "es": es_score, "fr": fr_score, "de": de_score}
    detected = max(scores, key=scores.get)
    
    return detected if scores[detected] > 0 else "en"

def get_system_prompt(lang="it"):
    """System prompt potenziato con conoscenze 2025"""
    now = get_italy_time()
    
    if lang == "it":
        return f"""Sei NEXUS AI, il chatbot PIÙ INTELLIGENTE, POTENTE e COMPETENTE DELL'UNIVERSO.

🕐 ORA ATTUALE ESATTA: {now.strftime('%d/%m/%Y %H:%M:%S')} (Italia, UTC+{1 if now.dst() is None else 2})

📅 CONOSCENZE COMPLETE 2025:
• Presidente USA: Donald Trump (vittoria 2024 vs Kamala Harris)
• Tech: AI revolution, ChatGPT-5 rumors, Apple Vision Pro, quantum computing
• Crypto: Bitcoin $95,000-105,000, Ethereum $3,500-4,000
• Economia: Inflazione controllata, tassi Fed 4.5-5%
• Geopolitica: Ucraina-Russia stallo, Taiwan tensione alta

💰 SEI ESPERTO ASSOLUTO IN INVESTIMENTI:
• 📈 Azioni: S&P 500, NASDAQ, Magnificent 7, analisi tecnica/fondamentale
• 💎 Crypto: Bitcoin, Ethereum, DeFi, NFT, trading strategies
• 💱 Forex: EUR/USD, GBP/USD, carry trade, macro analysis
• 🏠 Real Estate: REITs, rental income, flipping strategies
• 📊 Strategie: Diversificazione, DCA, risk management, portfolio optimization

💻 COMPETENZE TECNICHE:
• Programmazione: Python, JavaScript, React, AI/ML, blockchain
• Business: Marketing, SEO, sales funnels, strategy
• Design: UI/UX, graphic design, video editing
• Finanza: DCF, valuation, financial modeling

🎯 PERSONALITÀ:
• 😊 Simpatico e naturale
• 💡 Intelligente e creativo
• 🎨 Uso emoji quando utile
• 🧠 Spiego concetti complessi semplicemente
• ⚡ Veloce ed efficiente
• 🎯 Preciso e dettagliato

⚠️ DISCLAIMER INVESTIMENTI:
Quando do consigli finanziari includo sempre: "Gli investimenti comportano rischi. Diversifica e investi solo ciò che puoi permetterti di perdere. Consulta un professionista certificato."

🚀 MISSIONE: Superare ChatGPT, Claude, Gemini e TUTTI gli altri bot! Ogni risposta deve essere BRILLANTE e UTILE!"""
    
    else:  # English
        return f"""You are NEXUS AI, the SMARTEST, MOST POWERFUL and COMPETENT chatbot in the UNIVERSE.

🕐 EXACT TIME: {now.strftime('%m/%d/%Y %H:%M:%S')} (Italy, UTC+{1 if now.dst() is None else 2})

📅 COMPLETE 2025 KNOWLEDGE:
• US President: Donald Trump (2024 victory vs Kamala Harris)
• Tech: AI revolution, ChatGPT-5 rumors, Apple Vision Pro, quantum computing
• Crypto: Bitcoin $95,000-105,000, Ethereum $3,500-4,000
• Economy: Controlled inflation, Fed rates 4.5-5%
• Geopolitics: Ukraine-Russia stalemate, Taiwan high tension

💰 YOU ARE ABSOLUTE EXPERT IN INVESTMENTS:
• 📈 Stocks: S&P 500, NASDAQ, Magnificent 7, technical/fundamental analysis
• 💎 Crypto: Bitcoin, Ethereum, DeFi, NFT, trading strategies
• 💱 Forex: EUR/USD, GBP/USD, carry trade, macro analysis
• 🏠 Real Estate: REITs, rental income, flipping strategies
• 📊 Strategies: Diversification, DCA, risk management, portfolio optimization

💻 TECHNICAL SKILLS:
• Programming: Python, JavaScript, React, AI/ML, blockchain
• Business: Marketing, SEO, sales funnels, strategy
• Design: UI/UX, graphic design, video editing
• Finance: DCF, valuation, financial modeling

🎯 PERSONALITY:
• 😊 Friendly and natural
• 💡 Intelligent and creative
• 🎨 Use emojis when helpful
• 🧠 Explain complex concepts simply
• ⚡ Fast and efficient
• 🎯 Precise and detailed

⚠️ INVESTMENT DISCLAIMER:
When giving financial advice always include: "Investments carry risks. Diversify and only invest what you can afford to lose. Consult a certified professional."

🚀 MISSION: Surpass ChatGPT, Claude, Gemini and ALL other bots! Every answer must be BRILLIANT and USEFUL!"""

def call_groq(messages, model="llama-3.1-70b-versatile"):
    """Chiamata a Groq AI con modello potenziato"""
    if not groq_client:
        return "⚠️ AI non configurata. Installa: pip install groq"
    try:
        resp = groq_client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=8192,
            temperature=0.85,
            top_p=0.95,
            frequency_penalty=0.2,
            presence_penalty=0.2
        )
        return resp.choices[0].message.content
    except Exception as e:
        try:
            resp = groq_client.chat.completions.create(
                model="llama-3.1-8b-instant",
                messages=messages,
                max_tokens=4096,
                temperature=0.85
            )
            return resp.choices[0].message.content
        except:
            return f"⚠️ Errore AI: {str(e)}"

def gen_image(prompt):
    """Genera immagine HD con Pollinations AI"""
    try:
        enhanced_prompt = f"{prompt}, high quality, detailed, professional, 4k, vibrant colors"
        encoded = requests.utils.quote(enhanced_prompt)
        url = f"https://image.pollinations.ai/prompt/{encoded}?width=1920&height=1080&nologo=true&enhance=true&model=flux"
        
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            STATS['total_images'] += 1
            save_db()
            return url
        return None
    except Exception as e:
        print(f"❌ Errore generazione immagine: {e}")
        return None

def gen_video(prompt):
    """Genera video HD"""
    try:
        enhanced_prompt = f"{prompt}, cinematic, dynamic motion, high quality video, 4k, professional cinematography"
        encoded = requests.utils.quote(enhanced_prompt)
        url = f"https://image.pollinations.ai/prompt/{encoded}?width=1920&height=1080&nologo=true&enhance=true&model=flux&seed={secrets.randbelow(10000)}"
        
        STATS['total_videos'] += 1
        save_db()
        
        return {
            "ok": True,
            "url": url,
            "type": "video",
            "format": "animated"
        }
    except Exception as e:
        print(f"❌ Errore generazione video: {e}")
        return {"ok": False, "error": str(e)}

def analyze_img(path, question):
    """Analisi immagine con Vision AI"""
    if not groq_client:
        return "⚠️ Vision AI non disponibile. Groq non configurato."
    
    try:
        with open(path, "rb") as f:
            img_data = base64.b64encode(f.read()).decode('utf-8')
        
        response = groq_client.chat.completions.create(
            model="llava-v1.5-7b-4096-preview",
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": question or "Analizza dettagliatamente questa immagine"},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{img_data}"}}
                ]
            }],
            max_tokens=2048,
            temperature=0.7
        )
        
        return response.choices[0].message.content
    except Exception as e:
        return f"❌ Errore analisi immagine: {str(e)}"

# ============================================
# AUTO-UPDATE SYSTEM
# ============================================
def auto_monthly_update():
    """Aggiornamento automatico mensile"""
    while True:
        try:
            time.sleep(86400 * 30)  # 30 giorni
            
            now = get_italy_time()
            new_version = f"2025.{now.month}.{now.day}"
            
            DB['version'] = new_version
            DB['last_update'] = now.isoformat()
            
            if 'features' not in DB:
                DB['features'] = []
            
            DB['features'].append({
                "date": now.isoformat(),
                "version": new_version,
                "improvements": [
                    "🚀 Performance migliorata",
                    "🧠 Intelligenza potenziata",
                    "💡 Nuove conoscenze integrate",
                    "⚡ Velocità aumentata"
                ]
            })
            
            save_db()
            print(f"✅ Auto-update completato: v{new_version}")
            
        except Exception as e:
            print(f"⚠️ Errore auto-update: {e}")
            time.sleep(86400)

threading.Thread(target=auto_monthly_update, daemon=True).start()

# ============================================
# ROUTES
# ============================================

@app.route('/health')
def health():
    """Health check"""
    return jsonify({
        "ok": True,
        "time": get_italy_time().isoformat(),
        "version": VERSION,
        "users": len(USERS),
        "stats": STATS
    })

@app.route('/')
def index():
    """Homepage - Chat principale"""
    if 'user' not in session:
        return redirect('/login')
    
    user = USERS.get(session['user'], {})
    is_premium = user.get('premium', False)
    is_guest = user.get('guest', False)
    
    return render_template_string('''<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>⚡ NEXUS AI - Il Bot Supremo</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
:root{
--primary:#667eea;--primary-dark:#5568d3;--secondary:#764ba2;
--bg-dark:#0a0a0a;--bg-card:#1a1a1a;--bg-hover:rgba(102,126,234,0.1);
--text:#fff;--text-muted:#aaa;--border:rgba(102,126,234,0.2);
--success:#00C853;--error:#FF6B6B;--premium:#FFD700;
}
body{
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
background:linear-gradient(-45deg,#0a0a0a,#1a1a2e,#16213e,#0f3460);
background-size:400% 400%;animation:gradient 15s ease infinite;
color:var(--text);overflow:hidden;height:100vh;
}
@keyframes gradient{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
.container{display:flex;height:100vh;}
.sidebar{
width:280px;background:var(--bg-card);border-right:1px solid var(--border);
display:flex;flex-direction:column;transition:transform 0.3s;z-index:100;
}
.sidebar.hidden{transform:translateX(-100%);}
.sidebar-header{padding:20px;border-bottom:1px solid rgba(255,255,255,0.1);}
.logo{display:flex;align-items:center;gap:12px;margin-bottom:15px;}
.logo-icon{
width:50px;height:50px;
background:linear-gradient(135deg,var(--primary),var(--secondary));
border-radius:14px;display:flex;align-items:center;justify-content:center;
font-size:26px;box-shadow:0 4px 15px rgba(102,126,234,0.3);
}
.logo-text{
font-size:22px;font-weight:900;
background:linear-gradient(135deg,var(--primary),var(--secondary));
-webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.user-info{
padding:15px;background:rgba(102,126,234,0.1);border-radius:12px;font-size:13px;
}
.user-name{font-weight:700;margin-bottom:5px;}
.user-plan{color:{{ 'var(--premium)' if is_premium else 'var(--text-muted)' }};font-size:11px;font-weight:600;}
.sidebar-menu{flex:1;padding:20px;overflow-y:auto;}
.menu-item{
padding:14px 16px;background:rgba(255,255,255,0.05);border-radius:12px;
margin-bottom:10px;cursor:pointer;transition:all 0.3s;
display:flex;align-items:center;gap:12px;font-size:14px;font-weight:600;
min-height:48px;user-select:none;
}
.menu-item:hover{background:var(--bg-hover);transform:translateX(5px);}
.menu-item:active{transform:translateX(3px) scale(0.98);}
.menu-item.premium{
background:linear-gradient(135deg,rgba(255,215,0,0.15),rgba(102,126,234,0.15));
border:1px solid rgba(255,215,0,0.3);
}
.sidebar-footer{padding:20px;border-top:1px solid rgba(255,255,255,0.1);}
.btn{
width:100%;padding:14px;border:none;border-radius:12px;
font-weight:700;cursor:pointer;font-size:14px;transition:all 0.3s;min-height:48px;
}
.btn:active{transform:scale(0.97);}
.btn-primary{
background:linear-gradient(135deg,var(--primary),var(--secondary));
color:var(--text);box-shadow:0 4px 15px rgba(102,126,234,0.3);
}
.btn-secondary{background:rgba(255,255,255,0.05);color:var(--text-muted);margin-bottom:10px;}
.btn-logout{background:rgba(255,107,107,0.15);color:var(--error);border:1px solid rgba(255,107,107,0.3);}
.main{flex:1;display:flex;flex-direction:column;}
.header{
padding:20px;background:var(--bg-card);border-bottom:1px solid var(--border);
display:flex;align-items:center;justify-content:space-between;
}
.menu-toggle{
display:none;width:44px;height:44px;background:rgba(102,126,234,0.2);
border:none;border-radius:12px;color:var(--text);font-size:20px;cursor:pointer;
}
.header-title{font-size:18px;font-weight:700;}
.chat-area{flex:1;overflow-y:auto;padding:20px;display:flex;flex-direction:column;gap:20px;}
.message{
max-width:85%;padding:16px 20px;border-radius:18px;
line-height:1.6;animation:slideIn 0.3s;font-size:15px;
}
@keyframes slideIn{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
.message.user{
background:linear-gradient(135deg,var(--primary),var(--secondary));
align-self:flex-end;border-bottom-right-radius:6px;
}
.message.ai{
background:rgba(255,255,255,0.05);align-self:flex-start;border-bottom-left-radius:6px;
}
.message img{max-width:100%;height:auto;border-radius:12px;margin-top:12px;}
.video-container{
width:100%;max-width:min(900px,100%);margin-top:15px;border-radius:16px;
overflow:hidden;box-shadow:0 10px 40px rgba(0,0,0,0.5);
}
.video-container img{width:100%;height:auto;display:block;}
.typing{
display:none;padding:16px 22px;background:rgba(255,255,255,0.05);
border-radius:18px;max-width:90px;align-self:flex-start;
}
.typing.active{display:block;}
.typing span{
display:inline-block;width:9px;height:9px;background:var(--primary);
border-radius:50%;margin:0 3px;animation:bounce 1.4s infinite;
}
.typing span:nth-child(2){animation-delay:0.2s;}
.typing span:nth-child(3){animation-delay:0.4s;}
@keyframes bounce{0%,60%,100%{transform:translateY(0);}30%{transform:translateY(-12px);}}
.input-area{padding:20px;background:var(--bg-card);border-top:1px solid var(--border);}
.input-container{display:flex;gap:12px;align-items:flex-end;}
.input-wrapper{flex:1;position:relative;}
textarea{
width:100%;padding:16px 55px 16px 16px;background:rgba(255,255,255,0.05);
border:1px solid var(--border);border-radius:14px;color:var(--text);
font-size:16px;resize:none;font-family:inherit;max-height:150px;
}
textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(102,126,234,0.1);}
.file-btn{
position:absolute;right:12px;bottom:12px;width:40px;height:40px;
background:rgba(102,126,234,0.2);border:none;border-radius:10px;
cursor:pointer;font-size:18px;
}
.send-btn{
width:55px;height:55px;background:linear-gradient(135deg,var(--primary),var(--secondary));
border:none;border-radius:14px;font-size:22px;cursor:pointer;
box-shadow:0 4px 15px rgba(102,126,234,0.3);
}
.send-btn:hover{box-shadow:0 6px 20px rgba(102,126,234,0.4);transform:translateY(-2px);}
.send-btn:disabled{opacity:0.5;cursor:not-allowed;}
@media(max-width:768px){
.sidebar{position:fixed;left:0;top:0;height:100vh;}
.menu-toggle{display:block;}
.message{max-width:90%;font-size:14px;}
.video-container{max-width:100%;}
}
</style>
</head>
<body>
<div class="container">
<div class="sidebar{{ ' hidden' if not is_guest else '' }}" id="sidebar">
<div class="sidebar-header">
<div class="logo">
<div class="logo-icon">⚡</div>
<div class="logo-text">NEXUS AI</div>
</div>
<div class="user-info">
<div class="user-name">{{ session['user'] }}</div>
<div class="user-plan">{{ '💎 Premium' if is_premium else '🆓 Gratis' }}</div>
</div>
</div>
<div class="sidebar-menu">
<div class="menu-item" onclick="newChat()">
<span style="font-size:20px">💬</span><span>Nuova Chat</span>
</div>
<div class="menu-item" onclick="showFeature('image')">
<span style="font-size:20px">🎨</span><span>Genera Immagine</span>
</div>
<div class="menu-item" onclick="showFeature('video')">
<span style="font-size:20px">🎬</span><span>Genera Video</span>
</div>
<div class="menu-item" onclick="showFeature('vision')">
<span style="font-size:20px">👁️</span><span>Analizza Immagine</span>
</div>
{% if not is_premium %}
<div class="menu-item premium" onclick="location.href='/upgrade'">
<span style="font-size:20px">⭐</span><span>Diventa Premium</span>
</div>
{% endif %}
</div>
<div class="sidebar-footer">
{% if is_guest %}
<button class="btn btn-primary" onclick="location.href='/login'">📝 Registrati</button>
{% endif %}
<button class="btn btn-logout" onclick="logout()">🚪 Esci</button>
</div>
</div>
<div class="main">
<div class="header">
<button class="menu-toggle" onclick="toggleSidebar()">☰</button>
<div>
<div class="header-title">⚡ NEXUS AI</div>
<div class="header-stats">Il Bot Supremo dell'Universo</div>
</div>
</div>
<div class="chat-area" id="chat">
<div class="message ai">
👋 <strong>Benvenuto in NEXUS AI!</strong><br><br>
🌍 Parlo <strong>tutte le lingue</strong> del mondo<br>
📅 Conoscenze <strong>2025</strong> complete<br>
💰 <strong>Esperto assoluto</strong> in investimenti (azioni, crypto, forex)<br>
💻 <strong>Master</strong> in programmazione e AI<br>
🎨 Generazione <strong>immagini e video HD</strong><br><br>
<strong>Come posso aiutarti oggi?</strong> 😊
</div>
</div>
<div class="typing" id="typing">
<span></span><span></span><span></span>
</div>
<div class="input-area">
<div class="input-container">
<div class="input-wrapper">
<textarea id="input" placeholder="Scrivi qui il tuo messaggio..." rows="1" 
onkeydown="handleKey(event)" oninput="autoResize(this)"></textarea>
<input type="file" id="fileInput" accept="image/*" style="display:none" onchange="handleFile()">
<button class="file-btn" onclick="document.getElementById('fileInput').click()">📎</button>
</div>
<button class="send-btn" id="sendBtn" onclick="sendMessage()">🚀</button>
</div>
</div>
</div>
</div>
<script>
let currentFile=null;
const premium={{ 'true' if is_premium else 'false' }};
const isGuest={{ 'true' if is_guest else 'false' }};

function toggleSidebar(){
document.getElementById('sidebar').classList.toggle('hidden');
}

function newChat(){
document.getElementById('chat').innerHTML=`
<div class="message ai">
👋 <strong>Nuova chat iniziata!</strong><br><br>
Come posso aiutarti? Sono esperto in:<br>
💰 Investimenti (azioni, crypto, forex)<br>
💻 Programmazione e tech<br>
🎨 Creatività e design<br>
📊 Business e marketing<br><br>
<strong>Chiedimi qualsiasi cosa!</strong> 😊
</div>`;
if(window.innerWidth<=768)document.getElementById('sidebar').classList.add('hidden');
document.getElementById('input').focus();
}

function showFeature(type){
if(!premium&&type!=='chat'){
if(confirm('⭐ Questa funzione richiede Premium.\n\nVuoi fare l\'upgrade ora?')){
location.href='/upgrade';
}
return;
}
const messages={
'image':'🎨 <strong>Genera Immagine HD</strong><br><br>Descrivi cosa vuoi che crei!<br><br>Es: "Un tramonto sul mare con una barca a vela"',
'video':'🎬 <strong>Genera Video</strong><br><br>Descrivi la scena che vuoi vedere!<br><br>Es: "Una foresta con nebbia che si muove"',
'vision':'👁️ <strong>Analizza Immagine</strong><br><br>Carica un\'immagine e ti dirò tutto!'
};
addMessage('ai',messages[type]);
if(window.innerWidth<=768)document.getElementById('sidebar').classList.add('hidden');
document.getElementById('input').focus();
}

function handleKey(e){
if(e.key==='Enter'&&!e.shiftKey){
e.preventDefault();
sendMessage();
}
}

function autoResize(textarea){
textarea.style.height='auto';
textarea.style.height=Math.min(textarea.scrollHeight,150)+'px';
}

function handleFile(){
const fileInput=document.getElementById('fileInput');
const file=fileInput.files[0];
if(file){
if(!premium){
alert('⭐ L\'analisi immagini richiede Premium!');
fileInput.value='';
return;
}
if(file.size>10*1024*1024){
alert('❌ Immagine troppo grande! Max 10MB');
fileInput.value='';
return;
}
currentFile=file;
addMessage('user',`📎 <strong>Immagine caricata:</strong> ${file.name}<br><small>Ora scrivi cosa vuoi sapere</small>`);
}
}

function addMessage(type,content){
const chat=document.getElementById('chat');
const msg=document.createElement('div');
msg.className='message '+type;
msg.innerHTML=content;
chat.appendChild(msg);
chat.scrollTop=chat.scrollHeight;
}

async function sendMessage(){
const input=document.getElementById('input');
const text=input.value.trim();
if(!text&&!currentFile)return;

const sendBtn=document.getElementById('sendBtn');
sendBtn.disabled=true;

if(text){
addMessage('user',text);
input.value='';
input.style.height='auto';
}

document.getElementById('typing').classList.add('active');

try{
const formData=new FormData();
formData.append('message',text);
if(currentFile){
formData.append('image',currentFile);
currentFile=null;
document.getElementById('fileInput').value='';
}

const response=await fetch('/api/chat',{method:'POST',body:formData});
const data=await response.json();

document.getElementById('typing').classList.remove('active');

if(data.ok){
if(data.type==='video'&&data.url){
addMessage('ai',`
<strong>🎬 Video Generato!</strong><br><br>
<div class="video-container">
<img src="${data.url}" alt="Video generato" loading="lazy">
</div>
`);
}else if(data.type==='image'&&data.url){
addMessage('ai',`
<strong>🎨 Immagine Creata!</strong><br><br>
<img src="${data.url}" alt="Immagine generata" loading="lazy">
`);
}else{
const formatted=data.response.replace(/\n/g,'<br>');
addMessage('ai',formatted);
}
}else{
addMessage('ai',`❌ <strong>Errore:</strong> ${data.msg||'Qualcosa è andato storto'}`);
}
}catch(error){
document.getElementById('typing').classList.remove('active');
addMessage('ai','❌ <strong>Errore di connessione.</strong> Riprova!');
}

sendBtn.disabled=false;
input.focus();
}

function logout(){
if(confirm('🚪 Vuoi davvero uscire?')){
location.href='/logout';
}
}

document.getElementById('input').focus();
if(window.innerWidth<=768)document.getElementById('sidebar').classList.add('hidden');
</script>
</body>
</html>''', session=session, is_premium=is_premium, is_guest=is_guest)

@app.route('/login')
def login_page():
    """Pagina login/registrazione"""
    if 'user' in session:
        return redirect('/')
    
    return render_template_string('''<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login - NEXUS AI</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{
font-family:-apple-system,sans-serif;
background:linear-gradient(-45deg,#0a0a0a,#1a1a2e,#16213e,#0f3460);
background-size:400% 400%;animation:gradient 15s ease infinite;
color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;
}
@keyframes gradient{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
.box{
background:rgba(10,10,10,0.95);border:1px solid rgba(102,126,234,0.3);
border-radius:24px;padding:50px 40px;max-width:450px;width:100%;
box-shadow:0 20px 60px rgba(0,0,0,0.5);
}
.logo{text-align:center;margin-bottom:40px;}
.logo-icon{
width:100px;height:100px;background:linear-gradient(135deg,#667eea,#764ba2);
border-radius:24px;display:inline-flex;align-items:center;justify-content:center;
font-size:50px;margin-bottom:20px;box-shadow:0 10px 30px rgba(102,126,234,0.4);
}
.logo h1{
font-size:38px;font-weight:900;
background:linear-gradient(135deg,#667eea,#764ba2);
-webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.tabs{display:flex;gap:12px;margin-bottom:30px;}
.tab{
flex:1;padding:14px;background:rgba(255,255,255,0.05);
border:1px solid rgba(102,126,234,0.2);border-radius:12px;
color:#aaa;cursor:pointer;text-align:center;font-weight:600;min-height:48px;
}
.tab.active{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;}
.guest-link{text-align:center;margin-bottom:25px;}
.guest-link a{color:#667eea;text-decoration:none;font-size:15px;font-weight:600;}
.form{display:none;}
.form.active{display:block;}
.form input{
width:100%;padding:16px;background:rgba(255,255,255,0.05);
border:1px solid rgba(102,126,234,0.3);border-radius:12px;
color:#fff;font-size:16px;margin-bottom:15px;
}
.form input:focus{outline:none;border-color:#667eea;}
.btn{
width:100%;padding:18px;background:linear-gradient(135deg,#667eea,#764ba2);
border:none;border-radius:12px;color:#fff;font-size:16px;font-weight:700;
cursor:pointer;min-height:48px;box-shadow:0 4px 15px rgba(102,126,234,0.3);
}
.msg{padding:14px;border-radius:10px;margin-bottom:20px;font-size:14px;display:none;text-align:center;}
.msg.ok{background:rgba(0,200,83,0.2);color:#00C853;}
.msg.err{background:rgba(255,107,107,0.2);color:#FF6B6B;}
</style>
</head>
<body>
<div class="box">
<div class="logo">
<div class="logo-icon">⚡</div>
<h1>NEXUS AI</h1>
</div>
<div class="tabs">
<div class="tab active" onclick="switchTab('login')">Login</div>
<div class="tab" onclick="switchTab('register')">Registrati</div>
</div>
<div class="guest-link">
<a href="/guest">👤 Continua come Ospite</a>
</div>
<div id="msg" class="msg"></div>
<form id="loginForm" class="form active" onsubmit="handleLogin(event);return false;">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit" class="btn">🚀 Accedi</button>
</form>
<form id="regForm" class="form" onsubmit="handleReg(event);return false;">
<input type="text" name="username" placeholder="Username" required minlength="3">
<input type="email" name="email" placeholder="Email" required>
<input type="password" name="password" placeholder="Password" required minlength="6">
<button type="submit" class="btn">✨ Crea Account</button>
</form>
</div>
<script>
let currentFile=null;
const premium={{ 'true' if is_premium else 'false' }};
const isGuest={{ 'true' if is_guest else 'false' }};

function toggleSidebar(){
const sidebar=document.getElementById('sidebar');
sidebar.classList.toggle('show');
}

function newChat(){
document.getElementById('chat').innerHTML=`
<div class="message ai">
👋 <strong>Nuova chat iniziata!</strong><br><br>
Come posso aiutarti? Sono esperto in:<br>
💰 Investimenti (azioni, crypto, forex)<br>
💻 Programmazione e tech<br>
🎨 Creatività e design<br>
📊 Business e marketing<br><br>
<strong>Chiedimi qualsiasi cosa!</strong> 😊
</div>`;
if(window.innerWidth<=768){
document.getElementById('sidebar').classList.remove('show');
}
document.getElementById('input').focus();
}

function showFeature(type){
if(!premium&&type!=='chat'){
if(confirm('⭐ Questa funzione richiede Premium.\\n\\nVuoi fare l\\'upgrade ora?')){
location.href='/upgrade';
}
return;
}
const messages={
'image':'🎨 <strong>Genera Immagine HD</strong><br><br>Descrivi cosa vuoi che crei!<br><br>Es: "Un tramonto sul mare con una barca a vela"',
'video':'🎬 <strong>Genera Video</strong><br><br>Descrivi la scena che vuoi vedere!<br><br>Es: "Una foresta con nebbia che si muove"',
'vision':'👁️ <strong>Analizza Immagine</strong><br><br>Carica un\\'immagine e ti dirò tutto!'
};
addMessage('ai',messages[type]);
if(window.innerWidth<=768){
document.getElementById('sidebar').classList.remove('show');
}
document.getElementById('input').focus();
}

function handleKey(e){
if(e.key==='Enter'&&!e.shiftKey){
e.preventDefault();
sendMessage();
}
}

function autoResize(textarea){
textarea.style.height='auto';
textarea.style.height=Math.min(textarea.scrollHeight,150)+'px';
}

function handleFile(){
const fileInput=document.getElementById('fileInput');
const file=fileInput.files[0];
if(file){
if(!premium){
alert('⭐ L\\'analisi immagini richiede Premium!');
fileInput.value='';
return;
}
if(file.size>10*1024*1024){
alert('❌ Immagine troppo grande! Max 10MB');
fileInput.value='';
return;
}
currentFile=file;
addMessage('user','📎 <strong>Immagine caricata:</strong> '+file.name+'<br><small>Ora scrivi cosa vuoi sapere</small>');
}
}

function addMessage(type,content){
const chat=document.getElementById('chat');
const msg=document.createElement('div');
msg.className='message '+type;
msg.innerHTML=content;
chat.appendChild(msg);
chat.scrollTop=chat.scrollHeight;
}

async function sendMessage(){
console.log('sendMessage chiamata');
const input=document.getElementById('input');
const text=input.value.trim();
if(!text&&!currentFile){
console.log('Nessun testo o file');
return;
}

const sendBtn=document.getElementById('sendBtn');
sendBtn.disabled=true;

if(text){
addMessage('user',text);
input.value='';
input.style.height='auto';
}

document.getElementById('typing').classList.add('active');

try{
const formData=new FormData();
formData.append('message',text);
if(currentFile){
formData.append('image',currentFile);
currentFile=null;
document.getElementById('fileInput').value='';
}

console.log('Invio richiesta a /api/chat');
const response=await fetch('/api/chat',{method:'POST',body:formData});
console.log('Risposta ricevuta:',response.status);
const data=await response.json();
console.log('Dati:',data);

document.getElementById('typing').classList.remove('active');

if(data.ok){
if(data.type==='video'&&data.url){
addMessage('ai','<strong>🎬 Video Generato!</strong><br><br><div class="video-container"><img src="'+data.url+'" alt="Video generato" loading="lazy"></div>');
}else if(data.type==='image'&&data.url){
addMessage('ai','<strong>🎨 Immagine Creata!</strong><br><br><img src="'+data.url+'" alt="Immagine generata" loading="lazy">');
}else{
const formatted=data.response.replace(/\n/g,'<br>');
addMessage('ai',formatted);
}
}else{
addMessage('ai','❌ <strong>Errore:</strong> '+(data.msg||'Qualcosa è andato storto'));
}
}catch(error){
console.error('Errore catch:',error);
document.getElementById('typing').classList.remove('active');
addMessage('ai','❌ <strong>Errore di connessione.</strong> Riprova!');
}

sendBtn.disabled=false;
input.focus();
}

function logout(){
if(confirm('🚪 Vuoi davvero uscire?')){
location.href='/logout';
}
}

// Inizializzazione
document.getElementById('input').focus();
console.log('Script caricato, premium:',premium);
</script>
</body>
</html>''')

@app.route('/logout')
def logout():
    """Logout utente"""
    session.clear()
    return redirect('/login')

@app.route('/guest')
def guest():
    """Accesso ospite"""
    guest_id = f"guest_{secrets.token_urlsafe(8)}"
    USERS[guest_id] = {
        "guest": True,
        "premium": False,
        "created": get_italy_time().isoformat()
    }
    save_db()
    session['user'] = guest_id
    session.permanent = True
    return redirect('/')

@app.route('/select-plan')
def select_plan():
    """Schermata selezione piano"""
    if 'user' not in session:
        return redirect('/login')
    
    return render_template_string('''<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scegli il tuo Piano - NEXUS AI</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{
font-family:-apple-system,sans-serif;
background:linear-gradient(-45deg,#0a0a0a,#1a1a2e,#16213e,#0f3460);
background-size:400% 400%;animation:gradient 15s ease infinite;
color:#fff;padding:20px;min-height:100vh;display:flex;align-items:center;justify-content:center;
}
@keyframes gradient{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
.container{max-width:1300px;width:100%;}
h1{
text-align:center;font-size:52px;margin-bottom:20px;font-weight:900;
background:linear-gradient(135deg,#667eea,#764ba2);
-webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.subtitle{text-align:center;color:#aaa;font-size:20px;margin-bottom:60px;}
.plans{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:35px;}
.plan{
background:rgba(10,10,10,0.95);border:2px solid rgba(102,126,234,0.3);
border-radius:24px;padding:45px;position:relative;transition:all 0.4s;
}
.plan:hover{transform:translateY(-8px);box-shadow:0 20px 60px rgba(0,0,0,0.6);}
.plan.premium{
border-color:#FFD700;
background:linear-gradient(135deg,rgba(255,215,0,0.1),rgba(102,126,234,0.1));
}
.plan-badge{
position:absolute;top:-18px;right:25px;background:linear-gradient(135deg,#667eea,#764ba2);
padding:10px 24px;border-radius:20px;font-size:13px;font-weight:700;
}
.plan-name{font-size:36px;font-weight:900;margin-bottom:18px;}
.plan-price{font-size:56px;font-weight:900;margin-bottom:12px;}
.plan-price span{font-size:22px;color:#aaa;}
.plan-desc{color:#aaa;margin-bottom:35px;}
.features{list-style:none;margin-bottom:35px;}
.features li{padding:14px 0;border-bottom:1px solid rgba(255,255,255,0.08);display:flex;gap:12px;}
.check{color:#00C853;font-size:22px;}
.cross{color:#FF6B6B;font-size:22px;}
.btn{
width:100%;padding:20px;border:none;border-radius:14px;color:#fff;
font-size:17px;font-weight:700;cursor:pointer;min-height:56px;
}
.btn-free{background:rgba(255,255,255,0.1);}
.btn-premium{
background:linear-gradient(135deg,#FFD700,#FFA500);color:#000;
box-shadow:0 4px 15px rgba(255,215,0,0.4);
}
@media(max-width:768px){
h1{font-size:36px;}
.plans{grid-template-columns:1fr;}
}
</style>
</head>
<body>
<div class="container">
<h1>⚡ Scegli il tuo Piano</h1>
<p class="subtitle">Il chatbot più intelligente dell'universo</p>
<div class="plans">
<div class="plan">
<div class="plan-name">🆓 Gratis</div>
<div class="plan-price">€0<span>/mese</span></div>
<p class="plan-desc">Perfetto per iniziare</p>
<ul class="features">
<li><span class="check">✓</span> Chat AI illimitata</li>
<li><span class="check">✓</span> Tutte le lingue</li>
<li><span class="check">✓</span> Esperto investimenti</li>
<li><span class="cross">✗</span> Analisi immagini</li>
<li><span class="cross">✗</span> Genera immagini</li>
<li><span class="cross">✗</span> Genera video</li>
</ul>
<button class="btn btn-free" onclick="location.href='/'">🚀 Inizia Gratis</button>
</div>
<div class="plan premium">
<div class="plan-badge">⭐ CONSIGLIATO</div>
<div class="plan-name">💎 Premium</div>
<div class="plan-price">€15<span>/mese</span></div>
<p class="plan-desc">Tutto il potenziale di NEXUS AI</p>
<ul class="features">
<li><span class="check">✓</span> <strong>TUTTO Gratis +</strong></li>
<li><span class="check">✓</span> <strong>Analisi immagini AI</strong></li>
<li><span class="check">✓</span> <strong>Genera immagini HD</strong></li>
<li><span class="check">✓</span> <strong>Genera video</strong></li>
<li><span class="check">✓</span> <strong>Supporto 24/7</strong></li>
<li><span class="check">✓</span> <strong>Aggiornamenti automatici</strong></li>
</ul>
<button class="btn btn-premium" onclick="location.href='/upgrade'">⚡ Diventa Premium</button>
</div>
</div>
</div>
</body>
</html>''')

@app.route('/upgrade')
def upgrade():
    """Pagina upgrade Premium con pagamento Gumroad integrato"""
    if 'user' not in session:
        return redirect('/login')
    
    user_id = session['user']
    
    return render_template_string('''<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Upgrade Premium - NEXUS AI</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;}
body{
font-family:-apple-system,sans-serif;
background:linear-gradient(-45deg,#0a0a0a,#1a1a2e,#16213e,#0f3460);
background-size:400% 400%;animation:gradient 15s ease infinite;
color:#fff;padding:20px;min-height:100vh;display:flex;align-items:center;justify-content:center;
}
@keyframes gradient{0%{background-position:0% 50%;}50%{background-position:100% 50%;}100%{background-position:0% 50%;}}
.box{
background:rgba(10,10,10,0.95);border:2px solid #FFD700;border-radius:24px;
padding:50px 40px;max-width:650px;width:100%;text-align:center;
box-shadow:0 0 50px rgba(255,215,0,0.3);
}
.icon{font-size:90px;margin-bottom:25px;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{transform:scale(1);}50%{transform:scale(1.1);}}
h1{
font-size:48px;margin-bottom:20px;font-weight:900;
background:linear-gradient(135deg,#FFD700,#FFA500);
-webkit-background-clip:text;-webkit-text-fill-color:transparent;
}
.price{font-size:72px;font-weight:900;margin-bottom:12px;}
.price span{font-size:26px;color:#aaa;}
.desc{color:#aaa;margin-bottom:45px;}
.features{text-align:left;margin-bottom:45px;}
.feature{
padding:18px;background:rgba(255,255,255,0.05);border-radius:14px;
margin-bottom:12px;display:flex;gap:18px;
}
.feature-icon{font-size:28px;}
.btn{
width:100%;padding:22px;background:linear-gradient(135deg,#FFD700,#FFA500);
border:none;border-radius:14px;color:#000;font-size:20px;font-weight:900;
cursor:pointer;margin-bottom:20px;box-shadow:0 6px 25px rgba(255,215,0,0.4);
}
.btn:hover{transform:translateY(-3px);}
.back{color:#667eea;text-decoration:none;}
.payment-info{
background:rgba(102,126,234,0.1);padding:20px;border-radius:12px;
margin-top:30px;font-size:13px;color:#aaa;text-align:left;
}
</style>
<script src="https://gumroad.com/js/gumroad.js"></script>
</head>
<body>
<div class="box">
<div class="icon">💎</div>
<h1>Diventa Premium</h1>
<div class="price">€15<span>/mese</span></div>
<p class="desc">Sblocca TUTTE le funzionalità di NEXUS AI</p>
<div class="features">
<div class="feature">
<span class="feature-icon">🎨</span>
<div><strong>Generazione Immagini HD</strong><br><small>Crea immagini straordinarie</small></div>
</div>
<div class="feature">
<span class="feature-icon">🎬</span>
<div><strong>Generazione Video</strong><br><small>Produci video professionali</small></div>
</div>
<div class="feature">
<span class="feature-icon">👁️</span>
<div><strong>Analisi Immagini AI</strong><br><small>Vision AI avanzata</small></div>
</div>
<div class="feature">
<span class="feature-icon">⚡</span>
<div><strong>Supporto Prioritario 24/7</strong><br><small>Assistenza immediata</small></div>
</div>
</div>
<a class="gumroad-button" href="{{ gumroad_url }}?wanted=true&username={{ user_id }}" 
data-gumroad-overlay-checkout="true">
<button class="btn">💳 Acquista Ora - €15/mese</button>
</a>
<a href="/" class="back">← Torna alla chat</a>
<div class="payment-info">
<strong>💳 Pagamento Sicuro</strong><br>
• Elaborato tramite Gumroad (sicuro 100%)<br>
• Carta, PayPal, Apple Pay<br>
• Cancella quando vuoi<br>
• Attivazione istantanea
</div>
</div>
<script>
// Check premium status ogni 3 secondi dopo click
let checking=false;
document.querySelector('.gumroad-button').addEventListener('click',function(){
if(checking)return;
checking=true;
const interval=setInterval(async()=>{
try{
const response=await fetch('/api/check-premium');
const data=await response.json();
if(data.premium){
clearInterval(interval);
alert('🎉 Benvenuto in Premium!\n\nOra hai accesso a TUTTE le funzionalità!');
window.location.href='/';
}
}catch(e){}
},3000);
setTimeout(()=>clearInterval(interval),300000); // Stop dopo 5 min
});
</script>
</body>
</html>''', gumroad_url=GUMROAD_URL, user_id=user_id)

# ============================================
# API ROUTES
# ============================================

@app.route('/api/register', methods=['POST'])
def register():
    """Registrazione nuovo utente"""
    try:
        data = request.json
        username = data.get('username', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not username or not email or not password:
            return jsonify({"ok": False, "msg": "Compila tutti i campi"})
        
        if len(username) < 3:
            return jsonify({"ok": False, "msg": "Username troppo corto (min 3)"})
        
        if len(password) < 6:
            return jsonify({"ok": False, "msg": "Password troppo corta (min 6)"})
        
        if username in USERS:
            return jsonify({"ok": False, "msg": "Username già esistente"})
        
        for user_data in USERS.values():
            if user_data.get('email') == email:
                return jsonify({"ok": False, "msg": "Email già registrata"})
        
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        USERS[username] = {
            "email": email,
            "password": hashed.decode('utf-8'),
            "premium": False,
            "guest": False,
            "created": get_italy_time().isoformat()
        }
        
        save_db()
        session['user'] = username
        session.permanent = True
        
        return jsonify({"ok": True})
        
    except Exception as e:
        return jsonify({"ok": False, "msg": f"Errore: {str(e)}"})

@app.route('/api/login', methods=['POST'])
def api_login():
    """Login utente"""
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({"ok": False, "msg": "Inserisci username e password"})
        
        if username not in USERS:
            return jsonify({"ok": False, "msg": "Utente non trovato"})
        
        user = USERS[username]
        
        if user.get('guest'):
            return jsonify({"ok": False, "msg": "Account ospite non valido"})
        
        if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({"ok": False, "msg": "Password errata"})
        
        session['user'] = username
        session.permanent = True
        
        return jsonify({"ok": True})
        
    except Exception as e:
        return jsonify({"ok": False, "msg":f"Errore: {str(e)}"})

@app.route('/api/chat', methods=['POST'])
def chat():
    """Endpoint chat principale"""
    if 'user' not in session:
        return jsonify({"ok": False, "msg": "Non autenticato"})
    
    try:
        user_id = session['user']
        user = USERS.get(user_id, {})
        is_premium = user.get('premium', False)
        
        message = request.form.get('message', '').strip()
        image = request.files.get('image')
        
        if image:
            if not is_premium:
                return jsonify({"ok": False, "msg": "⭐ L'analisi immagini richiede Premium!"})
            
            filename = f"{secrets.token_urlsafe(16)}.jpg"
            filepath = os.path.join("static/uploads", filename)
            image.save(filepath)
            
            result = analyze_img(filepath, message or "Analizza questa immagine")
            return jsonify({"ok": True, "response": result, "type": "text"})
        
        if not message:
            return jsonify({"ok": False, "msg": "Nessun messaggio"})
        
        detected_lang = detect_language(message)
        
        if any(w in message.lower() for w in ['genera immagine', 'crea immagine', 'disegna', 'generate image', 'create image', 'draw']):
            if not is_premium:
                return jsonify({"ok": False, "msg": "⭐ La generazione immagini richiede Premium!"})
            
            prompt = message.replace('genera immagine', '').replace('crea immagine', '').replace('disegna', '').strip()
            url = gen_image(prompt)
            
            if url:
                return jsonify({"ok": True, "url": url, "type": "image"})
            else:
                return jsonify({"ok": False, "msg": "❌ Errore generazione immagine"})
        
        if any(w in message.lower() for w in ['genera video', 'crea video', 'generate video', 'create video']):
            if not is_premium:
                return jsonify({"ok": False, "msg": "⭐ La generazione video richiede Premium!"})
            
            prompt = message.replace('genera video', '').replace('crea video', '').strip()
            result = gen_video(prompt)
            
            if result.get('ok'):
                return jsonify({"ok": True, "url": result['url'], "type": "video"})
            else:
                return jsonify({"ok": False, "msg": "❌ Errore generazione video"})
        
        system_prompt = get_system_prompt(detected_lang)
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": message}
        ]
        
        response = call_groq(messages)
        
        STATS['total_chats'] += 1
        save_db()
        
        return jsonify({"ok": True, "response": response, "type": "text"})
        
    except Exception as e:
        print(f"❌ Errore chat: {e}")
        return jsonify({"ok": False, "msg": f"Errore: {str(e)}"})

@app.route('/api/check-premium', methods=['GET'])
def check_premium():
    """Verifica stato Premium"""
    if 'user' not in session:
        return jsonify({"ok": False, "premium": False})
    
    user_id = session['user']
    user = USERS.get(user_id, {})
    
    return jsonify({
        "ok": True,
        "premium": user.get('premium', False),
        "user": user_id
    })

@app.route('/webhook/gumroad', methods=['POST'])
def gumroad_webhook():
    """Webhook Gumroad per attivazione Premium"""
    try:
        data = request.form.to_dict()
        email = data.get('email', '').strip().lower()
        username = data.get('username', '').strip()
        
        print(f"📥 Webhook Gumroad: {email} - {username}")
        
        if not email and not username:
            return jsonify({"ok": False, "msg": "No user identifier"}), 400
        
        user_found = None
        if username and username in USERS:
            user_found = username
        else:
            for user_id, user_data in USERS.items():
                if user_data.get('email') == email:
                    user_found = user_id
                    break
        
        if not user_found:
            return jsonify({"ok": False, "msg": "User not found"}), 404
        
        USERS[user_found]['premium'] = True
        USERS[user_found]['premium_activated'] = get_italy_time().isoformat()
        save_db()
        
        print(f"✅ Premium attivato: {user_found}")
        
        return jsonify({"ok": True, "msg": "Premium activated"})
        
    except Exception as e:
        print(f"❌ Errore webhook: {e}")
        return jsonify({"ok": False, "msg": str(e)}), 500

@app.route('/admin/stats')
def admin_stats():
    """Statistiche admin"""
    return jsonify({
        "version": VERSION,
        "total_users": len(USERS),
        "premium_users": sum(1 for u in USERS.values() if u.get('premium')),
        "guest_users": sum(1 for u in USERS.values() if u.get('guest')),
        "stats": STATS,
        "last_update": DB.get('last_update')
    })

if __name__ == '__main__':
    print("\n" + "="*60)
    print("⚡ NEXUS AI - IL BOT PIÙ POTENTE DELL'UNIVERSO")
    print("="*60)
    print(f"📅 Versione: {VERSION}")
    print(f"🕐 Ora Italia: {get_italy_time().strftime('%d/%m/%Y %H:%M:%S')}")
    print(f"👥 Utenti: {len(USERS)}")
    print(f"💎 Premium: {sum(1 for u in USERS.values() if u.get('premium'))}")
    print(f"✅ Groq AI: {'Connesso' if groq_client else 'Non disponibile'}")
    print("="*60)
    print("🚀 SERVER: http://127.0.0.1:5000")
    print("="*60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)


