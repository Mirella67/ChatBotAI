#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXUS AI - IL BOT PIÙ POTENTE AL MONDO
"""

import os
import secrets
import json
import base64
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, render_template_string, redirect, url_for
import bcrypt

try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False
    print("⚠️ pip install groq")

# CONFIGURAZIONE
GROQ_API_KEY = "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"
REPLICATE_API_KEY = "r8_dvhoEsZoMZ4iVPCeLtenbcaML0VZw5233ilJP"  # Aggiungi la tua key da https://replicate.com
GUMROAD_PRODUCT_URL = "https://micheleguerra.gumroad.com/l/superchatbot"
DATA_FILE = "nexus_data.json"

os.makedirs("static/uploads", exist_ok=True)
os.makedirs("static/generated", exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Groq Client
groq_client = None
if HAS_GROQ and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("✅ Groq AI: ATTIVO")
    except Exception as e:
        print(f"⚠️ Groq: {e}")

# DATABASE
def load_db():
    if not os.path.exists(DATA_FILE):
        return {"users": {}, "premium_licenses": {}, "used_licenses": []}
    try:
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    except:
        return {"users": {}, "premium_licenses": {}, "used_licenses": []}

def save_db():
    try:
        data = {
            "users": USERS,
            "premium_licenses": PREMIUM_LICENSES,
            "used_licenses": list(USED_LICENSES)
        }
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception as e:
        print(f"❌ Save: {e}")
        return False

DB = load_db()
USERS = DB.get("users", {})
PREMIUM_LICENSES = DB.get("premium_licenses", {})
USED_LICENSES = set(DB.get("used_licenses", []))

# AI FUNCTIONS
def call_groq(messages, model="llama-3.1-8b-instant"):
    if not groq_client:
        return "⚠️ Groq non configurato."
    
    try:
        response = groq_client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=2048,
            temperature=0.8,
            top_p=0.9
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Errore AI: {e}"

def generate_image(prompt):
    return f"https://image.pollinations.ai/prompt/{requests.utils.quote(prompt)}?width=768&height=768&nologo=true"

def generate_video(prompt):
    """Genera video con API text-to-video"""
    
    # Se hai Replicate API key, usa questo
    if REPLICATE_API_KEY:
        try:
            import replicate
            
            output = replicate.run(
                "stability-ai/stable-video-diffusion:3f0457e4619daac51203dedb472816fd4af51f3149fa7a9e0b5ffcf1b8172438",
                input={
                    "cond_aug": 0.02,
                    "decoding_t": 7,
                    "input_image": f"https://image.pollinations.ai/prompt/{requests.utils.quote(prompt)}?width=1024&height=576",
                    "video_length": "14_frames_with_svd",
                    "sizing_strategy": "maintain_aspect_ratio",
                    "motion_bucket_id": 127,
                    "frames_per_second": 6
                }
            )
            
            if output:
                return {"url": output, "success": True}
        except Exception as e:
            print(f"Replicate error: {e}")
    
    # Fallback: usa servizio gratuito
    try:
        # Genera prima un'immagine
        image_url = f"https://image.pollinations.ai/prompt/{requests.utils.quote(prompt)}?width=1024&height=576&nologo=true"
        
        # Simula video con immagine animata
        video_html = f'''
        <div style="position: relative; width: 100%; max-width: 768px; margin-top: 12px;">
            <img src="{image_url}" style="width: 100%; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.3);" />
            <div style="position: absolute; top: 10px; right: 10px; background: rgba(255,107,107,0.9); padding: 6px 12px; border-radius: 8px; font-size: 12px; font-weight: 700;">
                🎬 VIDEO PREVIEW
            </div>
            <div style="margin-top: 8px; padding: 12px; background: rgba(102,126,234,0.1); border-radius: 8px; font-size: 13px; color: #aaa;">
                💡 Anteprima: Per generare video reali, aggiungi REPLICATE_API_KEY nel codice
            </div>
        </div>
        '''
        
        return {"html": video_html, "success": True, "preview": True}
        
    except Exception as e:
        return {"error": f"Errore generazione video: {e}", "success": False}

def analyze_image_vision(image_path, question):
    if not groq_client:
        return "Vision AI non disponibile"
    
    try:
        with open(image_path, "rb") as f:
            image_data = base64.b64encode(f.read()).decode()
        
        response = groq_client.chat.completions.create(
            model="llava-v1.5-7b-4096-preview",
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": question},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_data}"}}
                ]
            }],
            max_tokens=1024
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Analisi non disponibile: {e}"

# HTML CHAT
CHAT_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
    <title>NEXUS AI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        @keyframes gradient { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 20px rgba(102,126,234,0.5); } 50% { box-shadow: 0 0 40px rgba(102,126,234,0.8); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: linear-gradient(-45deg, #0a0a0a, #1a1a2e, #16213e, #0f3460);
            background-size: 400% 400%;
            animation: gradient 15s ease infinite;
            color: #fff; 
            height: 100vh; 
            display: flex; 
            overflow: hidden; 
        }
        
        .sidebar { 
            width: 280px; 
            background: rgba(10,10,10,0.95); 
            backdrop-filter: blur(20px);
            display: flex; 
            flex-direction: column; 
            border-right: 1px solid rgba(102,126,234,0.2); 
        }
        
        .logo {
            padding: 24px;
            text-align: center;
            border-bottom: 1px solid rgba(102,126,234,0.2);
        }
        
        .logo h1 {
            font-size: 28px;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .new-chat { 
            margin: 16px;
            padding: 14px; 
            background: linear-gradient(135deg, #667eea, #764ba2); 
            border: none; 
            border-radius: 12px; 
            color: #fff; 
            cursor: pointer; 
            font-size: 15px; 
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .new-chat:hover { 
            transform: translateY(-2px);
        }
        
        .sidebar-content { 
            flex: 1; 
            overflow-y: auto; 
            padding: 16px; 
        }
        
        .user-section { 
            border-top: 1px solid rgba(102,126,234,0.2); 
            padding: 20px; 
        }
        
        .user-info { 
            display: flex; 
            align-items: center; 
            gap: 12px; 
            margin-bottom: 12px; 
        }
        
        .avatar { 
            width: 44px; 
            height: 44px; 
            background: linear-gradient(135deg, #667eea, #764ba2); 
            border-radius: 50%; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-weight: 900; 
            font-size: 18px;
        }
        
        .username { font-size: 15px; font-weight: 600; }
        .plan { font-size: 12px; color: #888; }
        
        .upgrade-btn { 
            width: 100%; 
            padding: 14px; 
            background: linear-gradient(135deg, #FF6B6B, #FF8E53); 
            border: none; 
            border-radius: 12px; 
            color: #fff; 
            font-weight: 700; 
            cursor: pointer; 
            margin-bottom: 8px;
            font-size: 14px;
        }
        
        .logout-btn { background: linear-gradient(135deg, #667eea, #764ba2); }
        
        .main { 
            flex: 1; 
            display: flex; 
            flex-direction: column; 
        }
        
        .chat { 
            flex: 1; 
            overflow-y: auto; 
            padding: 24px;
        }
        
        .message { 
            max-width: 900px; 
            margin: 0 auto 24px; 
            display: flex; 
            gap: 16px;
            animation: fadeIn 0.5s ease;
        }
        
        .message.user { flex-direction: row-reverse; }
        
        .msg-avatar { 
            width: 40px; 
            height: 40px; 
            border-radius: 12px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 20px;
        }
        
        .msg-avatar.bot { background: linear-gradient(135deg, #667eea, #764ba2); }
        .msg-avatar.user { background: linear-gradient(135deg, #f093fb, #f5576c); }
        
        .bubble { 
            padding: 16px 20px; 
            border-radius: 18px; 
            max-width: 700px;
            line-height: 1.6;
            white-space: pre-wrap;
        }
        
        .bubble.bot { 
            background: rgba(102,126,234,0.15); 
            border: 1px solid rgba(102,126,234,0.2);
        }
        
        .bubble.user { 
            background: rgba(240,147,251,0.2); 
            border: 1px solid rgba(240,147,251,0.3);
        }
        
        .bubble img { 
            max-width: 100%; 
            border-radius: 12px; 
            margin-top: 12px; 
        }
        
        .bubble video {
            max-width: 100%;
            border-radius: 12px;
            margin-top: 12px;
        }
        
        .input-area { 
            border-top: 1px solid rgba(102,126,234,0.2); 
            padding: 20px;
            background: rgba(10,10,10,0.95);
        }
        
        .input-wrapper { 
            max-width: 900px; 
            margin: 0 auto; 
            display: flex; 
            gap: 12px; 
            align-items: flex-end;
        }
        
        .tool-btn { 
            width: 50px; 
            height: 50px; 
            background: rgba(102,126,234,0.2); 
            border: 1px solid rgba(102,126,234,0.3); 
            border-radius: 12px; 
            color: #fff; 
            cursor: pointer; 
            font-size: 22px;
            flex-shrink: 0;
        }
        
        #input { 
            flex: 1; 
            padding: 14px 18px; 
            background: rgba(255,255,255,0.05); 
            border: 1px solid rgba(102,126,234,0.3); 
            border-radius: 16px; 
            color: #fff; 
            font-size: 15px; 
            resize: none; 
            min-height: 50px; 
            max-height: 200px; 
            font-family: inherit;
        }
        
        #input:focus { 
            outline: none; 
            border-color: #667eea;
        }
        
        #input::placeholder { color: rgba(255,255,255,0.4); }
        
        #sendBtn { 
            width: 50px; 
            height: 50px; 
            background: linear-gradient(135deg, #667eea, #764ba2); 
            border: none; 
            border-radius: 12px; 
            color: #fff; 
            cursor: pointer; 
            font-size: 22px; 
            flex-shrink: 0;
        }
        
        #sendBtn:disabled { opacity: 0.5; cursor: not-allowed; }
        
        .welcome { 
            display: flex; 
            flex-direction: column; 
            align-items: center; 
            justify-content: center; 
            height: 100%; 
            text-align: center; 
            padding: 40px;
        }
        
        .welcome-icon { 
            width: 120px; 
            height: 120px; 
            background: linear-gradient(135deg, #667eea, #764ba2); 
            border-radius: 30px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 60px; 
            margin-bottom: 30px;
            animation: glow 2s infinite;
        }
        
        .welcome h1 { 
            font-size: 48px; 
            margin-bottom: 16px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 900;
        }
        
        .welcome p { color: #aaa; font-size: 18px; max-width: 600px; }
        
        /* MOBILE */
        .mobile-header { display: none; }
        .sidebar-overlay { display: none; }
        
        @media (max-width: 768px) {
            body { flex-direction: column; }
            
            .sidebar {
                position: fixed;
                left: -280px;
                top: 0;
                height: 100vh;
                z-index: 1000;
                transition: left 0.3s ease;
            }
            
            .sidebar.open { left: 0; }
            
            .mobile-header {
                display: flex;
                align-items: center;
                justify-content: space-between;
                padding: 16px 20px;
                background: rgba(10,10,10,0.95);
                border-bottom: 1px solid rgba(102,126,234,0.2);
            }
            
            .menu-btn {
                background: rgba(102,126,234,0.2);
                border: 1px solid rgba(102,126,234,0.3);
                border-radius: 10px;
                color: #fff;
                font-size: 24px;
                width: 45px;
                height: 45px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .mobile-title {
                font-size: 18px;
                font-weight: 700;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            
            .sidebar-overlay {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.7);
                z-index: 999;
            }
            
            .sidebar-overlay.show { display: block; }
            
            .chat { padding: 16px; }
            .welcome { padding: 20px; }
            .welcome-icon { width: 80px; height: 80px; font-size: 40px; }
            .welcome h1 { font-size: 32px; }
            .welcome p { font-size: 16px; }
            .message { margin-bottom: 16px; }
            .msg-avatar { width: 35px; height: 35px; font-size: 18px; }
            .bubble { padding: 12px 16px; font-size: 15px; }
            .input-area { padding: 12px; }
            .input-wrapper { gap: 8px; }
            .tool-btn { width: 45px; height: 45px; }
            #input { font-size: 16px; padding: 12px; min-height: 45px; }
            #sendBtn { width: 45px; height: 45px; }
        }
    </style>
</head>
<body>
    <div class="mobile-header">
        <button class="menu-btn" onclick="toggleSidebar()">☰</button>
        <div class="mobile-title">⚡ NEXUS AI</div>
        <div style="width: 45px;"></div>
    </div>
    
    <div class="sidebar-overlay" id="sidebarOverlay" onclick="toggleSidebar()"></div>

    <div class="sidebar" id="sidebar">
        <div class="logo">
            <h1>⚡ NEXUS</h1>
        </div>
        <button class="new-chat" onclick="newChat()">✨ Nuova Chat</button>
        <div class="sidebar-content">
            <div id="chatHistory">
                {% if not is_guest %}
                <div style="padding: 12px; color: #888; font-size: 13px;">📚 Cronologia Chat</div>
                {% else %}
                <div style="padding: 12px; color: #888; font-size: 13px; text-align: center;">⚠️ Modalità Ospite</div>
                {% endif %}
            </div>
        </div>
        <div class="user-section">
            <div class="user-info">
                <div class="avatar">{{ username[0]|upper }}</div>
                <div>
                    <div class="username">{{ username }}</div>
                    <div class="plan">
                        {% if premium %}Premium{% else %}Free{% endif %}
                    </div>
                </div>
            </div>
            {% if not premium and not is_guest %}
            <button class="upgrade-btn" onclick="showUpgradeModal()">🚀 UPGRADE</button>
            {% endif %}
            {% if not is_guest %}
            <button class="upgrade-btn logout-btn" onclick="logout()">🚪 Logout</button>
            {% else %}
            <button class="upgrade-btn logout-btn" onclick="window.location.href='/login'">🔐 Accedi</button>
            {% endif %}
        </div>
    </div>

    <div class="main">
        <div class="chat" id="chat">
            <div class="welcome">
                <div class="welcome-icon">🤖</div>
                <h1>Benvenuto!</h1>
                <p>Sono NEXUS, il bot AI più potente. Posso generare immagini, creare video, analizzare foto e rispondere in qualsiasi lingua!</p>
            </div>
        </div>
        
        <div class="input-area">
            <div class="input-wrapper">
                <button class="tool-btn" onclick="document.getElementById('fileInput').click()">📎</button>
                <input type="file" id="fileInput" style="display: none;" accept="image/*">
                
                <textarea id="input" placeholder="Scrivi: 'genera immagine di...' o 'crea video di...' o qualsiasi domanda!" 
                    onkeydown="if(event.key==='Enter' && !event.shiftKey) { event.preventDefault(); sendMessage(); }"></textarea>
                
                <button id="sendBtn" onclick="sendMessage()">➤</button>
            </div>
        </div>
    </div>

    <script>
        let selectedFile = null;
        let currentChatMessages = [];
        let isGuest = {{ 'true' if is_guest else 'false' }};
        
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('open');
            document.getElementById('sidebarOverlay').classList.toggle('show');
        }

        function newChat() {
            if (currentChatMessages.length > 0 && !isGuest) {
                saveCurrentChat();
            }
            
            currentChatMessages = [];
            document.getElementById('chat').innerHTML = '<div class="welcome"><div class="welcome-icon">🤖</div><h1>Nuova Chat</h1><p>Cosa posso fare per te?</p></div>';
            document.getElementById('input').value = '';
            selectedFile = null;
            
            if (window.innerWidth <= 768) {
                toggleSidebar();
            }
        }
        
        async function saveCurrentChat() {
            if (isGuest || currentChatMessages.length === 0) return;
            
            try {
                await fetch('/api/save-chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        messages: currentChatMessages,
                        timestamp: new Date().toISOString()
                    })
                });
            } catch (e) {
                console.error('Errore salvataggio:', e);
            }
        }

        async function sendMessage() {
            const input = document.getElementById('input');
            const text = input.value.trim();
            
            if (!text && !selectedFile) return;
            
            const sendBtn = document.getElementById('sendBtn');
            input.disabled = true;
            sendBtn.disabled = true;
            
            const welcome = document.querySelector('.welcome');
            if (welcome) welcome.remove();
            
            addMessageToUI('user', text);
            currentChatMessages.push({role: 'user', content: text, media: null});
            input.value = '';
            
            try {
                const formData = new FormData();
                formData.append('message', text);
                
                if (selectedFile) {
                    formData.append('file', selectedFile);
                    formData.append('type', 'vision');
                } else if (text.toLowerCase().match(/crea|genera|create|generate/) && text.toLowerCase().match(/video/)) {
                    formData.append('type', 'video');
                } else if (text.toLowerCase().match(/genera|generate/) && text.toLowerCase().match(/immag|image|foto|photo/)) {
                    formData.append('type', 'image');
                } else {
                    formData.append('type', 'chat');
                }
                
                const response = await fetch('/api/chat', {
                    method: 'POST',
                    body: formData
                });
                
                const data = await response.json();
                
                if (data.error) {
                    addMessageToUI('bot', `❌ ${data.error}`);
                    currentChatMessages.push({role: 'bot', content: data.error, media: null});
                } else {
                    addMessageToUI('bot', data.response, data.media, data.html);
                    currentChatMessages.push({role: 'bot', content: data.response, media: data.media || data.html});
                }
                
            } catch (error) {
                addMessageToUI('bot', '❌ Errore: ' + error.message);
            } finally {
                input.disabled = false;
                sendBtn.disabled = false;
                input.focus();
                selectedFile = null;
            }
        }

        function addMessageToUI(role, content, media = null, html = null) {
            const chat = document.getElementById('chat');
            const isBot = role === 'bot';
            
            let mediaHtml = '';
            if (html) {
                mediaHtml = html;
            } else if (media) {
                if (media.endsWith('.mp4') || media.endsWith('.webm')) {
                    mediaHtml = `<video src="${media}" controls style="max-width: 100%; border-radius: 12px; margin-top: 12px;"></video>`;
                } else {
                    mediaHtml = `<img src="${media}" alt="Generated" loading="lazy">`;
                }
            }
            
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}`;
            messageDiv.innerHTML = `
                <div class="msg-avatar ${role}">${isBot ? '🤖' : '👤'}</div>
                <div class="bubble ${role}">${content}${mediaHtml}</div>
            `;
            
            chat.appendChild(messageDiv);
            chat.scrollTop = chat.scrollHeight;
        }

        document.getElementById('fileInput').addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                selectedFile = e.target.files[0];
                addMessageToUI('user', `📎 Immagine: ${selectedFile.name}`);
            }
        });

        function showUpgradeModal() {
            alert('Premium: €15/mese\\n\\nUsa license key: PREMIUM-TEST123');
        }

        async function logout() {
            if (currentChatMessages.length > 0 && !isGuest) {
                await saveCurrentChat();
            }
            
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch(e) {}
            window.location.href = '/login';
        }
        
        window.addEventListener('beforeunload', () => {
            if (currentChatMessages.length > 0 && !isGuest) {
                saveCurrentChat();
            }
        });

        document.getElementById('input').addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 200) + 'px';
        });
    </script>
</body>
</html>
"""

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>NEXUS AI - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(-45deg, #0a0a0a, #1a1a2e, #16213e, #0f3460);
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .login-container {
            background: rgba(10,10,10,0.95);
            border: 1px solid rgba(102,126,234,0.2);
            border-radius: 24px;
            padding: 50px 40px;
            max-width: 450px;
            width: 100%;
        }
        
        .logo-container {
            text-align: center;
            margin-bottom: 40px;
        }
        
        .logo-icon {
            width: 90px;
            height: 90px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 22px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 45px;
            margin-bottom: 20px;
        }
        
        .logo-container h1 {
            font-size: 36px;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
        }
        
        .tab {
            flex: 1;
            padding: 12px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(102,126,234,0.2);
            border-radius: 12px;
            color: #aaa;
            cursor: pointer;
            text-align: center;
            font-weight: 600;
        }
        
        .tab.active {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: #fff;
            border-color: transparent;
        }
        
        .guest-link {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .guest-link a {
            color: #667eea;
            text-decoration: none;
            font-size: 14px;
            font-weight: 600;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #aaa;
            font-size: 14px;
            font-weight: 600;
        }
        
        .form-group input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(102,126,234,0.3);
            border-radius: 12px;
            color: #fff;
            font-size: 15px;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .submit-btn {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border: none;
            border-radius: 12px;
            color: #fff;
            font-size: 16px;
            font-weight: 700;
            cursor: pointer;
            margin-top: 10px;
        }
        
        .message {
            padding: 12px 16px;
            border-radius: 10px;
            margin-bottom: 20px;
            font-size: 14px;
            display: none;
        }
        
        .message.success {
            background: rgba(0,200,83,0.2);
            color: #00C853;
        }
        
        .message.error {
            background: rgba(255,107,107,0.2);
            color: #FF6B6B;
        }
        
        #registerForm { display: none; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-container">
            <div class="logo-icon">⚡</div>
            <h1>NEXUS AI</h1>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('login')">Login</div>
            <div class="tab" onclick="switchTab('register')">Registrati</div>
        </div>
        
        <div class="guest-link">
            <a href="/guest">👤 Oppure continua come Ospite →</a>
        </div>
        
        <div id="message" class="message"></div>
        
        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Il tuo username" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="La tua password" required>
            </div>
            <button type="submit" class="submit-btn">🚀 Accedi</button>
        </form>
        
        <form id="registerForm" onsubmit="handleRegister(event)">
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" placeholder="Scegli un username" required>
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" placeholder="La tua email" required>
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="Crea una password" required>
            </div>
            <button type="submit" class="submit-btn">✨ Crea Account</button>
        </form>
    </div>
    
    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            
            document.getElementById('loginForm').style.display = tab === 'login' ? 'block' : 'none';
            document.getElementById('registerForm').style.display = tab === 'register' ? 'block' : 'none';
            document.getElementById('message').style.display = 'none';
        }
        
        function showMessage(text, type) {
            const msg = document.getElementById('message');
            msg.textContent = text;
            msg.className = 'message ' + type;
            msg.style.display = 'block';
        }
        
        async function handleLogin(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            try {
                const response = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.fromEntries(formData))
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('✅ Login effettuato!', 'success');
                    setTimeout(() => window.location.href = '/', 1000);
                } else {
                    showMessage('❌ ' + data.message, 'error');
                }
            } catch (error) {
                showMessage('❌ Errore di connessione', 'error');
            }
        }
        
        async function handleRegister(e) {
            e.preventDefault();
            const formData = new FormData(e.target);
            
            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(Object.fromEntries(formData))
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showMessage('✅ Account creato! Accedi ora.', 'success');
                    setTimeout(() => {
                        document.querySelector('.tab:first-child').click();
                    }, 2000);
                } else {
                    showMessage('❌ ' + data.message, 'error');
                }
            } catch (error) {
                showMessage('❌ Errore di connessione', 'error');
            }
        }
    </script>
</body>
</html>
"""

# ROUTES
@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for('login_page'))
    
    username = session.get("username")
    user = USERS.get(username, {})
    
    chat_history = user.get("chat_history", [])
    
    return render_template_string(
        CHAT_HTML, 
        username=user.get("username", "User"),
        premium=user.get("premium", False),
        chat_history=json.dumps(chat_history),
        is_guest=False
    )

@app.route("/guest")
def guest_mode():
    session["username"] = "guest"
    session["is_guest"] = True
    return render_template_string(
        CHAT_HTML, 
        username="Ospite",
        premium=False,
        chat_history="[]",
        is_guest=True
    )

@app.route("/login")
def login_page():
    return render_template_string(LOGIN_HTML)

@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.json
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        
        if not username or not email or not password:
            return jsonify({"success": False, "message": "Compila tutti i campi"})
        
        if username in USERS:
            return jsonify({"success": False, "message": "Username già esistente"})
        
        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        
        USERS[username] = {
            "username": username,
            "email": email,
            "password": hashed.decode(),
            "premium": False,
            "created_at": datetime.utcnow().isoformat(),
            "chat_count": 0,
            "chat_history": []
        }
        
        save_db()
        
        return jsonify({"success": True})
    except Exception as e:
        print(f"Register error: {e}")
        return jsonify({"success": False, "message": "Errore registrazione"})

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.json
        username = data.get("username", "").strip()
        password = data.get("password", "")
        
        user = USERS.get(username)
        
        if not user:
            return jsonify({"success": False, "message": "Username non trovato"})
        
        if not bcrypt.checkpw(password.encode(), user["password"].encode()):
            return jsonify({"success": False, "message": "Password errata"})
        
        session["username"] = username
        session.permanent = True
        return jsonify({"success": True})
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"success": False, "message": "Errore login"})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

@app.route("/api/chat", methods=["POST"])
def chat():
    try:
        if "username" not in session:
            return jsonify({"error": "Login richiesto"}), 401
        
        username = session.get("username")
        is_guest = session.get("is_guest", False)
        
        if is_guest:
            user = {"premium": False, "chat_count": 0}
        else:
            user = USERS.get(username)
            if not user:
                return jsonify({"error": "Utente non trovato"}), 404
        
        message = request.form.get("message", "").strip()
        request_type = request.form.get("type", "chat")
        
        if not is_guest and not user.get("premium", False):
            today_count = user.get("chat_count", 0)
            if today_count >= 50:
                return jsonify({
                    "error": "Limite giornaliero raggiunto (50 messaggi). Passa a Premium!"
                })
        
        if not is_guest:
            user["chat_count"] = user.get("chat_count", 0) + 1
        
        response_data = {}
        
        if request_type == "video":
            video_result = generate_video(message)
            if video_result.get("success"):
                if video_result.get("preview"):
                    response_data = {
                        "success": True,
                        "response": "🎬 Video generato (preview):",
                        "html": video_result.get("html")
                    }
                else:
                    response_data = {
                        "success": True,
                        "response": "🎬 Video generato con successo:",
                        "media": video_result.get("url")
                    }
            else:
                response_data = {
                    "error": video_result.get("error", "Errore generazione video")
                }
        
        elif request_type == "image":
            image_url = generate_image(message)
            response_data = {
                "success": True,
                "response": "✨ Ecco l'immagine generata:",
                "media": image_url
            }
        
        elif request_type == "vision" and 'file' in request.files:
            file = request.files['file']
            if file:
                filename = f"upload_{secrets.token_hex(8)}.{file.filename.split('.')[-1]}"
                filepath = os.path.join("static/uploads", filename)
                file.save(filepath)
                
                analysis = analyze_image_vision(filepath, message or "Descrivi questa immagine")
                
                response_data = {
                    "success": True,
                    "response": f"👁️ Analisi:\n\n{analysis}"
                }
        
        else:
            now = datetime.utcnow()
            current_date = now.strftime("%A, %d %B %Y")
            current_time = now.strftime("%H:%M UTC")
            
            messages = [
                {
                    "role": "system",
                    "content": f"""You are NEXUS, the most powerful AI assistant.

CRITICAL: ALWAYS respond in the EXACT SAME LANGUAGE the user writes to you.
- Italian → Rispondi in italiano
- English → Respond in English  
- Spanish → Responde en español
- French → Réponds en français

CURRENT INFO:
📅 Date: {current_date}
🕐 Time: {current_time}
📍 Year: {now.year}
🌍 Knowledge updated to January 2025

You are modern, fast, expert in all fields. You know recent events up to January 2025.

Special capabilities:
🎨 Image generation ("generate/genera un'immagine di...")
🎥 Video generation ("create/crea un video di...")
👁️ Image analysis (user uploads photos)
💻 Programming expert
📊 Data analysis

Always respond naturally in the user's language."""
                },
                {
                    "role": "user",
                    "content": message
                }
            ]
            
            model = "llama-3.3-70b-versatile" if user.get("premium") else "llama-3.1-8b-instant"
            ai_response = call_groq(messages, model)
            
            response_data = {
                "success": True,
                "response": ai_response
            }
        
        if not is_guest:
            save_db()
        
        return jsonify(response_data)
    
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({
            "error": f"Errore: {str(e)}"
        }), 500

@app.route("/api/save-chat", methods=["POST"])
def save_chat():
    try:
        if "username" not in session or session.get("is_guest"):
            return jsonify({"success": False}), 401
        
        username = session.get("username")
        user = USERS.get(username)
        
        if not user:
            return jsonify({"success": False}), 404
        
        data = request.json
        messages = data.get("messages", [])
        timestamp = data.get("timestamp")
        
        if len(messages) == 0:
            return jsonify({"success": False})
        
        if "chat_history" not in user:
            user["chat_history"] = []
        
        new_chat = {
            "timestamp": timestamp,
            "messages": messages
        }
        
        user["chat_history"].insert(0, new_chat)
        user["chat_history"] = user["chat_history"][:50]
        
        save_db()
        
        return jsonify({"success": True})
    
    except Exception as e:
        print(f"Save chat error: {e}")
        return jsonify({"success": False}), 500

@app.route("/api/activate-premium", methods=["POST"])
def activate_premium():
    try:
        if "username" not in session or session.get("is_guest"):
            return jsonify({"success": False, "message": "Login richiesto"}), 401
        
        data = request.json
        license_key = data.get("license_key", "").strip()
        
        if not license_key:
            return jsonify({"success": False, "message": "Inserisci license key"})
        
        if license_key in USED_LICENSES:
            return jsonify({"success": False, "message": "License key già utilizzata"})
        
        username = session.get("username")
        user = USERS.get(username)
        
        if len(license_key) >= 10:
            user["premium"] = True
            user["premium_activated_at"] = datetime.utcnow().isoformat()
            user["license_key"] = license_key
            
            USED_LICENSES.add(license_key)
            PREMIUM_LICENSES[license_key] = {
                "username": username,
                "activated_at": datetime.utcnow().isoformat()
            }
            
            save_db()
            
            return jsonify({
                "success": True,
                "message": "Premium attivato!"
            })
        else:
            return jsonify({
                "success": False,
                "message": "License key non valida"
            })
    
    except Exception as e:
        print(f"Premium error: {e}")
        return jsonify({
            "success": False,
            "message": "Errore attivazione"
        }), 500

if __name__ == "__main__":
    print("\n" + "="*60)
    print("⚡ NEXUS AI - IL BOT PIÙ POTENTE AL MONDO")
    print("="*60)
    print(f"✅ Groq AI: {'ATTIVO' if groq_client else 'NON CONFIGURATO'}")
    print(f"\n📊 Utenti: {len(USERS)}")
    print(f"💎 Premium: {sum(1 for u in USERS.values() if u.get('premium', False))}")
    print("\n🌐 Server: http://127.0.0.1:5000")
    print("\n💡 FUNZIONALITÀ:")
    print("   ✅ Login permanente (30 giorni)")
    print("   ✅ Multilingua automatico")
    print("   ✅ Data e ora aggiornate")
    print("   ✅ Chat salvate (nuova chat o chiusura)")
    print("   ✅ Generazione immagini ('genera immagine di...')")
    print("   ✅ Generazione video ('crea video di...')")
    print("   ✅ Analisi foto con Vision AI")
    print("   ✅ Responsive mobile e desktop")
    print("   ✅ Modalità ospite (no salvataggio)")
    print("\n📦 Installa: pip install flask groq bcrypt requests")
    print("   Opzionale video reali: pip install replicate")
    print("   Poi aggiungi REPLICATE_API_KEY nel codice")
    print("="*60 + "\n")
    
    app.run(debug=True, host="0.0.0.0", port=5000)
