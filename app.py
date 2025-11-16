#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NEXUS AI - IL BOT PIÙ POTENTE AL MONDO
✨ Groq AI Ultra-Veloce
🎨 Generazione Immagini 
📷 Analisi Immagini con Vision AI
💳 Pagamenti Gumroad
"""

import os
import secrets
import json
import base64
import requests
from datetime import datetime
from flask import Flask, request, jsonify, session, render_template_string, redirect, url_for
import bcrypt

try:
    from groq import Groq
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False
    print("⚠️ pip install groq")

# ============================================
# CONFIGURAZIONE
# ============================================
GROQ_API_KEY = "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"
GUMROAD_PRODUCT_URL = "https://micheleguerra.gumroad.com/l/superchatbot"
DATA_FILE = "nexus_data.json"

os.makedirs("static/uploads", exist_ok=True)
os.makedirs("static/generated", exist_ok=True)

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)

# Groq Client
groq_client = None
if HAS_GROQ and GROQ_API_KEY:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("✅ Groq AI: ATTIVO")
    except Exception as e:
        print(f"⚠️ Groq: {e}")

# ============================================
# DATABASE
# ============================================
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

# ============================================
# AI FUNCTIONS
# ============================================
def call_groq(messages, model="llama-3.1-8b-instant"):
    if not groq_client:
        return "⚠️ Groq non configurato. Aggiungi la tua API key."
    
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

# ============================================
# HTML TEMPLATES
# ============================================

CHAT_HTML = """
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>NEXUS AI - The Ultimate Bot</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        @keyframes gradient { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 20px rgba(102,126,234,0.5); } 50% { box-shadow: 0 0 40px rgba(102,126,234,0.8); } }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.05); } }
        
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
            box-shadow: 5px 0 30px rgba(0,0,0,0.5);
        }
        
        .logo {
            padding: 24px;
            text-align: center;
            border-bottom: 1px solid rgba(102,126,234,0.2);
            background: linear-gradient(135deg, rgba(102,126,234,0.1), rgba(118,75,162,0.1));
        }
        
        .logo h1 {
            font-size: 28px;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 2px;
        }
        
        .logo p {
            font-size: 11px;
            color: #888;
            margin-top: 4px;
            letter-spacing: 1px;
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
            box-shadow: 0 4px 15px rgba(102,126,234,0.3);
        }
        .new-chat:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(102,126,234,0.5);
        }
        
        .sidebar-content { 
            flex: 1; 
            overflow-y: auto; 
            padding: 16px; 
        }
        
        .user-section { 
            border-top: 1px solid rgba(102,126,234,0.2); 
            padding: 20px; 
            background: rgba(0,0,0,0.3);
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
            box-shadow: 0 4px 15px rgba(102,126,234,0.4);
        }
        
        .username { 
            font-size: 15px; 
            font-weight: 600; 
        }
        
        .plan { 
            font-size: 12px; 
            color: #888; 
        }
        
        .premium-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            background: linear-gradient(135deg, #FFD700, #FFA500);
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            color: #000;
            animation: pulse 2s infinite;
        }
        
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
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(255,107,107,0.4);
            font-size: 14px;
        }
        
        .upgrade-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(255,107,107,0.6);
        }
        
        .logout-btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
        }
        
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
        
        .message.user { 
            flex-direction: row-reverse; 
        }
        
        .msg-avatar { 
            width: 40px; 
            height: 40px; 
            border-radius: 12px; 
            display: flex; 
            align-items: center; 
            justify-content: center; 
            flex-shrink: 0;
            font-size: 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        }
        
        .msg-avatar.bot { 
            background: linear-gradient(135deg, #667eea, #764ba2); 
        }
        
        .msg-avatar.user { 
            background: linear-gradient(135deg, #f093fb, #f5576c); 
        }
        
        .bubble { 
            padding: 16px 20px; 
            border-radius: 18px; 
            max-width: 700px;
            line-height: 1.6;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
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
            display: block;
            box-shadow: 0 8px 30px rgba(0,0,0,0.3);
        }
        
        .input-area { 
            border-top: 1px solid rgba(102,126,234,0.2); 
            padding: 20px;
            background: rgba(10,10,10,0.95);
            backdrop-filter: blur(20px);
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
            transition: all 0.3s;
            flex-shrink: 0;
        }
        
        .tool-btn:hover { 
            background: rgba(102,126,234,0.4);
            transform: translateY(-2px);
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
            transition: all 0.3s;
        }
        
        #input:focus { 
            outline: none; 
            border-color: #667eea;
            background: rgba(255,255,255,0.08);
        }
        
        #input::placeholder {
            color: rgba(255,255,255,0.4);
        }
        
        #sendBtn { 
            width: 50px; 
            height: 50px; 
            background: linear-gradient(135deg, #667eea, #764ba2); 
            border: none; 
            border-radius: 12px; 
            color: #fff; 
            cursor: pointer; 
            font-size: 22px; 
            transition: all 0.3s;
            flex-shrink: 0;
        }
        
        #sendBtn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(102,126,234,0.6);
        }
        
        #sendBtn:disabled { 
            opacity: 0.5; 
            cursor: not-allowed;
        }
        
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
        
        .welcome p { 
            color: #aaa; 
            font-size: 18px; 
            max-width: 600px;
            line-height: 1.6;
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 40px;
            max-width: 800px;
        }
        
        .feature {
            background: rgba(102,126,234,0.1);
            border: 1px solid rgba(102,126,234,0.2);
            padding: 20px;
            border-radius: 16px;
            transition: all 0.3s;
        }
        
        .feature:hover {
            transform: translateY(-4px);
            box-shadow: 0 8px 30px rgba(102,126,234,0.3);
        }
        
        .feature-icon {
            font-size: 32px;
            margin-bottom: 12px;
        }
        
        .feature h3 {
            font-size: 16px;
            margin-bottom: 8px;
        }
        
        .feature p {
            font-size: 13px;
            color: #888;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(10px);
        }
        
        .modal.show {
            display: flex;
        }
        
        .modal-content {
            background: linear-gradient(135deg, rgba(102,126,234,0.2), rgba(118,75,162,0.2));
            border: 2px solid rgba(102,126,234,0.3);
            border-radius: 24px;
            padding: 40px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            animation: fadeIn 0.3s ease;
        }
        
        .modal-content h2 {
            font-size: 28px;
            margin-bottom: 20px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .modal-content input {
            width: 100%;
            padding: 14px;
            background: rgba(255,255,255,0.1);
            border: 1px solid rgba(102,126,234,0.3);
            border-radius: 12px;
            color: #fff;
            font-size: 15px;
            margin-bottom: 20px;
        }
        
        .modal-buttons {
            display: flex;
            gap: 12px;
        }
        
        .modal-btn {
            flex: 1;
            padding: 14px;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .modal-btn.primary {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: #fff;
        }
        
        .modal-btn.secondary {
            background: rgba(255,255,255,0.1);
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="logo">
            <h1>⚡ NEXUS</h1>
            <p>ULTIMATE AI ASSISTANT</p>
        </div>
        <button class="new-chat" onclick="newChat()">✨ Nuova Chat</button>
        <div class="sidebar-content">
            <div id="chatHistory"></div>
        </div>
        <div class="user-section">
            <div class="user-info">
                <div class="avatar" id="userAvatar">{{ username[0]|upper }}</div>
                <div>
                    <div class="username" id="username">{{ username }}</div>
                    <div class="plan" id="userPlan">
                        {% if premium %}
                        <span class="premium-badge">⭐ PREMIUM</span>
                        {% else %}
                        <span>Free Plan</span>
                        {% endif %}
                    </div>
                </div>
            </div>
            {% if not premium %}
            <button class="upgrade-btn" onclick="showUpgradeModal()">🚀 UPGRADE PREMIUM</button>
            {% endif %}
            <button class="upgrade-btn logout-btn" onclick="logout()">🚪 Logout</button>
        </div>
    </div>

    <div class="main">
        <div class="chat" id="chat">
            <div class="welcome">
                <div class="welcome-icon">🤖</div>
                <h1>Benvenuto {{ username }}!</h1>
                <p>Sono NEXUS, il bot AI più potente al mondo. Posso generare immagini, analizzare foto e rispondere a qualsiasi domanda!</p>
                
                <div class="features">
                    <div class="feature">
                        <div class="feature-icon">⚡</div>
                        <h3>Ultra Veloce</h3>
                        <p>Risposte istantanee</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">🎨</div>
                        <h3>Genera Immagini</h3>
                        <p>Scrivi "genera immagine di..."</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">👁️</div>
                        <h3>Analizza Foto</h3>
                        <p>Carica un'immagine con 📎</p>
                    </div>
                    <div class="feature">
                        <div class="feature-icon">💬</div>
                        <h3>Chat Intelligente</h3>
                        <p>Chiedi qualsiasi cosa</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="input-area">
            <div class="input-wrapper">
                <button class="tool-btn" onclick="document.getElementById('fileInput').click()" title="Carica immagine">📎</button>
                <input type="file" id="fileInput" style="display: none;" accept="image/*">
                
                <textarea id="input" placeholder="Prova: 'genera un'immagine di un gatto spaziale' oppure 'ciao, come stai?'" 
                    onkeydown="if(event.key==='Enter' && !event.shiftKey) { event.preventDefault(); sendMessage(); }"></textarea>
                
                <button id="sendBtn" onclick="sendMessage()">➤</button>
            </div>
        </div>
    </div>

    <div id="upgradeModal" class="modal">
        <div class="modal-content">
            <h2>🚀 Upgrade a Premium</h2>
            <p style="margin-bottom: 20px; color: #aaa;">Sblocca chat illimitate e funzionalità avanzate</p>
            
            <div style="background: rgba(102,126,234,0.1); padding: 20px; border-radius: 12px; margin-bottom: 20px;">
                <h3 style="font-size: 20px; margin-bottom: 12px;">💎 Piano Premium - €15/mese</h3>
                <ul style="color: #aaa; line-height: 2; margin-left: 20px;">
                    <li>✨ Chat illimitate</li>
                    <li>🎨 Generazione immagini HD illimitata</li>
                    <li>🤖 Modello AI più potente (Llama 3.3 70B)</li>
                    <li>👁️ Analisi immagini avanzata</li>
                    <li>⚡ Risposte prioritarie</li>
                    <li>🔥 Accesso anticipato a nuove features</li>
                </ul>
            </div>
            
            <a href="{{ GUMROAD_PRODUCT_URL }}" target="_blank" style="
                display: block;
                width: 100%;
                padding: 16px;
                background: linear-gradient(135deg, #FFD700, #FFA500);
                border: none;
                border-radius: 12px;
                color: #000;
                font-size: 16px;
                font-weight: 700;
                text-align: center;
                text-decoration: none;
                transition: all 0.3s;
                box-shadow: 0 4px 15px rgba(255,215,0,0.4);
                margin-bottom: 12px;
            ">
                💳 Acquista su Gumroad
            </a>
            
            <div style="text-align: center; color: #888; font-size: 13px; margin-bottom: 20px;">
                Dopo l'acquisto, riceverai la license key via email
            </div>
            
            <input type="text" id="licenseKey" placeholder="Inserisci la tua License Key ricevuta via email" style="margin-bottom: 20px;">
            
            <div class="modal-buttons">
                <button class="modal-btn secondary" onclick="closeUpgradeModal()">Chiudi</button>
                <button class="modal-btn primary" onclick="activateLicense()">✅ Attiva License</button>
            </div>
            
            <div style="margin-top: 20px; text-align: center; color: #666; font-size: 12px;">
                💡 Per test: usa "PREMIUM-TEST123" come license key
            </div>
        </div>
    </div>

    <script>
        let selectedFile = null;

        function newChat() {
            document.getElementById('chat').innerHTML = `
                <div class="welcome">
                    <div class="welcome-icon">🤖</div>
                    <h1>Nuova Chat</h1>
                    <p>Cosa posso fare per te oggi?</p>
                </div>
            `;
            document.getElementById('input').value = '';
            selectedFile = null;
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
            input.value = '';
            
            try {
                const formData = new FormData();
                formData.append('message', text);
                
                if (selectedFile) {
                    formData.append('file', selectedFile);
                    formData.append('type', 'vision');
                } else if (text.toLowerCase().includes('genera') && (text.toLowerCase().includes('immagine') || text.toLowerCase().includes('immagin') || text.toLowerCase().includes('foto') || text.toLowerCase().includes('disegn'))) {
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
                } else {
                    addMessageToUI('bot', data.response, data.media);
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

        function addMessageToUI(role, content, media = null) {
            const chat = document.getElementById('chat');
            const isBot = role === 'bot';
            
            let mediaHtml = '';
            if (media) {
                mediaHtml = `<img src="${media}" alt="Generated" loading="lazy">`;
            }
            
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${role}`;
            messageDiv.innerHTML = `
                <div class="msg-avatar ${role}">${isBot ? '🤖' : '👤'}</div>
                <div class="bubble ${role}">
                    ${content}
                    ${mediaHtml}
                </div>
            `;
            
            chat.appendChild(messageDiv);
            chat.scrollTop = chat.scrollHeight;
        }

        document.getElementById('fileInput').addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                selectedFile = e.target.files[0];
                addMessageToUI('user', `📎 Immagine caricata: ${selectedFile.name}`);
            }
        });

        function showUpgradeModal() {
            document.getElementById('upgradeModal').classList.add('show');
        }

        function closeUpgradeModal() {
            document.getElementById('upgradeModal').classList.remove('show');
        }

        async function activateLicense() {
            const licenseKey = document.getElementById('licenseKey').value.trim();
            
            if (!licenseKey) {
                alert('Inserisci una license key valida');
                return;
            }
            
            try {
                const response = await fetch('/api/activate-premium', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ license_key: licenseKey })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    alert('✅ Premium attivato!');
                    closeUpgradeModal();
                    location.reload();
                } else {
                    alert('❌ ' + (data.message || 'License key non valida'));
                }
            } catch (error) {
                alert('❌ Errore attivazione');
            }
        }

        async function logout() {
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch(e) {}
            window.location.href = '/login';
        }

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
        
        @keyframes gradient { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } }
        @keyframes glow { 0%, 100% { box-shadow: 0 0 30px rgba(102,126,234,0.5); } 50% { box-shadow: 0 0 60px rgba(102,126,234,0.8); } }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(-45deg, #0a0a0a, #1a1a2e, #16213e, #0f3460);
            background-size: 400% 400%;
            animation: gradient 15s ease infinite;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .login-container {
            background: rgba(10,10,10,0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(102,126,234,0.2);
            border-radius: 24px;
            padding: 50px 40px;
            max-width: 450px;
            width: 100%;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
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
            animation: glow 2s infinite;
        }
        
        .logo-container h1 {
            font-size: 36px;
            font-weight: 900;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: 2px;
            margin-bottom: 8px;
        }
        
        .logo-container p {
            color: #888;
            font-size: 14px;
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
            transition: all 0.3s;
        }
        
        .tab.active {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: #fff;
            border-color: transparent;
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
            transition: all 0.3s;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #667eea;
            background: rgba(255,255,255,0.08);
            box-shadow: 0 0 20px rgba(102,126,234,0.2);
        }
        
        .form-group input::placeholder {
            color: rgba(255,255,255,0.3);
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
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102,126,234,0.4);
            margin-top: 10px;
        }
        
        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 25px rgba(102,126,234,0.6);
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
            border: 1px solid rgba(0,200,83,0.3);
            color: #00C853;
        }
        
        .message.error {
            background: rgba(255,107,107,0.2);
            border: 1px solid rgba(255,107,107,0.3);
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
            <p>The Ultimate AI Assistant</p>
        </div>
        
        <div class="tabs">
            <div class="tab active" onclick="switchTab('login')">Login</div>
            <div class="tab" onclick="switchTab('register')">Registrati</div>
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
            hideMessage();
        }
        
        function showMessage(text, type) {
            const msg = document.getElementById('message');
            msg.textContent = text;
            msg.className = `message ${type}`;
            msg.style.display = 'block';
        }
        
        function hideMessage() {
            document.getElementById('message').style.display = 'none';
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

# ============================================
# ROUTES
# ============================================

@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for('login_page'))
    
    username = session.get("username")
    user = USERS.get(username, {})
    
    return render_template_string(
        CHAT_HTML, 
        username=user.get("username", "User"),
        premium=user.get("premium", False),
        GUMROAD_PRODUCT_URL=GUMROAD_PRODUCT_URL
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
            "chat_count": 0
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
        user = USERS.get(username)
        
        if not user:
            return jsonify({"error": "Utente non trovato"}), 404
        
        message = request.form.get("message", "").strip()
        request_type = request.form.get("type", "chat")
        
        if not user.get("premium", False):
            today_count = user.get("chat_count", 0)
            if today_count >= 50:
                return jsonify({
                    "error": "Limite giornaliero raggiunto (50 messaggi). Passa a Premium per chat illimitate!",
                    "upgrade": True
                })
        
        user["chat_count"] = user.get("chat_count", 0) + 1
        save_db()
        
        if request_type == "image":
            image_url = generate_image(message)
            return jsonify({
                "success": True,
                "response": "✨ Ecco l'immagine generata:",
                "media": image_url
            })
        
        elif request_type == "vision" and 'file' in request.files:
            file = request.files['file']
            if file:
                filename = f"upload_{secrets.token_hex(8)}.{file.filename.split('.')[-1]}"
                filepath = os.path.join("static/uploads", filename)
                file.save(filepath)
                
                analysis = analyze_image_vision(filepath, message or "Descrivi questa immagine in dettaglio")
                
                return jsonify({
                    "success": True,
                    "response": f"👁️ Analisi dell'immagine:\n\n{analysis}"
                })
        
        else:
            messages = [
                {
                    "role": "system",
                    "content": """You are NEXUS, the most powerful and advanced AI assistant in the world. 

KEY INSTRUCTION: Always respond in the SAME LANGUAGE the user writes to you. If they write in Italian, respond in Italian. If they write in English, respond in English. If they write in Spanish, respond in Spanish, etc.

Characteristics:
- Ultra-fast and intelligent
- Expert in all fields: programming, math, science, art, writing
- Creative, innovative and friendly
- Give complete, clear and engaging answers
- ALWAYS match the user's language automatically

Special capabilities:
🎨 HD image generation (user can ask "generate an image of...")
👁️ Advanced image analysis (user can upload photos)
💻 Expert programming
📊 Analysis and problem solving
✍️ Creative writing

Always respond naturally and helpfully in the user's language."""
                },
                {
                    "role": "user",
                    "content": message
                }
            ]
            
            model = "llama-3.3-70b-versatile" if user.get("premium") else "llama-3.1-8b-instant"
            response = call_groq(messages, model)
            
            return jsonify({
                "success": True,
                "response": response
            })
    
    except Exception as e:
        print(f"Chat error: {e}")
        return jsonify({
            "error": f"Errore: {str(e)}"
        }), 500

@app.route("/api/activate-premium", methods=["POST"])
def activate_premium():
    try:
        if "username" not in session:
            return jsonify({"success": False, "message": "Login richiesto"}), 401
        
        data = request.json
        license_key = data.get("license_key", "").strip()
        
        if not license_key:
            return jsonify({"success": False, "message": "Inserisci una license key"})
        
        if license_key in USED_LICENSES:
            return jsonify({"success": False, "message": "Questa license key è già stata utilizzata"})
        
        username = session.get("username")
        user = USERS.get(username)
        
        # Accetta qualsiasi key nel formato corretto (minimo 10 caratteri)
        # In produzione, integrerai Gumroad API per la verifica reale
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
                "message": "🎉 Premium attivato con successo! Ricarica la pagina."
            })
        else:
            return jsonify({
                "success": False,
                "message": "License key non valida. Deve essere almeno 10 caratteri."
            })
    
    except Exception as e:
        print(f"Premium error: {e}")
        return jsonify({
            "success": False,
            "message": "Errore durante l'attivazione"
        }), 500

# ============================================
# AVVIO APP
# ============================================

if __name__ == "__main__":
    print("\n" + "="*60)
    print("⚡ NEXUS AI - IL BOT PIÙ POTENTE AL MONDO")
    print("="*60)
    print(f"✅ Groq AI: {'ATTIVO' if groq_client else 'NON CONFIGURATO'}")
    print(f"\n📊 Utenti: {len(USERS)}")
    print(f"💎 Premium: {sum(1 for u in USERS.values() if u.get('premium', False))}")
    print("\n🌐 Server: http://127.0.0.1:5000")
    print("\n💡 ISTRUZIONI:")
    print("   1. Registrati/Login")
    print("   2. Il bot risponde automaticamente nella TUA lingua")
    print("   3. Scrivi 'generate an image of...' o 'genera un'immagine di...'")
    print("   4. Clicca 📎 per analizzare foto")
    print("   5. Premium: clicca UPGRADE e usa 'PREMIUM-TEST123' per test")
    print("   6. Cambia GUMROAD_PRODUCT_URL nel codice con il tuo link prodotto")
    print("="*60 + "\n")
    
    app.run(debug=True, host="0.0.0.0", port=5000)
