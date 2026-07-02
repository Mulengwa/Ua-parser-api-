from flask import Flask, request, jsonify, send_from_directory
from user_agents import parse
from waitress import serve
import os, hashlib, hmac, json, uuid, time, re
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from contextlib import contextmanager
import requests
import secrets
from html import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
MAX_UA_LENGTH = 5000
MAX_EMAIL_LENGTH = 254
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
API_KEY_PATTERN = re.compile(r'^(sk_live_[a-zA-Z0-9_\-]{16,}|test)$')
ALLOWED_ORIGINS = set(os.environ.get("ALLOWED_ORIGINS", "").split(",")) if os.environ.get("ALLOWED_ORIGINS") else set()
BASE_URL = os.environ.get("BASE_URL", "http://localhost:10000")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", BASE_URL)
ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")
if 'localhost' in BASE_URL and ENVIRONMENT == 'production': 
    raise RuntimeError("Cannot use localhost URLs in production")

limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"], storage_uri="memory://")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
if not ADMIN_SECRET: 
    raise RuntimeError("ADMIN_SECRET environment variable must be set")
if len(ADMIN_SECRET) < 32: 
    raise RuntimeError("ADMIN_SECRET must be 32+ characters for production")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL: 
    raise RuntimeError("DATABASE_URL not set")

pool = ConnectionPool(conninfo=DATABASE_URL, kwargs={"sslmode": "require", "connect_timeout": 5}, min_size=1, max_size=20, open=True)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "noreply@ua-parser-api.com")
SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "mulengwa6@gmail.com")
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET")
USDT_PRICE_USD = float(os.environ.get("USDT_PRICE_USD", "5.00"))

# Raw HTML Templates to avoid multi-line formatting issues
HOME_HTML = """<!DOCTYPE html><html><head><title>UA Parser API</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;line-height:1.6}h1{color:#111}.card{border:1px solid #e5e5e5;border-radius:12px;padding:24px;margin:20px 0}textarea{width:100%;height:80px;padding:10px;font-family:monospace;border:1px solid #ddd;border-radius:8px}button{background:#000;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-size:16px;margin-top:10px}button:hover{background:#333}pre{background:#f6f8fa;padding:16px;border-radius:8px;overflow-x:auto}.badge{background:#e6f7ff;color:#0958d9;padding:4px 12px;border-radius:20px;font-size:14px;display:inline-block}a{color:#0969da;text-decoration:none}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;margin:10px 0}</style></head><body><h1>UA Parser for Humans + AI Agents</h1><p class="badge">1000 free requests/day with key=test</p><p>Fast, accurate User-Agent parsing. 2ms avg latency. No signup needed to test.</p><div class="card"><h3>Try it now</h3><textarea id="ua" placeholder="Paste User-Agent here...">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36</textarea><button onclick="testAPI()">Run Test</button><pre id="result">Result will appear here...</pre></div><div class="card"><h3>Ready to go beyond free?</h3><p>$5 for 1000 requests. Card or crypto. No memo needed.</p><input id="email" type="email" placeholder="Enter your email"><button onclick="buyAPI()">Buy $5</button></div><p><a href="/docs">📖 API Docs</a> | <a href="/openapi.json">OpenAPI Spec</a></p><script>async function testAPI(){const ua=document.getElementById('ua').value;const resultEl=document.getElementById('result');resultEl.textContent='Loading...';try{const res=await fetch(`/v1/parse?key=test&ua=${encodeURIComponent(ua)}`);const data=await res.json();resultEl.textContent=JSON.stringify(data,null,2)}catch(e){resultEl.textContent='Error: '+e.message}}async function buyAPI(){const email=document.getElementById('email').value;if(!email)return alert('Enter email first');const res=await fetch('/create-order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});const data=await res.json();console.log('NowPayments response:',data);if(data.checkout_url)window.open(data.checkout_url,'_self');else alert(data.error||'Error: '+JSON.stringify(data))}</script></body></html>"""

DOCS_HTML = """<!DOCTYPE html><html><head><title>UA Parser API Docs</title><link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui',presets:[SwaggerUIBundle.presets.apis]})</script></body></html>"""

THANKS_HTML = """<!DOCTYPE html><html><head><title>Payment Successful - UA Parser API</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:600px;margin:60px auto;padding:0 20px;line-height:1.6;text-align:center}h1{color:#22c55e}.card{border:1px solid #e5e5e5;border-radius:12px;padding:24px;margin:20px 0}p{color:#666}a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}</style></head><body><h1>✓ Payment Successful!</h1><div class="card"><p>Thank you for your purchase!</p><p>Your API key has been sent to your email. Check your inbox (and spam folder) in the next few minutes.</p><p>If you don't receive it within 15 minutes, <a href="mailto:SUPPORT_EMAIL_PLACEHOLDER">contact support</a>.</p><p><a href="/">Back to Home</a></p></div></body></html>"""

@contextmanager
def get_db_cursor(row_factory=None):
    with pool.connection() as conn:
        with conn.cursor(row_factory=row_factory) as cur:
            yield cur
        conn.commit()

def validate_email(email):
    if not email or not isinstance(email, str): return False
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH or len(email) < 5: return False
    return bool(re.match(EMAIL_PATTERN, email))

def validate_api_key_format(key):
    return bool(API_KEY_PATTERN.match(key)) if key else False

def detect_ai_agent(ua_string):
    ua_lower = ua_string.lower()
    ai_agents = {
        'gptbot': {'type': 'GPTBot', 'allows_training': False},
        'chatgpt-user': {'type': 'ChatGPT-User', 'allows_training': True},
        'claudebot': {'type': 'ClaudeBot', 'allows_training': False},
        'claude-web': {'type': 'Claude-Web', 'allows_training': True},
        'google-extended': {'type': 'Google-Extended', 'allows_training': False},
        'perplexitybot': {'type': 'PerplexityBot', 'allows_training': False},
        'applebot-extended': {'type': 'Applebot-Extended', '
