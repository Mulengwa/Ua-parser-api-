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

limiter = Limiter(
    app=app, 
    key_func=get_remote_address, 
    default_limits=["200 per day", "50 per hour"], 
    storage_uri="memory://"
)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
if not ADMIN_SECRET: 
    raise RuntimeError("ADMIN_SECRET environment variable must be set")
if len(ADMIN_SECRET) < 32: 
    raise RuntimeError("ADMIN_SECRET must be 32+ characters for production")

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL: 
    raise RuntimeError("DATABASE_URL not set")

pool = ConnectionPool(
    conninfo=DATABASE_URL, 
    kwargs={"sslmode": "require", "connect_timeout": 5}, 
    min_size=1, 
    max_size=20, 
    open=True
)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "noreply@ua-parser-api.com")
SUPPORT_EMAIL = os.environ.get("SUPPORT_EMAIL", "mulengwa6@gmail.com")
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET")
USDT_PRICE_USD = float(os.environ.get("USDT_PRICE_USD", "5.00"))

@contextmanager
def get_db_cursor(row_factory=None):
    with pool.connection() as conn:
        with conn.cursor(row_factory=row_factory) as cur:
            yield cur
        conn.commit()

def validate_email(email):
    if not email or not isinstance(email, str): 
        return False
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH or len(email) < 5: 
        return False
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
        'applebot-extended': {'type': 'Applebot-Extended', 'allows_training': False},
        'bytespider': {'type': 'Bytespider', 'allows_training': False},
        'ccbot': {'type': 'CCBot', 'allows_training': True}
    }
    for token, info in ai_agents.items():
        if token in ua_lower: 
            return True, info['type'], info['allows_training']
    return False, None, True

def detect_headless(ua_string):
    ua_lower = ua_string.lower()
    headless_signals = ['headlesschrome', 'puppeteer', 'playwright', 'webdriver', 'selenium', 'phantomjs']
    return any(signal in ua_lower for signal in headless_signals)

def get_browser_engine(ua_string):
    ua_lower = ua_string.lower()
    if 'chrome' in ua_lower or 'chromium' in ua_lower: 
        return 'chromium'
    elif 'firefox' in ua_lower or 'gecko' in ua_lower: 
        return 'gecko'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower: 
        return 'webkit'
    return 'unknown'

def parse_language(request):
    accept_lang = request.headers.get('Accept-Language', '')
    if not accept_lang: 
        return None, None
    primary = accept_lang.split(',')[0].strip()
    parts = primary.split('-')
    lang = parts[0] if parts else None
    region = parts[1] if len(parts) > 1 else None
    return lang, region

def init_db():
    with get_db_cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS api_keys (key TEXT PRIMARY KEY, credits INT NOT NULL DEFAULT 0, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE TABLE IF NOT EXISTS orders (order_id TEXT PRIMARY KEY, api_key TEXT, email TEXT, provider TEXT DEFAULT 'nowpayments', amount NUMERIC, status TEXT DEFAULT 'pending', tx_hash TEXT, idempotency_key TEXT UNIQUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_email_status ON orders(email, status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_orders_idempotency_status ON orders(idempotency_key, status)")

def deduct_credit(api_key):
    if api_key == 'test':
        with get_db_cursor() as cur:
            cur.execute("INSERT INTO api_keys (key, credits) VALUES ('test', 1000) ON CONFLICT DO NOTHING")
            
    with get_db_cursor() as cur:
        cur.execute("UPDATE api_keys SET credits = credits - 1, updated_at = NOW() WHERE key = %s AND credits > 0 RETURNING credits", (api_key,))
        row = cur.fetchone()
        return row[0] if row else None

def create_or_update_key(api_key, credits=1000):
    with get_db_cursor() as cur:
        cur.execute("INSERT INTO api_keys (key, credits, updated_at) VALUES (%s, %s, NOW()) ON CONFLICT (key) DO UPDATE SET credits = api_keys.credits + %s, updated_at = NOW()", (api_key, credits, credits))

def send_api_key_email(to_email, api_key):
    if not RESEND_API_KEY: 
        print("ERROR: RESEND_API_KEY not set")
        return
    payload = {
        "from": f"UA Parser API <{RESEND_FROM_EMAIL}>", 
        "to": [to_email], 
        "subject": "Your UA Parser API Key is Ready", 
        "html": f"<h2>Thanks for your purchase!</h2><p>Your API key is ready:</p><pre>{escape(api_key)}</pre><p>Use: curl -H \"X-API-Key: {escape(api_key)}\" {BASE_URL}/v1/parse?ua=...</p>"
    }
    headers = {"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"}
    try:
        r = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10)
        r.raise
