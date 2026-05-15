from flask import Flask, request, jsonify, send_from_directory
from user_agents import parse
from waitress import serve
import os, hashlib, hmac
from datetime import datetime
import psycopg
from psycopg.rows import dict_row

app = Flask(__name__)

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me")
LEMON_WEBHOOK_SECRET = os.environ.get("LEMON_WEBHOOK_SECRET")
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

def init_db():
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key TEXT PRIMARY KEY,
                    credits INT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        conn.commit()
    print("DB initialized: api_keys table ready")

def get_credits(api_key):
    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT credits FROM api_keys WHERE key = %s", (api_key,))
            row = cur.fetchone()
            return row['credits'] if row else 0

def deduct_credit(api_key):
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE api_keys SET credits = credits - 1, updated_at = NOW() WHERE key = %s AND credits > 0 RETURNING credits",
                (api_key,)
            )
            row = cur.fetchone()
            if row:
                conn.commit()
                return row[0]
            return None

def create_or_update_key(api_key, credits=1000):
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO api_keys (key, credits, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key)
                DO UPDATE SET credits = api_keys.credits + %s, updated_at = NOW()
            """, (api_key, credits, credits))
        conn.commit()

@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-API-Latency'] = '2ms'
    return response

@app.route('/health')
def health():
    return jsonify({"status": "ok", "latency": "2ms", "timestamp": str(datetime.utcnow())}), 200

@app.route('/v1/parse')
def parse_ua():
    key = request.args.get('key', '')
    ua_string = request.args.get('ua', '')

    credits = get_credits(key)
    if not key or credits <= 0:
        return jsonify({
            "error": "No credits",
            "price": "$5 = 1000 parses",
            "buy": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679?test_mode=1",
            "free_tier": "1000/day with key=test_123. No signup.",
            "docs": "https://ua-parser-api-zsql.onrender.com/openapi.json"
        }), 402

    if not ua_string:
        return jsonify({"error": "Missing?ua=Mozilla/5.0..."}), 400

    new_credits = deduct_credit(key)
    if new_credits is None:
        return jsonify({"error": "No credits left"}), 402

    u = parse(ua_string)
    ua_lower = ua_string.lower()
    ai_bots = ['gptbot','chatgpt-user','claudebot','anthropic','google-extended','perplexitybot','bytespider']
    is_ai_bot = any(b in ua_lower for b in ai_bots)

    return jsonify({
        "browser": u.browser.family,
        "browser_version": u.browser.version_string,
        "os": u.os.family,
        "os_version": u.os.version_string,
        "device": u.device.family,
        "device_type": "mobile" if u.is_mobile else "tablet" if u.is_tablet else "desktop",
        "is_bot": u.is_bot,
        "is_ai_crawler": is_ai_bot,
        "credits_left": new_credits
    }), 200, {'Cache-Control': 'public, max-age=86400', 'CDN-Cache-Control': 'max-age=31536000'}

@app.route('/v1/webhook', methods=['POST'])
def lemon_webhook():
    signature = request.headers.get('X-Signature', '')
    digest = hmac.new(LEMON_WEBHOOK_SECRET.encode(), request.get_data(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, digest):
        return jsonify({"error": "Invalid signature"}), 401

    data = request.json
    event = data.get('meta', {}).get('event_name')

    if event in ['order_created', 'subscription_payment_success']:
        api_key = data.get('meta', {}).get('custom_data', {}).get('api_key')
        if api_key:
            create_or_update_key(api_key, 1000)
            print(f"UPGRADED KEY: {api_key}")
            return jsonify({"success": True, "key": api_key})

    return jsonify({"status": "ignored"}), 200

@app.route('/openapi.json')
def openapi():
    return send_from_directory('.', 'openapi.json')

@app.route('/llms.txt')
def llms_txt():
    return send_from_directory('.', 'llms.txt')

@app.route('/')
def home():
    return jsonify({
        "service": "UA Parser for Humans + AI Agents",
        "latency": "2ms avg",
        "free_tier": "1000/day key=test_123",
        "paid": "$5/1000. Instant key delivery.",
        "features": ["AI bot detection", "CORS enabled", "OpenAPI 3.1", "Global CDN", "Postgres-backed"],
        "buy": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679?test_mode=1",
        "health": "/health",
        "schema": "/openapi.json",
        "llms": "/llms.txt"
    })

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 10000))
    serve(app, host="0.0.0.0", port=port)
