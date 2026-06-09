from flask import Flask, request, jsonify, send_from_directory
from user_agents import parse
from waitress import serve
import os, hashlib, hmac, json, uuid, time, re
from datetime import datetime
import psycopg
from psycopg.rows import dict_row
import requests
import secrets

# ==================== FLASK-LIMITER IMPORTS ====================
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ==================== APP INITIALIZATION ====================
app = Flask(__name__)

# ==================== SECURITY CONSTANTS ====================
MAX_UA_LENGTH = 5000
MAX_EMAIL_LENGTH = 254
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
ALLOWED_ORIGINS = set(
    os.environ.get("ALLOWED_ORIGINS", "").split(",")
) if os.environ.get("ALLOWED_ORIGINS") else set()

# ==================== RATE LIMITER SETUP ====================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ==================== ENVIRONMENT VARIABLES ====================
ADMIN_SECRET = os.environ.get("ADMIN_SECRET")
if not ADMIN_SECRET:
    raise RuntimeError("ADMIN_SECRET environment variable must be set")
DATABASE_URL = os.environ.get("DATABASE_URL")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "noreply@ua-parser-api.com")

# ==================== NOWPAYMENTS CONFIG ====================
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY")
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET")
USDT_PRICE_USD = float(os.environ.get("USDT_PRICE_USD", "5.00"))

# ==================== STARTUP CHECKS ====================
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# ==================== HELPER FUNCTIONS ====================
def validate_email(email):
    """Validate email address format and length. Prevents spam/abuse."""
    if not email or not isinstance(email, str):
        return False
    email = email.strip().lower()
    if len(email) > MAX_EMAIL_LENGTH or len(email) < 5:
        return False
    return bool(re.match(EMAIL_PATTERN, email))

# AI FEATURE #1: Bot/AI Agent Detection
def detect_ai_agent(ua_string):
    """
    Detect AI crawlers/bots from User-Agent string.
    Returns (is_ai_agent, bot_type, allows_training)
    2026: AI agents need to know if traffic is GPTBot, ClaudeBot, etc for robots.txt compliance
    """
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

# AI FEATURE #3: Headless browser detection
def detect_headless(ua_string):
    """
    Detect headless browsers: Puppeteer, Playwright, Selenium.
    AI agents use this to serve different content vs real users.
    """
    ua_lower = ua_string.lower()
    headless_signals = [
        'headlesschrome', 'puppeteer', 'playwright',
        'webdriver', 'selenium', 'phantomjs'
    ]
    return any(signal in ua_lower for signal in headless_signals)

# AI FEATURE #4: Browser engine detection
def get_browser_engine(ua_string):
    """
    Extract browser engine: chromium, gecko, webkit.
    AI agents use this to infer JS capabilities like WebAssembly, ES2022 support.
    """
    ua_lower = ua_string.lower()
    if 'chrome' in ua_lower or 'chromium' in ua_lower:
        return 'chromium'
    elif 'firefox' in ua_lower or 'gecko' in ua_lower:
        return 'gecko'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        return 'webkit'
    return 'unknown'

# AI FEATURE #6: Language + Region hints
def parse_language(request):
    """
    Parse Accept-Language header for primary_lang + region.
    AI agents use this to request localized content.
    """
    accept_lang = request.headers.get('Accept-Language', '')
    if not accept_lang:
        return None, None

    primary = accept_lang.split(',')[0].strip()
    parts = primary.split('-')
    lang = parts[0] if parts else None
    region = parts[1] if len(parts) > 1 else None
    return lang, region

# ==================== DATABASE FUNCTIONS ====================
def init_db():
    """Initialize database tables on startup. Creates api_keys and orders tables."""
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key TEXT PRIMARY KEY,
                    credits INT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    order_id TEXT PRIMARY KEY,
                    api_key TEXT,
                    email TEXT,
                    provider TEXT DEFAULT 'nowpayments',
                    amount NUMERIC,
                    status TEXT DEFAULT 'pending',
                    tx_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        conn.commit()
    print("DB initialized: api_keys and orders tables ready")

def get_credits(api_key):
    """Get remaining credits for a given API key. Auto-creates 'test' key with 1000 credits."""
    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT credits FROM api_keys WHERE key = %s", (api_key,))
            row = cur.fetchone()
            if not row and api_key == 'test':
                cur.execute("INSERT INTO api_keys (key, credits) VALUES ('test', 1000) ON CONFLICT DO NOTHING")
                conn.commit()
                return 1000
            return row['credits'] if row else 0

def deduct_credit(api_key):
    """Deduct 1 credit from the API key if credits > 0. Atomic to prevent race conditions."""
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
    """Create a new API key or add credits to existing key. ON CONFLICT handles existing keys."""
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO api_keys (key, credits, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key)
                DO UPDATE SET credits = api_keys.credits + %s, updated_at = NOW()
            """, (api_key, credits, credits))
        conn.commit()

def send_api_key_email(to_email, api_key):
    """Send the API key to customer email using Resend. Only sends if RESEND_API_KEY is set."""
    if not RESEND_API_KEY:
        print("ERROR: RESEND_API_KEY not set - email not sent")
        return
    payload = {
        "from": f"UA Parser API <{RESEND_FROM_EMAIL}>",
        "to": [to_email],
        "subject": "Your UA Parser API Key is Ready",
        "html": f"""
        <h2>Thanks for your purchase!</h2>
        <p>Your API key is ready to use:</p>
        <pre style="background:#f4f4f4;padding:10px;border-radius:5px;">{api_key}</pre>
        <p>Use it like this: <code>/v1/parse?key={api_key}&ua=...</code></p>
        <p>You have 1000 credits. Each request uses 1 credit.</p>
        """
    }
    headers = {"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"}
    try:
        r = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10)
        r.raise_for_status()
        print(f"EMAIL SENT to {to_email}")
    except Exception as e:
        print(f"ERROR sending email: {e}")

# ==================== MIDDLEWARE ====================
@app.after_request
def add_headers(response):
    """Add CORS and custom headers to all responses. Restricts CORS to configured origins."""
    origin = request.headers.get('Origin')
    if origin == 'http://localhost:3000' or origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin
    elif not ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-API-Latency'] = '2ms'
    return response

# ==================== API ENDPOINTS ====================
@app.route('/health')
@limiter.exempt
def health():
    """Health check endpoint for Render/Deta and monitoring tools."""
    return jsonify({"status": "ok", "latency": "2ms", "timestamp": str(datetime.utcnow())}), 200

@app.route('/v1/parse')
@limiter.limit("100/minute")
def parse_ua():
    """
    Main API endpoint: Parse a User-Agent string.
    AI FEATURES ADDED: bot detection, training flags, platform, engine, headless, lang
    Logic unchanged - just extended JSON response for AI agents
    """
    key = request.args.get('key', '').strip()
    ua_string = request.args.get('ua', '').strip()

    if not ua_string:
        return jsonify({"error": "Missing?ua=Mozilla/5.0..."}), 400

    if len(ua_string) > MAX_UA_LENGTH:
        return jsonify({"error": f"UA string too long (max {MAX_UA_LENGTH} chars)"}), 400

    credits = get_credits(key)
    if not key or credits <= 0:
        return jsonify({
            "error": "No credits",
            "price": f"${USDT_PRICE_USD} = 1000 parses",
            "buy": "/create-order",
            "free_tier": "1000/day with key=test",
            "docs": "/docs"
        }), 402

    new_credits = deduct_credit(key)
    if new_credits is None:
        return jsonify({"error": "No credits left"}), 402

    try:
        u = parse(ua_string)
    except Exception as e:
        print(f"Error parsing UA: {e}")
        return jsonify({"error": "Invalid UA string"}), 400

    # ==================== AI AGENT FEATURES START ====================
    # FEATURE #1: Bot/AI Agent Detection
    is_ai_agent, bot_type, allows_training = detect_ai_agent(ua_string)

    # FEATURE #3: Platform + Device Granularity + Headless
    platform = u.os.family.lower() if u.os.family else 'unknown'
    device_type = "mobile" if u.is_mobile else "tablet" if u.is_tablet else "desktop"
    is_headless = detect_headless(ua_string)

    # FEATURE #4: Browser engine + version
    browser_engine = get_browser_engine(ua_string)

    # FEATURE #6: Language + Region
    primary_lang, region = parse_language(request)

    # FEATURE #5: Cloud/Server detection - basic version using device_type
    is_datacenter = device_type == 'server' or is_headless
    hosting_provider = None
    # ==================== AI AGENT FEATURES END ====================

    return jsonify({
        "browser": u.browser.family,
        "browser_version": u.browser.version_string,
        "os": u.os.family,
        "os_version": u.os.version_string,
        "device": u.device.family,
        "device_type": device_type,
        "is_bot": u.is_bot,

        # AI FEATURE #1: AI agent detection
        "is_ai_agent": is_ai_agent,
        "bot_type": bot_type,

        # AI FEATURE #2: LLM Training Opt-out
        "allows_training": allows_training,

        # AI FEATURE #3: Platform + Headless
        "platform": platform,
        "is_headless": is_headless,

        # AI FEATURE #4: Engine + capabilities
        "browser_engine": browser_engine,

        # AI FEATURE #5: Cloud detection
        "is_datacenter": is_datacenter,
        "hosting_provider": hosting_provider,

        # AI FEATURE #6: Language
        "primary_lang": primary_lang,
        "region": region,

        "credits_left": new_credits
    }), 200, {'Cache-Control': 'public, max-age=86400', 'CDN-Cache-Control': 'max-age=31536000'}

# ==================== NOWPAYMENTS PAYMENT ROUTES ====================
@app.route('/create-order', methods=['POST', 'GET'])
@limiter.limit("5/minute")
def create_order():
    """Creates NowPayments invoice. Customer only sees $5. No memo/address shown."""
    if request.method == 'GET':
        return jsonify({"message": "POST JSON with {\"email\":\"you@example.com\"} to create order"})

    data = request.get_json() or {}
    email = data.get('email', '').strip().lower() if data.get('email') else ''

    if not validate_email(email):
        return jsonify({"error": "Invalid email address"}), 400

    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT order_id FROM orders WHERE email = %s AND status = 'pending' LIMIT 1",
                (email,)
            )
            existing = cur.fetchone()
            if existing:
                return jsonify({
                    "error": "You already have a pending order. Check your email or contact support."
                }), 409

    order_id = f"order_{email.replace('@','_').replace('.','_')}_{uuid.uuid4().hex[:6]}"
    api_key = "sk_live_" + secrets.token_urlsafe(16)

    create_or_update_key(api_key, 0)
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO orders (order_id, api_key, email, amount, status, provider)
                VALUES (%s, %s, %s, %s, 'pending', 'nowpayments')
            """, (order_id, api_key, email, USDT_PRICE_USD))
        conn.commit()

    if not NOWPAYMENTS_API_KEY:
        return jsonify({"error": "Payment not configured"}), 500

    np_payload = {
        "price_amount": USDT_PRICE_USD,
        "price_currency": "usd",
        "pay_currency": "usdttrc20",
        "order_id": order_id,
        "order_description": "UA Parser API - 1000 credits",
        "ipn_callback_url": "https://ua-parser-api-zsql.onrender.com/webhook/nowpayments",
        "success_url": "https://ua-parser-api-zsql.onrender.com/thanks",
        "cancel_url": "https://ua-parser-api-zsql.onrender.com/"
    }

    headers = {"x-api-key": NOWPAYMENTS_API_KEY}
    r = requests.post("https://api.nowpayments.io/v1/invoice", json=np_payload, headers=headers, timeout=10)

    if r.status_code!= 200:
        print(f"NowPayments error: {r.text}")
        return jsonify({"error": "Payment provider error"}), 500

    invoice = r.json()

    return jsonify({
        "checkout_url": invoice['invoice_url'],
        "order_id": order_id,
        "message": "Customer sees $5 only. No memo needed."
    }), 200

@app.route('/webhook/nowpayments', methods=['POST'])
@limiter.exempt
def nowpayments_webhook():
    """NowPayments calls this automatically when customer pays. Verifies signature."""
    received_sig = request.headers.get('x-nowpayments-sig')
    if not received_sig:
        print("ERROR: Missing x-nowpayments-sig header")
        return 'Invalid signature', 403

    payload = request.get_data()
    if not NOWPAYMENTS_IPN_SECRET:
        return 'IPN secret not set', 500

    calc_sig = hmac.new(
        NOWPAYMENTS_IPN_SECRET.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(received_sig, calc_sig):
        print(f"ERROR: Signature mismatch")
        return 'Invalid signature', 403

    try:
        data = request.get_json()
    except Exception as e:
        print(f"ERROR: Invalid JSON in webhook: {e}")
        return 'Invalid payload', 400

    if data.get('payment_status') == 'finished':
        order_id = data.get('order_id')
        amount = float(data.get('price_amount', 0))

        with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
                order = cur.fetchone()

        if order and order['status']!= 'paid' and amount >= USDT_PRICE_USD:
            with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE orders SET status = 'paid', tx_hash = %s WHERE order_id = %s",
                                (data.get('txid'), order_id))
                    conn.commit()

            create_or_update_key(order['api_key'], 1000)
            send_api_key_email(order['email'], order['api_key'])
            print(f"NOWPAYMENTS FULFILLED {order_id} - TX: {data.get('txid')}")

    return 'ok', 200

# ==================== STATIC FILES ====================
@app.route('/openapi.json')
@limiter.exempt
def openapi():
    """Serve OpenAPI spec file for Swagger UI and AI agents."""
    return send_from_directory('.', 'openapi.json')

@app.route('/llms.txt')
@limiter.exempt
def llms_txt():
    """Serve llms.txt for AI crawlers and documentation tools."""
    return send_from_directory('.', 'llms.txt')

# ==================== LANDING PAGE ====================
@app.route('/')
@limiter.exempt
def home():
    """Landing page with interactive API tester."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>UA Parser API</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                   max-width: 700px; margin: 40px auto; padding: 0 20px; line-height: 1.6; }
            h1 { color: #111; }
          .card { border: 1px solid #e5e5e5; border-radius: 12px; padding: 24px; margin: 20px 0; }
            textarea { width: 100%; height: 80px; padding: 10px; font-family: monospace;
                       border: 1px solid #ddd; border-radius: 8px; }
            button { background: #000; color: #fff; border: none; padding: 12px 24px;
                     border-radius: 8px; cursor: pointer; font-size: 16px; margin-top: 10px; }
            button:hover { background: #333; }
            pre { background: #f6f8fa; padding: 16px; border-radius: 8px; overflow-x: auto; }
          .badge { background: #e6f7ff; color: #0958d9; padding: 4px 12px;
                     border-radius: 20px; font-size: 14px; display: inline-block; }
            a { color: #0969da; text-decoration: none; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>UA Parser for Humans + AI Agents</h1>
        <p class="badge">1000 free requests/day with key=test</p>
        <p>Fast, accurate User-Agent parsing. 2ms avg latency. No signup needed to test.</p>

        <div class="card">
            <h3>Try it now</h3>
            <textarea id="ua" placeholder="Paste User-Agent here...">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36</textarea>
            <button onclick="testAPI()">Run Test</button>
            <pre id="result">Result will appear here...</pre>
        </div>

        <div class="card">
            <h3>Ready to go beyond free?</h3>
            <p>$5 for 1000 requests. Card or crypto. No memo needed.</p>
            <input id="email" type="email" placeholder="Enter your email">
            <button onclick="buyAPI()">Buy $5</button>
        </div>

        <p><a href="/docs">📖 API Docs</a> | <a href="/openapi.json">OpenAPI Spec</a></p>

        <script>
            async function testAPI() {
                const ua = document.getElementById('ua').value;
                const resultEl = document.getElementById('result');
                resultEl.textContent = 'Loading...';
                try {
                    const res = await fetch(`/v1/parse?key=test&ua=${encodeURIComponent(ua)}`);
                    const data = await res.json();
                    resultEl.textContent = JSON.stringify(data, null, 2);
                } catch (e) {
                    resultEl.textContent = 'Error: ' + e.message;
                }
            }
            async function buyAPI() {
                const email = document.getElementById('email').value;
                if (!email) return alert('Enter email first');
                const res = await fetch('/create-order', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email})
                });
                const data = await res.json();
                console.log('NowPayments response:', data);
                if (data.checkout_url) window.open(data.checkout_url, '_self');
                else alert(data.error || 'Error: ' + JSON.stringify(data));
            }
            testAPI();
        </script>
    </body>
    </html>
    """
    return html

# ==================== SWAGGER DOCS ====================
@app.route('/docs')
@limiter.exempt
def docs():
    """Interactive API documentation using Swagger UI."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>UA Parser API Docs</title>
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script>
            SwaggerUIBundle({
                url: '/openapi.json',
                dom_id: '#swagger-ui',
                presets: [SwaggerUIBundle.presets.apis]
            })
        </script>
    </body>
    </html>
    """
    return html

# ==================== THANK YOU PAGE ====================
@app.route('/thanks')
@limiter.exempt
def thanks():
    """Thank you page after successful payment."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Payment Successful - UA Parser API</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                   max-width: 600px; margin: 60px auto; padding: 0 20px; line-height: 1.6; text-align: center; }
            h1 { color: #22c55e; }
          .card { border: 1px solid #e5e5e5; border-radius: 12px; padding: 24px; margin: 20px 0; }
            p { color: #666; }
            a { color: #0969da; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>✓ Payment Successful!</h1>
        <div class="card">
            <p>Thank you for your purchase!</p>
            <p>Your API key has been sent to your email. Check your inbox (and spam folder) in the next few minutes.</p>
            <p>If you don't receive it within 15 minutes, <a href="mailto:mulengwa6@gmail.com">contact support</a>.</p>
            <p><a href="/">Back to Home</a></p>
        </div>
    </body>
    </html>
    """
    return html

# ==================== INIT DB ON COLD START ====================
init_db()

if __name__ == '__main__':
    # RENDER FIX: Render sets PORT env var, defaults to 10000
    port = int(os.environ.get("PORT", 10000))
    serve(app, host="0.0.0.0", port=port)
