from flask import Flask, request, jsonify, send_from_directory
from user_agents import parse
from waitress import serve
import os, hashlib, hmac, json, uuid, time
from datetime import datetime
import psycopg
from psycopg.rows import dict_row
import requests
import secrets

# Initialize Flask app
app = Flask(__name__)

# ==================== ENVIRONMENT VARIABLES ====================
# Secret used for admin operations
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me")
# PostgreSQL connection string from Render/Neon/Supabase
DATABASE_URL = os.environ.get("DATABASE_URL")
# Resend API key for sending emails
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")

# ==================== BINANCE USDT CONFIG ====================
# TronGrid API key for checking TRC20 transactions
TRONGRID_API_KEY = os.environ.get("TRONGRID_API_KEY") # Get free key at trongrid.io
# Your Binance USDT TRC20 deposit address
USDT_TRC20_ADDRESS = os.environ.get("USDT_TRC20_ADDRESS")
# Price for 1000 credits in USD
USDT_PRICE_USD = float(os.environ.get("USDT_PRICE_USD", "5.00"))
# USDT TRC20 contract address on Tron network
TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t" # USDT TRC20 contract address

# Fail fast if required env vars are missing
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")
if not USDT_TRC20_ADDRESS:
    raise RuntimeError("USDT_TRC20_ADDRESS not set")

def init_db():
    """
    Initialize database tables on startup.
    Creates api_keys and orders tables if they don't exist.
    Orders table tracks Binance USDT payments.
    """
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            # Table for storing API keys and remaining credits
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key TEXT PRIMARY KEY,
                    credits INT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            # Table for tracking payment orders
            cur.execute("""
                CREATE TABLE IF NOT EXISTS orders (
                    order_id TEXT PRIMARY KEY,
                    api_key TEXT,
                    email TEXT,
                    provider TEXT DEFAULT 'binance_usdt',
                    amount NUMERIC,
                    status TEXT DEFAULT 'pending',
                    tx_hash TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        conn.commit()
    print("DB initialized: api_keys and orders tables ready")

def get_credits(api_key):
    """
    Get remaining credits for a given API key.
    Returns 0 if key doesn't exist.
    """
    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT credits FROM api_keys WHERE key = %s", (api_key,))
            row = cur.fetchone()
            return row['credits'] if row else 0

def deduct_credit(api_key):
    """
    Deduct 1 credit from the API key if credits > 0.
    Returns remaining credits or None if no credits left.
    """
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
    """
    Create a new API key or add credits to existing key.
    Used for both free tier setup and paid fulfillment.
    """
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
    """
    Send the API key to customer email using Resend.
    """
    if not RESEND_API_KEY:
        print("ERROR: RESEND_API_KEY not set - email not sent")
        return

    payload = {
        "from": "UA Parser API <onboarding@resend.dev>",
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

@app.after_request
def add_headers(response):
    """
    Add CORS and custom headers to all responses.
    X-API-Latency is for marketing/social proof.
    """
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-API-Latency'] = '2ms'
    return response

@app.route('/health')
def health():
    """
    Health check endpoint for Render and monitoring tools.
    """
    return jsonify({"status": "ok", "latency": "2ms", "timestamp": str(datetime.utcnow())}), 200

@app.route('/v1/parse')
def parse_ua():
    """
    Main API endpoint: Parse a User-Agent string.
    Requires key and ua parameters.
    Free tier uses key=test with 1000 requests/day.
    """
    key = request.args.get('key', '')
    ua_string = request.args.get('ua', '')

    # Check if key exists and has credits
    credits = get_credits(key)
    if not key or credits <= 0:
        return jsonify({
            "error": "No credits",
            "price": f"${USDT_PRICE_USD} = 1000 parses",
            "buy": "/create-order",
            "free_tier": "1000/day with key=test",
            "docs": "/docs"
        }), 402

    # Validate ua parameter
    if not ua_string:
        return jsonify({"error": "Missing?ua=Mozilla/5.0..."}), 400

    # Deduct 1 credit
    new_credits = deduct_credit(key)
    if new_credits is None:
        return jsonify({"error": "No credits left"}), 402

    # Parse the User-Agent
    u = parse(ua_string)
    ua_lower = ua_string.lower()
    ai_bots = ['gptbot','chatgpt-user','claudebot','anthropic','google-extended','perplexitybot','bytespider']
    is_ai_bot = any(b in ua_lower for b in ai_bots)

    # Return parsed data
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

# ==================== BINANCE USDT PAYMENT ROUTES ====================
@app.route('/create-order', methods=['POST', 'GET'])
def create_order():
    """
    Create a new USDT payment order.
    GET returns instructions. POST with email creates order and returns payment details.
    """
    if request.method == 'GET':
        return jsonify({"message": "POST JSON with {\"email\":\"you@example.com\"} to create order"})

    data = request.get_json() or {}
    email = data.get('email')
    if not email:
        return jsonify({"error": "Missing email"}), 400

    # Generate unique order ID and API key
    order_id = f"order_{uuid.uuid4().hex[:8]}"
    api_key = "sk_live_" + secrets.token_urlsafe(16)

    # Create key with 0 credits and pending order
    create_or_update_key(api_key, 0)
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO orders (order_id, api_key, email, amount, status)
                VALUES (%s, %s, %s, %s, 'pending')
            """, (order_id, api_key, email, USDT_PRICE_USD))
        conn.commit()

    return jsonify({
        "order_id": order_id,
        "address": USDT_TRC20_ADDRESS,
        "network": "TRC20",
        "amount": USDT_PRICE_USD,
        "memo": order_id,
        "instructions": f"Send exactly {USDT_PRICE_USD} USDT TRC20 to the address above. Include memo: {order_id}. Payment confirms in ~30s."
    }), 200

@app.route('/check-payment/<order_id>')
def check_payment(order_id):
    """
    Check if payment for order_id has been received and confirmed on Tron blockchain.
    Frontend polls this every 5s after showing payment instructions.
    """
    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
            order = cur.fetchone()

    if not order:
        return jsonify({"error": "Order not found"}), 404

    # If already paid, return key immediately
    if order['status'] == 'paid':
        return jsonify({"status": "paid", "api_key": order['api_key']})

    # Query TronGrid for TRC20 transactions to your address
    url = f"https://api.trongrid.io/v1/accounts/{USDT_TRC20_ADDRESS}/transactions/trc20"
    headers = {"TRON-PRO-API-KEY": TRONGRID_API_KEY} if TRONGRID_API_KEY else {}
    params = {
        "limit": 50,
        "contract_address": TRC20_CONTRACT,
        "only_confirmed": "true"
    }

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        txs = r.json().get("data", [])
    except Exception as e:
        print(f"TronGrid error: {e}")
        return jsonify({"status": "pending", "error": "chain_check_failed"}), 200

    # Check each transaction for matching amount and memo
    for tx in txs:
        amount_received = float(tx.get('value', 0)) / 1e6 # USDT has 6 decimals
        memo = tx.get('data', '')

        if (tx.get('to') == USDT_TRC20_ADDRESS and
            abs(amount_received - float(order['amount'])) < 0.001 and
            memo == order_id and
            tx.get('confirmed') == True):

            # Payment confirmed - mark as paid
            with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE orders SET status = 'paid', tx_hash = %s WHERE order_id = %s",
                                (tx['transaction_id'], order_id))
                conn.commit()

            # Fulfill order: add 1000 credits and send email
            create_or_update_key(order['api_key'], 1000)
            send_api_key_email(order['email'], order['api_key'])
            print(f"FULFILLED ORDER {order_id} - TX: {tx['transaction_id']}")

            return jsonify({"status": "paid", "api_key": order['api_key'], "tx_hash": tx['transaction_id']})

    return jsonify({"status": "pending"}), 200

@app.route('/openapi.json')
def openapi():
    """
    Serve OpenAPI spec file for Swagger UI and AI agents.
    """
    return send_from_directory('.', 'openapi.json')

@app.route('/llms.txt')
def llms_txt():
    """
    Serve llms.txt for AI crawlers and documentation tools.
    """
    return send_from_directory('.', 'llms.txt')

# ==================== LANDING PAGE ====================
@app.route('/')
def home():
    """
    Landing page with interactive API tester.
    Lets users try the API without reading docs.
    """
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
            <p>$5 for 10,000 requests. Pay with USDT TRC20.</p>
            <a href="/create-order"><button>Get API Key</button></a>
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
            testAPI();
        </script>
    </body>
    </html>
    """
    return html

# ==================== SWAGGER DOCS ====================
@app.route('/docs')
def docs():
    """
    Interactive API documentation using Swagger UI.
    Loads openapi.json and provides a UI to test endpoints.
    """
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

if __name__ == '__main__':
    # Initialize database and start server
    init_db()
    port = int(os.environ.get("PORT", 10000))
    serve(app, host="0.0.0.0", port=port)
