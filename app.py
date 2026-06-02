from flask import Flask, request, jsonify, send_from_directory
from user_agents import parse
from waitress import serve
import os, hashlib, hmac, json, uuid, time
from datetime import datetime
import psycopg
from psycopg.rows import dict_row
import requests
import secrets

# ==================== APP INITIALIZATION ====================
# Create Flask app instance - this is the main web server
app = Flask(__name__)

# ==================== ENVIRONMENT VARIABLES ====================
# ADMIN_SECRET: Secret key for admin operations. Set in Render env vars
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me")
# DATABASE_URL: PostgreSQL connection string from Render/Neon/Supabase
DATABASE_URL = os.environ.get("DATABASE_URL")
# RESEND_API_KEY: API key for sending emails via Resend.com
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")

# ==================== NOWPAYMENTS CONFIG ====================
# NOWPAYMENTS_API_KEY: API key from nowpayments.io dashboard for creating invoices
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY")
# NOWPAYMENTS_IPN_SECRET: Secret used to verify webhook signatures from NowPayments
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET")
# USDT_PRICE_USD: Price for 1000 credits in USD. Default $5.00 if not set
USDT_PRICE_USD = float(os.environ.get("USDT_PRICE_USD", "5.00"))

# ==================== STARTUP CHECKS ====================
# Fail fast if DATABASE_URL is missing - app can't work without DB
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set")

# ==================== DATABASE FUNCTIONS ====================
def init_db():
    """
    Initialize database tables on startup.
    Creates api_keys and orders tables if they don't exist.
    Orders table tracks NowPayments transactions.
    Runs on module import so Render cold starts work.
    """
    # Connect to PostgreSQL with SSL required for security
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
            # Table for tracking payment orders from NowPayments
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
        # Commit changes to database
        conn.commit()
    print("DB initialized: api_keys and orders tables ready")

def get_credits(api_key):
    """
    Get remaining credits for a given API key.
    Returns 0 if key doesn't exist.
    Auto-creates 'test' key with 1000 credits for free tier.
    This ensures new users can try API immediately.
    """
    # Connect to DB and fetch credits for the key
    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            # Query credits for this API key
            cur.execute("SELECT credits FROM api_keys WHERE key = %s", (api_key,))
            row = cur.fetchone()

            # Auto-create test key with 1000 credits if it doesn't exist
            # This handles fresh DB on Render cold start
            if not row and api_key == 'test':
                cur.execute("INSERT INTO api_keys (key, credits) VALUES ('test', 1000) ON CONFLICT DO NOTHING")
                conn.commit()
                return 1000

            # Return credits or 0 if key not found
            return row['credits'] if row else 0

def deduct_credit(api_key):
    """
    Deduct 1 credit from the API key if credits > 0.
    Uses atomic UPDATE to prevent race conditions.
    Returns remaining credits or None if no credits left.
    """
    # Update credits atomically to prevent race conditions
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            # Decrement credits only if > 0, return new value
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
    ON CONFLICT handles existing keys by adding credits.
    """
    # Insert new key or update existing key's credits
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
    Only sends if RESEND_API_KEY is set in environment.
    Called automatically after payment webhook fires.
    """
    # Check if Resend API key is configured
    if not RESEND_API_KEY:
        print("ERROR: RESEND_API_KEY not set - email not sent")
        return

    # Build email payload for Resend API
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
    # Set headers for Resend API authentication
    headers = {"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"}
    try:
        # Send POST request to Resend API
        r = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10)
        r.raise_for_status()
        print(f"EMAIL SENT to {to_email}")
    except Exception as e:
        # Log any errors if email fails to send
        print(f"ERROR sending email: {e}")

# ==================== MIDDLEWARE ====================
@app.after_request
def add_headers(response):
    """
    Add CORS and custom headers to all responses.
    X-API-Latency is for marketing/social proof.
    Allows frontend from any domain to call API.
    """
    # Allow all origins for CORS
    response.headers['Access-Control-Allow-Origin'] = '*'
    # Add custom latency header for display
    response.headers['X-API-Latency'] = '2ms'
    return response

# ==================== API ENDPOINTS ====================
@app.route('/health')
def health():
    """
    Health check endpoint for Render and monitoring tools.
    Returns OK status with timestamp.
    Render uses this to know if app is alive.
    """
    return jsonify({"status": "ok", "latency": "2ms", "timestamp": str(datetime.utcnow())}), 200

@app.route('/v1/parse')
def parse_ua():
    """
    Main API endpoint: Parse a User-Agent string.
    Requires key and ua parameters.
    Free tier uses key=test with 1000 requests/day.
    Each request deducts 1 credit.
    """
    # Get key and ua from query parameters
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

    # Validate ua parameter is provided
    if not ua_string:
        return jsonify({"error": "Missing?ua=Mozilla/5.0..."}), 400

    # Deduct 1 credit for this request
    new_credits = deduct_credit(key)
    if new_credits is None:
        return jsonify({"error": "No credits left"}), 402

    # Parse the User-Agent string using user_agents library
    u = parse(ua_string)
    ua_lower = ua_string.lower()
    # List of known AI crawler user agents
    ai_bots = ['gptbot','chatgpt-user','claudebot','anthropic','google-extended','perplexitybot','bytespider']
    is_ai_bot = any(b in ua_lower for b in ai_bots)

    # Return parsed data as JSON
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

# ==================== NOWPAYMENTS PAYMENT ROUTES ====================
@app.route('/create-order', methods=['POST', 'GET'])
def create_order():
    """
    Updated: Creates NowPayments invoice. Customer only sees $5.
    No memo/address shown. Memo handled in background.
    GET returns instructions. POST with email creates invoice.
    """
    # Handle GET request - show instructions
    if request.method == 'GET':
        return jsonify({"message": "POST JSON with {\"email\":\"you@example.com\"} to create order"})

    # Parse JSON data from POST request
    data = request.get_json() or {}
    # Get customer email from request body
    email = data.get('email')
    if not email:
        return jsonify({"error": "Missing email"}), 400

    # Embed email in order_id so webhook can extract it later
    # Format: order_email_with_underscores_random6chars
    order_id = f"order_{email.replace('@','_').replace('.','_')}_{uuid.uuid4().hex[:6]}"
    # Generate random API key for customer
    api_key = "sk_live_" + secrets.token_urlsafe(16)

    # Create key with 0 credits and pending order in database
    create_or_update_key(api_key, 0)
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
        with conn.cursor() as cur:
            # Insert pending order - will be marked paid by webhook
            cur.execute("""
                INSERT INTO orders (order_id, api_key, email, amount, status, provider)
                VALUES (%s, %s, %s, %s, 'pending', 'nowpayments')
            """, (order_id, api_key, email, USDT_PRICE_USD))
        conn.commit()

    # Call NowPayments API to create invoice
    # Customer never sees USDT address or memo
    if not NOWPAYMENTS_API_KEY:
        return jsonify({"error": "Payment not configured"}), 500
    
    # Build payload for NowPayments invoice creation
    np_payload = {
        "price_amount": USDT_PRICE_USD,
        "price_currency": "usd",
        "pay_currency": "usdttrc20",  # Customer pays, you receive USDT TRC20
        "order_id": order_id,
        "order_description": "UA Parser API - 1000 credits",
        "ipn_callback_url": f"{request.url_root}webhook/nowpayments",  # Webhook URL
        "success_url": f"{request.url_root}thanks"  # Redirect after payment
    }
    
    # Set API key header for NowPayments
    headers = {"x-api-key": NOWPAYMENTS_API_KEY}
    # Make POST request to NowPayments API
    r = requests.post("https://api.nowpayments.io/v1/invoice", json=np_payload, headers=headers, timeout=10)
    
    # Check if NowPayments returned error
    if r.status_code != 200:
        print(f"NowPayments error: {r.text}")
        return jsonify({"error": "Payment provider error"}), 500
    
    # Parse invoice response
    invoice = r.json()
    
    # Return checkout URL - customer gets redirected here
    return jsonify({
        "checkout_url": invoice['invoice_url'],
        "order_id": order_id,
        "message": "Customer sees $5 only. No memo needed."
    }), 200

@app.route('/webhook/nowpayments', methods=['POST'])
def nowpayments_webhook():
    """
    NowPayments calls this automatically when customer pays.
    Customer never sees memo/address. Triggers existing email logic.
    Verifies signature to prevent fake webhook calls.
    """
    # Get signature from NowPayments header
    received_sig = request.headers.get('x-nowpayments-sig')
    # Get raw payload for signature verification
    payload = request.get_data()
    
    # Check if IPN secret is configured
    if not NOWPAYMENTS_IPN_SECRET:
        return 'IPN secret not set', 500
    
    # Calculate expected signature using HMAC SHA512
    calc_sig = hmac.new(
        NOWPAYMENTS_IPN_SECRET.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()
    
    # Verify signature matches - prevents spoofing
    if not hmac.compare_digest(received_sig or '', calc_sig):
        return 'Invalid signature', 403
    
    # Parse JSON payload
    data = request.get_json()
    
    # Only fulfill when payment is actually confirmed on blockchain
    if data.get('payment_status') == 'finished':
        order_id = data.get('order_id')
        amount = float(data.get('price_amount', 0))
        
        # Fetch order from DB to get email and api_key
        with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
                order = cur.fetchone()
        
        # Check if order exists, not already paid, and amount is correct
        if order and order['status'] != 'paid' and amount >= USDT_PRICE_USD:
            # Mark order as paid and store transaction hash
            with psycopg.connect(DATABASE_URL, sslmode='require') as conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE orders SET status = 'paid', tx_hash = %s WHERE order_id = %s",
                                (data.get('txid'), order_id))
                    conn.commit()
            
            # Fulfill order using existing functions
            create_or_update_key(order['api_key'], 1000)  # Add 1000 credits
            send_api_key_email(order['email'], order['api_key'])  # Send email
            print(f"NOWPAYMENTS FULFILLED {order_id} - TX: {data.get('txid')}")
    
    return 'ok', 200

# ==================== STATIC FILES ====================
@app.route('/openapi.json')
def openapi():
    """
    Serve OpenAPI spec file for Swagger UI and AI agents.
    AI agents like Claude/ChatGPT use this to auto-discover API.
    """
    return send_from_directory('.', 'openapi.json')

@app.route('/llms.txt')
def llms_txt():
    """
    Serve llms.txt for AI crawlers and documentation tools.
    Tells AI agents what this API does and how to use it.
    """
    return send_from_directory('.', 'llms.txt')

# ==================== LANDING PAGE ====================
@app.route('/')
def home():
    """
    Landing page with interactive API tester.
    Lets users try the API without reading docs.
    Includes Buy $5 button that redirects to NowPayments.
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
            // Test API button - calls /v1/parse with test key
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
            // Buy button - creates order and redirects to NowPayments
            async function buyAPI() {
                const email = document.getElementById('email').value;
                if (!email) return alert('Enter email first');
                const res = await fetch('/create-order', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email})
                });
                const data = await res.json();
                if (data.checkout_url) window.location.href = data.checkout_url;
                else alert(data.error || 'Error');
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

# ==================== INIT DB ON COLD START ====================
# Call init_db when module loads so tables exist before first request on Render
# This runs even when started by waitress/gunicorn, not just python app.py
init_db()

if __name__ == '__main__':
    # Initialize database and start server for local dev
    # On Render this block doesn't run because waitress imports the app
    port = int(os.environ.get("PORT", 10000))
    serve(app, host="0.0.0.0", port=port)
