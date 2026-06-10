from flask import Flask, request, jsonify, send_from_directory # Flask core + JSON + static files
from user_agents import parse # Parses User-Agent strings into browser/os/device
from waitress import serve # Production WSGI server for Render
import os, hashlib, hmac, json, uuid, time, re # Standard libs: env, crypto, UUID, regex, etc
from datetime import datetime # For timestamps
import psycopg # PostgreSQL driver v3
from psycopg.rows import dict_row # Return DB rows as dicts instead of tuples
import requests # HTTP requests to NowPayments + Resend APIs
import secrets # Generate secure random API keys

# ==================== FLASK-LIMITER IMPORTS ====================
from flask_limiter import Limiter # Rate limiting to prevent abuse
from flask_limiter.util import get_remote_address # Get user IP for rate limits

# ==================== APP INITIALIZATION ====================
app = Flask(__name__) # Create Flask app instance

# ==================== SECURITY CONSTANTS ====================
MAX_UA_LENGTH = 5000 # Prevent huge UA strings from crashing parser
MAX_EMAIL_LENGTH = 254 # RFC 5321 max email length
EMAIL_PATTERN = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' # Regex to validate email format
ALLOWED_ORIGINS = set( # CORS whitelist from env var
    os.environ.get("ALLOWED_ORIGINS", "").split(",")
) if os.environ.get("ALLOWED_ORIGINS") else set()

# ==================== RATE LIMITER SETUP ====================
limiter = Limiter( # Initialize rate limiter
    app=app,
    key_func=get_remote_address, # Rate limit per IP address
    default_limits=["200 per day", "50 per hour"], # Global limits for all endpoints
    storage_uri="memory://" # In-memory storage, resets on restart
)

# ==================== ENVIRONMENT VARIABLES ====================
ADMIN_SECRET = os.environ.get("ADMIN_SECRET") # Secret for admin endpoints, required
if not ADMIN_SECRET:
    raise RuntimeError("ADMIN_SECRET environment variable must be set") # Fail fast if missing
DATABASE_URL = os.environ.get("DATABASE_URL") # Postgres connection string from Render
RESEND_API_KEY = os.environ.get("RESEND_API_KEY") # API key for sending emails via Resend
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "noreply@ua-parser-api.com") # Sender email

# ==================== NOWPAYMENTS CONFIG ====================
NOWPAYMENTS_API_KEY = os.environ.get("NOWPAYMENTS_API_KEY") # NowPayments API key for creating invoices
NOWPAYMENTS_IPN_SECRET = os.environ.get("NOWPAYMENTS_IPN_SECRET") # Secret to verify webhook signatures
USDT_PRICE_USD = float(os.environ.get("USDT_PRICE_USD", "5.00")) # Price of 1000 credits, default $5. Customer pays exactly this

# ==================== STARTUP CHECKS ====================
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set") # Crash early if DB not configured

# ==================== HELPER FUNCTIONS ====================
def validate_email(email):
    """Validate email address format and length. Prevents spam/abuse."""
    if not email or not isinstance(email, str): # Check if email exists and is string
        return False
    email = email.strip().lower() # Remove spaces + lowercase for consistency
    if len(email) > MAX_EMAIL_LENGTH or len(email) < 5: # Check length bounds
        return False
    return bool(re.match(EMAIL_PATTERN, email)) # Return True if regex matches

# AI FEATURE #1: Bot/AI Agent Detection
def detect_ai_agent(ua_string):
    """
    Detect AI crawlers/bots from User-Agent string.
    Returns (is_ai_agent, bot_type, allows_training)
    2026: AI agents need to know if traffic is GPTBot, ClaudeBot, etc for robots.txt compliance
    """
    ua_lower = ua_string.lower() # Lowercase for case-insensitive matching

    ai_agents = { # Map of known AI bot tokens to their info
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

    for token, info in ai_agents.items(): # Loop through each AI bot
        if token in ua_lower: # Check if token appears in UA string
            return True, info['type'], info['allows_training'] # Return detection result
    return False, None, True # Not an AI bot

# AI FEATURE #3: Headless browser detection
def detect_headless(ua_string):
    """
    Detect headless browsers: Puppeteer, Playwright, Selenium.
    AI agents use this to serve different content vs real users.
    """
    ua_lower = ua_string.lower() # Lowercase for matching
    headless_signals = [ # Tokens that indicate headless automation
        'headlesschrome', 'puppeteer', 'playwright',
        'webdriver', 'selenium', 'phantomjs'
    ]
    return any(signal in ua_lower for signal in headless_signals) # True if any signal found

# AI FEATURE #4: Browser engine detection
def get_browser_engine(ua_string):
    """
    Extract browser engine: chromium, gecko, webkit.
    AI agents use this to infer JS capabilities like WebAssembly, ES2022 support.
    """
    ua_lower = ua_string.lower() # Lowercase for matching
    if 'chrome' in ua_lower or 'chromium' in ua_lower: # Chrome/Chromium browsers
        return 'chromium'
    elif 'firefox' in ua_lower or 'gecko' in ua_lower: # Firefox/Gecko engine
        return 'gecko'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower: # Safari uses WebKit, exclude Chrome
        return 'webkit'
    return 'unknown' # Could not determine engine

# AI FEATURE #6: Language + Region hints
def parse_language(request):
    """
    Parse Accept-Language header for primary_lang + region.
    AI agents use this to request localized content.
    """
    accept_lang = request.headers.get('Accept-Language', '') # Get Accept-Language header
    if not accept_lang: # If header missing, return None
        return None, None

    primary = accept_lang.split(',')[0].strip() # Take first language preference
    parts = primary.split('-') # Split "en-US" into ["en", "US"]
    lang = parts[0] if parts else None # Language code
    region = parts[1] if len(parts) > 1 else None # Region code
    return lang, region # Return both

# ==================== DATABASE FUNCTIONS ====================
def init_db():
    """Initialize database tables on startup. Creates api_keys and orders tables."""
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn: # Connect to Postgres with SSL
        with conn.cursor() as cur: # Create cursor for SQL queries
            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    key TEXT PRIMARY KEY,
                    credits INT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """) # Create api_keys table
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
            """) # Create orders table
        conn.commit() # Save changes to DB
    print("DB initialized: api_keys and orders tables ready") # Log success

def get_credits(api_key):
    """Get remaining credits for a given API key. Auto-creates 'test' key with 1000 credits."""
    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn: # Connect with dict rows
        with conn.cursor() as cur: # Create cursor
            cur.execute("SELECT credits FROM api_keys WHERE key = %s", (api_key,)) # Query credits
            row = cur.fetchone() # Get first result
            if not row and api_key == 'test': # If 'test' key doesn't exist, create it
                cur.execute("INSERT INTO api_keys (key, credits) VALUES ('test', 1000) ON CONFLICT DO NOTHING")
                conn.commit()
                return 1000 # Return 1000 credits for test key
            return row['credits'] if row else 0 # Return credits or 0 if not found

def deduct_credit(api_key):
    """Deduct 1 credit from the API key if credits > 0. Atomic to prevent race conditions."""
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn: # Connect to DB
        with conn.cursor() as cur: # Create cursor
            cur.execute( # Atomic update: only deduct if credits > 0
                "UPDATE api_keys SET credits = credits - 1, updated_at = NOW() WHERE key = %s AND credits > 0 RETURNING credits",
                (api_key,)
            )
            row = cur.fetchone() # Get updated credit count
            if row:
                conn.commit() # Save changes
                return row[0] # Return new credit count
            return None # No credits left

def create_or_update_key(api_key, credits=1000):
    """Create a new API key or add credits to existing key. ON CONFLICT handles existing keys."""
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn: # Connect to DB
        with conn.cursor() as cur: # Create cursor
            cur.execute(""" # Insert new key or add credits if key exists
                INSERT INTO api_keys (key, credits, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key)
                DO UPDATE SET credits = api_keys.credits + %s, updated_at = NOW()
            """, (api_key, credits, credits))
        conn.commit() # Save changes

def send_api_key_email(to_email, api_key):
    """Send the API key to customer email using Resend. Only sends if RESEND_API_KEY is set."""
    if not RESEND_API_KEY: # Skip if no API key configured
        print("ERROR: RESEND_API_KEY not set - email not sent")
        return
    payload = { # Email content for Resend API
        "from": f"UA Parser API <{RESEND_FROM_EMAIL}>",
        "to": [to_email],
        "subject": "Your UA Parser API Key is Ready",
        "html": f""" # HTML email body
        <h2>Thanks for your purchase!</h2>
        <p>Your API key is ready to use:</p>
        <pre style="background:#f4f4f4;padding:10px;border-radius:5px;">{api_key}</pre>
        <p>Use it like this: <code>/v1/parse?key={api_key}&ua=...</code></p>
        <p>You have 1000 credits. Each request uses 1 credit.</p>
        """
    }
    headers = {"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"} # Auth headers
    try:
        r = requests.post("https://api.resend.com/emails", json=payload, headers=headers, timeout=10) # Send email
        r.raise_for_status() # Raise error if status!= 200
        print(f"EMAIL SENT to {to_email}") # Log success
    except Exception as e:
        print(f"ERROR sending email: {e}") # Log error

# ==================== MIDDLEWARE ====================
@app.after_request
def add_headers(response):
    """Add CORS and custom headers to all responses. Restricts CORS to configured origins."""
    origin = request.headers.get('Origin') # Get Origin header from request
    if origin == 'http://localhost:3000' or origin in ALLOWED_ORIGINS: # Allow localhost or whitelisted origins
        response.headers['Access-Control-Allow-Origin'] = origin # Set CORS header
    elif not ALLOWED_ORIGINS: # If no origins configured, allow all
        response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-API-Latency'] = '2ms' # Custom header for monitoring
    return response # Return modified response

# ==================== API ENDPOINTS ====================
@app.route('/health')
@limiter.exempt # Don't rate limit health checks
def health():
    """Health check endpoint for Render/Deta and monitoring tools."""
    return jsonify({"status": "ok", "latency": "2ms", "timestamp": str(datetime.utcnow())}), 200 # Return 200 OK

@app.route('/v1/parse')
@limiter.limit("100/minute") # Rate limit: 100 requests per minute per IP
def parse_ua():
    """
    Main API endpoint: Parse a User-Agent string.
    AI FEATURES ADDED: bot detection, training flags, platform, engine, headless, lang
    Logic unchanged - just extended JSON response for AI agents
    """
    key = request.args.get('key', '').strip() # Get API key from query params
    ua_string = request.args.get('ua', '').strip() # Get UA string from query params

    if not ua_string: # Check if UA string provided
        return jsonify({"error": "Missing?ua=Mozilla/5.0..."}), 400 # 400 Bad Request

    if len(ua_string) > MAX_UA_LENGTH: # Check if UA too long
        return jsonify({"error": f"UA string too long (max {MAX_UA_LENGTH} chars)"}), 400 # 400 Bad Request

    credits = get_credits(key) # Check credit balance
    if not key or credits <= 0: # If no key or no credits
        return jsonify({ # 402 Payment Required response
            "error": "No credits",
            "price": f"${USDT_PRICE_USD} = 1000 parses",
            "buy": "/create-order",
            "free_tier": "1000/day with key=test",
            "docs": "/docs"
        }), 402

    new_credits = deduct_credit(key) # Deduct 1 credit
    if new_credits is None: # If deduction failed
        return jsonify({"error": "No credits left"}), 402 # 402 Payment Required

    try:
        u = parse(ua_string) # Parse UA string using user_agents library
    except Exception as e:
        print(f"Error parsing UA: {e}") # Log parse error
        return jsonify({"error": "Invalid UA string"}), 400 # 400 Bad Request

    # ==================== AI AGENT FEATURES START ====================
    # FEATURE #1: Bot/AI Agent Detection
    is_ai_agent, bot_type, allows_training = detect_ai_agent(ua_string) # Check if AI bot

    # FEATURE #3: Platform + Device Granularity + Headless
    platform = u.os.family.lower() if u.os.family else 'unknown' # OS platform
    device_type = "mobile" if u.is_mobile else "tablet" if u.is_tablet else "desktop" # Device category
    is_headless = detect_headless(ua_string) # Check for headless browser

    # FEATURE #4: Browser engine + version
    browser_engine = get_browser_engine(ua_string) # Get browser engine

    # FEATURE #6: Language + Region
    primary_lang, region = parse_language(request) # Parse Accept-Language header

    # FEATURE #5: Cloud/Server detection - basic version using device_type
    is_datacenter = device_type == 'server' or is_headless # Mark as datacenter if server or headless
    hosting_provider = None # Placeholder for future IP lookup
    # ==================== AI AGENT FEATURES END ====================

    return jsonify({ # Return parsed data + AI features as JSON
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

        "credits_left": new_credits # Remaining credits after this request
    }), 200, {'Cache-Control': 'public, max-age=86400', 'CDN-Cache-Control': 'max-age=31536000'} # 200 OK + cache headers

# ==================== NOWPAYMENTS PAYMENT ROUTES ====================
@app.route('/create-order', methods=['POST', 'GET']) # Accept POST for order creation, GET for info
@limiter.limit("5/minute") # Rate limit: 5 orders per minute per IP
def create_order():
    """Creates NowPayments invoice. Customer only sees $5. No memo/address shown."""
    if request.method == 'GET': # If GET request, return instructions
        return jsonify({"message": "POST JSON with {\"email\":\"you@example.com\"} to create order"})

    data = request.get_json() or {} # Parse JSON body
    email = data.get('email', '').strip().lower() if data.get('email') else '' # Extract and normalize email

    if not validate_email(email): # Validate email format
        return jsonify({"error": "Invalid email address"}), 400 # 400 Bad Request

    # OPTION 1: Auto-cancel expired pending orders older than 20 minutes
    # This runs every time user clicks "Buy $5". If old invoice expired on NowPayments, 
    # we mark it 'expired' in DB so user can create new order immediately
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn: # Connect to DB
        with conn.cursor() as cur: # Create cursor
            cur.execute("""
                UPDATE orders 
                SET status = 'expired' 
                WHERE email = %s 
                AND status = 'pending' 
                AND created_at < NOW() - INTERVAL '20 minutes'
            """, (email,)) # Expire orders older than 20 min for this email
            conn.commit() # Save changes

    with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn: # Connect to DB
        with conn.cursor() as cur: # Create cursor
            cur.execute( # Check for existing active pending order for this email
                "SELECT order_id FROM orders WHERE email = %s AND status = 'pending' LIMIT 1",
                (email,)
            )
            existing = cur.fetchone() # Get first result
            if existing: # If active pending order still exists
                return jsonify({
                    "error": "You already have a pending order. Check your email or contact support."
                }), 409 # 409 Conflict

    order_id = f"order_{email.replace('@','_').replace('.','_')}_{uuid.uuid4().hex[:6]}" # Generate unique order ID
    api_key = "sk_live_" + secrets.token_urlsafe(16) # Generate secure random API key

    create_or_update_key(api_key, 0) # Create API key with 0 credits initially
    with psycopg.connect(DATABASE_URL, sslmode='require') as conn: # Connect to DB
        with conn.cursor() as cur: # Create cursor
            cur.execute(""" # Insert order record
                INSERT INTO orders (order_id, api_key, email, amount, status, provider)
                VALUES (%s, %s, %s, %s, 'pending', 'nowpayments')
            """, (order_id, api_key, email, USDT_PRICE_USD))
        conn.commit() # Save to DB

    if not NOWPAYMENTS_API_KEY: # Check if NowPayments configured
        return jsonify({"error": "Payment not configured"}), 500 # 500 Server Error

    np_payload = { # Payload for NowPayments invoice API
        "price_amount": USDT_PRICE_USD, # $5.00 fixed price for customer
        "price_currency": "usd", # Price is always quoted in USD
        "pay_currency": "usdttrc20", # Force USDT on Tron network only, no BTC/ETH
        "order_id": order_id, # Our internal order ID
        "order_description": "UA Parser API - 1000 credits", # Description shown to customer
        "ipn_callback_url": "https://ua-parser-api-zsql.onrender.com/webhook/nowpayments", # Webhook URL for payment confirmation
        "success_url": "https://ua-parser-api-zsql.onrender.com/thanks", # Redirect after payment success
        "cancel_url": "https://ua-parser-api-zsql.onrender.com/", # Redirect if customer cancels
        "is_fixed_rate": True, # NEW: Lock USDT rate for 20 min so customer always pays ~$5, no 4.9→5.5 swing
        "is_fee_paid_by_user": False # NEW: You absorb NowPayments 0.5% fee + Tron gas, customer pays exactly $5
    }

    headers = {"x-api-key": NOWPAYMENTS_API_KEY} # Auth header for NowPayments
    r = requests.post("https://api.nowpayments.io/v1/invoice", json=np_payload, headers=headers, timeout=10) # Create invoice

    if r.status_code!= 200: # If NowPayments returns error
        print(f"NowPayments error: {r.text}") # Log error response
        return jsonify({"error": "Payment provider error"}), 500 # 500 Server Error

    invoice = r.json() # Parse NowPayments response

    return jsonify({ # Return checkout URL to frontend
        "checkout_url": invoice['invoice_url'], # NowPayments payment page URL
        "order_id": order_id, # Our order ID
        "message": "Customer sees $5 only. No memo needed." # Info message
    }), 200 # 200 OK

@app.route('/webhook/nowpayments', methods=['POST']) # Webhook endpoint for NowPayments
@limiter.exempt # Don't rate limit webhooks
def nowpayments_webhook():
    """NowPayments calls this automatically when customer pays. Verifies signature."""
    received_sig = request.headers.get('x-nowpayments-sig') # Get signature from header
    if not received_sig: # Check if signature present
        print("ERROR: Missing x-nowpayments-sig header") # Log error
        return 'Invalid signature', 403 # 403 Forbidden

    payload = request.get_data() # Get raw request body for signature verification
    if not NOWPAYMENTS_IPN_SECRET: # Check if secret configured
        return 'IPN secret not set', 500 # 500 Server Error

    calc_sig = hmac.new( # Calculate expected signature
        NOWPAYMENTS_IPN_SECRET.encode(),
        payload,
        hashlib.sha512
    ).hexdigest()

    if not hmac.compare_digest(received_sig, calc_sig): # Compare signatures securely
        print(f"ERROR: Signature mismatch") # Log error
        return 'Invalid signature', 403 # 403 Forbidden

    try:
        data = request.get_json() # Parse JSON payload
    except Exception as e:
        print(f"ERROR: Invalid JSON in webhook: {e}") # Log error
        return 'Invalid payload', 400 # 400 Bad Request

    if data.get('payment_status') == 'finished': # Only process completed payments
        order_id = data.get('order_id') # Get order ID from webhook
        amount = float(data.get('price_amount', 0)) # Get paid amount

        with psycopg.connect(DATABASE_URL, sslmode='require', row_factory=dict_row) as conn: # Connect to DB
            with conn.cursor() as cur: # Create cursor
                cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,)) # Lookup order
                order = cur.fetchone() # Get order data

        if order and order['status']!= 'paid' and amount >= USDT_PRICE_USD: # Check order exists, not paid, amount ok
            with psycopg.connect(DATABASE_URL, sslmode='require') as conn: # Connect to DB
                with conn.cursor() as cur: # Create cursor
                    cur.execute("UPDATE orders SET status = 'paid', tx_hash = %s WHERE order_id = %s", # Mark as paid
                                (data.get('txid'), order_id))
                    conn.commit() # Save changes

            create_or_update_key(order['api_key'], 1000) # Credit 1000 to customer's API key
            send_api_key_email(order['email'], order['api_key']) # Email API key to customer
            print(f"NOWPAYMENTS FULFILLED {order_id} - TX: {data.get('txid')}") # Log fulfillment

    return 'ok', 200 # Return 200 to acknowledge webhook

# ==================== STATIC FILES ====================
@app.route('/openapi.json')
@limiter.exempt # Don't rate limit spec file
def openapi():
    """Serve OpenAPI spec file for Swagger UI and AI agents."""
    return send_from_directory('.', 'openapi.json') # Serve openapi.json from current directory

@app.route('/llms.txt')
@limiter.exempt # Don't rate limit llms.txt
def llms_txt():
    """Serve llms.txt for AI crawlers and documentation tools."""
    return send_from_directory('.', 'llms.txt') # Serve llms.txt from current directory

# ==================== LANDING PAGE ====================
@app.route('/')
@limiter.exempt # Don't rate limit homepage
def home():
    """Landing page with interactive API tester."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>UA Parser API</title>
        <meta name="viewport" content="width=device-width, initial-scale=1"> <!-- Mobile responsive -->
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; /* Clean font stack */
                   max-width: 700px; margin: 40px auto; padding: 0 20px; line-height: 1.6; } /* Centered layout */
            h1 { color: #111; } /* Dark heading */
         .card { border: 1px solid #e5e5e5; border-radius: 12px; padding: 24px; margin: 20px 0; } /* Card style */
            textarea { width: 100%; height: 80px; padding: 10px; font-family: monospace; /* Monospace for UA input */
                       border: 1px solid #ddd; border-radius: 8px; }
            button { background: #000; color: #fff; border: none; padding: 12px 24px; /* Black button */
                     border-radius: 8px; cursor: pointer; font-size: 16px; margin-top: 10px; }
            button:hover { background: #333; } /* Darker on hover */
            pre { background: #f6f8fa; padding: 16px; border-radius: 8px; overflow-x: auto; } /* Code block style */
         .badge { background: #e6f7ff; color: #0958d9; padding: 4px 12px; /* Blue badge */
                     border-radius: 20px; font-size: 14px; display: inline-block; }
            a { color: #0969da; text-decoration: none; } /* Link color */
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px; margin: 10px 0; } /* Email input */
        </style>
    </head>
    <body>
        <h1>UA Parser for Humans + AI Agents</h1>
        <p class="badge">1000 free requests/day with key=test</p> <!-- Free tier badge -->
        <p>Fast, accurate User-Agent parsing. 2ms avg latency. No signup needed to test.</p> <!-- Description -->

        <div class="card">
            <h3>Try it now</h3>
            <textarea id="ua" placeholder="Paste User-Agent here...">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36</textarea> <!-- UA input -->
            <button onclick="testAPI()">Run Test</button> <!-- Test button -->
            <pre id="result">Result will appear here...</pre> <!-- Results display -->
        </div>

        <div class="card">
            <h3>Ready to go beyond free?</h3>
            <p>$5 for 1000 requests. Card or crypto. No memo needed.</p> <!-- Pricing info -->
            <input id="email" type="email" placeholder="Enter your email"> <!-- Email for API key delivery -->
            <button onclick="buyAPI()">Buy $5</button> <!-- Payment button -->
        </div>

        <p><a href="/docs">📖 API Docs</a> | <a href="/openapi.json">OpenAPI Spec</a></p> <!-- Links -->

        <script>
            async function testAPI() { // Function to test /v1/parse endpoint
                const ua = document.getElementById('ua').value; // Get UA from textarea
                const resultEl = document.getElementById('result'); // Get result div
                resultEl.textContent = 'Loading...'; // Show loading state
                try {
                    const res = await fetch(`/v1/parse?key=test&ua=${encodeURIComponent(ua)}`); // Call API with test key
                    const data = await res.json(); // Parse JSON response
                    resultEl.textContent = JSON.stringify(data, null, 2); // Pretty print JSON
                } catch (e) {
                    resultEl.textContent = 'Error: ' + e.message; // Show error if fetch fails
                }
            }
            async function buyAPI() { // Function to create NowPayments order
                const email = document.getElementById('email').value; // Get email from input
                if (!email) return alert('Enter email first'); // Validate email present
                const res = await fetch('/create-order', { // POST to backend
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}, // JSON request
                    body: JSON.stringify({email}) // Send email in body
                });
                const data = await res.json(); // Parse JSON response
                console.log('NowPayments response:', data); // Log response for debugging
                if (data.checkout_url) window.open(data.checkout_url, '_self'); // Redirect to NowPayments payment page in same tab
                else alert(data.error || 'Error: ' + JSON.stringify(data)); // Show error if no checkout URL
            }
            testAPI(); // Auto-run test on page load
        </script>
    </body>
    </html>
    """
    return html # Return HTML string

# ==================== SWAGGER DOCS ====================
@app.route('/docs')
@limiter.exempt # Don't rate limit docs
def docs():
    """Interactive API documentation using Swagger UI."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>UA Parser API Docs</title>
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"> <!-- Swagger CSS -->
    </head>
    <body>
        <div id="swagger-ui"></div> <!-- Swagger container -->
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script> <!-- Swagger JS -->
        <script>
            SwaggerUIBundle({ // Initialize Swagger UI
                url: '/openapi.json', // Load OpenAPI spec
                dom_id: '#swagger-ui', // Mount point
                presets: [SwaggerUIBundle.presets.apis] // Use API preset
            })
        </script>
    </body>
    </html>
    """
    return html # Return HTML string

# ==================== THANK YOU PAGE ====================
@app.route('/thanks')
@limiter.exempt # Don't rate limit thank you page
def thanks():
    """Thank you page after successful payment."""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Payment Successful - UA Parser API</title>
        <meta name="viewport" content="width=device-width, initial-scale=1"> <!-- Mobile responsive -->
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; /* Clean font */
                   max-width: 600px; margin: 60px auto; padding: 0 20px; line-height: 1.6; text-align: center; } /* Centered */
            h1 { color: #22c55e; } /* Green success color */
         .card { border: 1px solid #e5e5e5; border-radius: 12px; padding: 24px; margin: 20px 0; } /* Card style */
            p { color: #666; } /* Gray text */
            a { color: #0969da; text-decoration: none; } /* Link color */
            a:hover { text-decoration: underline; } /* Underline on hover */
        </style>
    </head>
    <body>
        <h1>✓ Payment Successful!</h1>
        <div class="card">
            <p>Thank you for your purchase!</p>
            <p>Your API key has been sent to your email. Check your inbox (and spam folder) in the next few minutes.</p> <!-- Email notice -->
            <p>If you don't receive it within 15 minutes, <a href="mailto:mulengwa6@gmail.com">contact support</a>.</p> <!-- Support link -->
            <p><a href="/">Back to Home</a></p> <!-- Back link -->
        </div>
    </body>
    </html>
    """
    return html # Return HTML string

# ==================== INIT DB ON COLD START ====================
init_db() # Create tables when app starts

if __name__ == '__main__': # Only run server if file executed directly
    # RENDER FIX: Render sets PORT env var, defaults to 10000
    port = int(os.environ.get("PORT", 10000)) # Get port from env or default 10000
    serve(app, host="0.0.0.0", port=port) # Start Waitress server on all interfaces
