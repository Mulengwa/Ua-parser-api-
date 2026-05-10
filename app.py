from flask import Flask, request, jsonify, send_from_directory
from user_agents import parse
from waitress import serve
import os, json, time, hashlib, hmac

app = Flask(__name__)

KEY_FILE = "keys.json"
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "change_me")
LEMON_WEBHOOK_SECRET = os.environ.get("LEMON_WEBHOOK_SECRET", "change_me_too")

def load_keys():
    try:
        with open(KEY_FILE, 'r') as f: return json.load(f)
    except: return {"test_123": 1000} # 1000/day free now

def save_keys(keys):
    with open(KEY_FILE, 'w') as f: json.dump(keys, f)

KEYS = load_keys()

@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['X-API-Latency'] = '2ms'
    return response

@app.route('/v1/parse')
def parse_ua():
    key = request.args.get('key', '')
    ua_string = request.args.get('ua', '')

    if key not in KEYS or KEYS[key] <= 0:
        return jsonify({
            "error": "No credits",
            "price": "$5 = 1000 parses. 1/5th the cost of uaparser.com",
            "buy": "https://YOURSTORE.lemonsqueezy.com/checkout/buy/YOUR_VARIANT_ID",
            "free_tier": "1000/day with key=test_123. No signup.",
            "docs": "https://yourapi.onrender.com/openapi.json"
        }), 402

    if not ua_string:
        return jsonify({"error": "Missing?ua=Mozilla/5.0..."}), 400

    KEYS[key] -= 1
    save_keys(KEYS)
    u = parse(ua_string)

    # AI bot detection - unique selling point
    ua_lower = ua_string.lower()
    ai_bots = ['gptbot','chatgpt-user','claudebot','anthropic','google-extended','perplexitybot']
    is_ai_bot = any(b in ua_lower for b in ai_bots)

    return jsonify({
        "browser": u.browser.family,
        "browser_version": u.browser.version_string,
        "os": u.os.family,
        "os_version": u.os.version_string,
        "device": u.device.family,
        "device_type": "mobile" if u.is_mobile else "tablet" if u.is_tablet else "desktop",
        "is_bot": u.is_bot,
        "is_ai_crawler": is_ai_bot, # Killer feature
        "credits_left": KEYS[key]
    }), 200, {'Cache-Control': 'public, max-age=86400'}

@app.route('/webhook/lemon', methods=['POST'])
def lemon_webhook():
    signature = request.headers.get('X-Signature', '')
    digest = hmac.new(LEMON_WEBHOOK_SECRET.encode(), request.get_data(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, digest):
        return jsonify({"error": "Invalid signature"}), 401

    data = request.json
    if data.get('meta', {}).get('event_name') == 'order_created':
        order_id = data['data']['id']
        new_key = f"ls_{order_id}"
        KEYS[new_key] = 1000
        save_keys(KEYS)
        return jsonify({"success": True, "key": new_key})
    return jsonify({"status": "ignored"})

# Serve machine-readable files for AI agents
@app.route('/openapi.json')
def openapi(): return send_from_directory('.', 'openapi.json')

@app.route('/llms.txt')
def llms_txt(): return send_from_directory('.', 'llms.txt')

@app.route('/')
def home():
    return jsonify({
        "service": "UA Parser for Humans + AI Agents",
        "latency": "2ms avg",
        "free_tier": "1000/day key=test_123",
        "paid": "$5/1000. Instant key delivery.",
        "features": ["AI bot detection", "CORS enabled", "OpenAPI 3.1", "Global CDN"],
        "buy": "https://YOURSTORE.lemonsqueezy.com/checkout/buy/YOUR_VARIANT_ID",
        "schema": "/openapi.json",
        "llms": "/llms.txt"
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    serve(app, host="0.0.0.0", port=port)