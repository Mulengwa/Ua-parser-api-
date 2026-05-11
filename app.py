from flask import Flask, request, jsonify
from flask_cors import CORS
from ua_parser import user_agent_parser
import os

app = Flask(__name__)
CORS(app)

# API Keys: email -> credits remaining. Add keys manually after purchase.
KEYS = {
    "FREE": 1000,
    # Add paid keys here: "sk_live_abc123": 10000
}

@app.route('/')
def home():
    return jsonify({
        "service": "UA Parser API",
        "docs": "https://ua-parser-api-zsql.onrender.com/docs",
        "free_test": "https://ua-parser-api-zsql.onrender.com/v1/parse?key=FREE&ua=Mozilla/5.0",
        "buy_pro": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "latency_ms": "<80"})

@app.route('/v1/parse')
def parse():
    key = request.args.get('key', '')
    ua_string = request.args.get('ua', '')

    if key not in KEYS or KEYS[key] <= 0:
        return jsonify({
            "error": "Rate limit exceeded or invalid key",
            "price": "ZMW 100/month = 10,000 requests. Free tier available",
            "buy": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679",
            "free_tier": "Email mulengwa6@gmail.com with subject 'FREE KEY' for 1000 requests/month",
            "docs": "https://ua-parser-api-zsql.onrender.com/docs"
        }), 402

    if not ua_string:
        return jsonify({"error": "Missing?ua=Mozilla/5.0... parameter"}), 400

    # Deduct credit for non-FREE keys
    if key!= "FREE":
        KEYS[key] -= 1

    parsed = user_agent_parser.Parse(ua_string)

    return jsonify({
        "user_agent": ua_string,
        "browser": {
            "family": parsed['user_agent']['family'],
            "major": parsed['user_agent']['major'],
            "minor": parsed['user_agent']['minor']
        },
        "os": {
            "family": parsed['os']['family'],
            "major": parsed['os']['major'],
            "minor": parsed['os']['minor']
        },
        "device": {
            "family": parsed['device']['family'],
            "brand": parsed['device']['brand'],
            "model": parsed['device']['model']
        },
        "credits_remaining": KEYS[key] if key!= "FREE" else "unlimited_free_tier"
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)    response.headers['Access-Control-Allow-Origin'] = '*'
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
