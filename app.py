from flask import Flask, request, jsonify
from flask_cors import CORS
from ua_parser import user_agent_parser
import os, json, uuid, hmac, hashlib
from datetime import datetime

app = Flask(__name__)
CORS(app)

KEYS_FILE = 'keys.json'
LEMONSQUEEZY_SIGNING_SECRET = os.environ.get('LEMONSQUEEZY_SECRET', '')

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    return {"FREE": {"credits": 1000, "plan": "free"}}

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f)

def generate_key():
    return f"PRO-{uuid.uuid4().hex[:12]}"

def verify_signature(payload, signature):
    if not LEMONSQUEEZY_SIGNING_SECRET:
        return False
    computed = hmac.new(
        LEMONSQUEEZY_SIGNING_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

@app.route('/')
def home():
    return jsonify({
        "service": "UA Parser API",
        "status": "live",
        "buy_pro": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679",
        "docs": "https://ua-parser-api-zsql.onrender.com/docs"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/v1/parse')
def parse():
    key = request.args.get('key', '')
    ua_string = request.args.get('ua', '')

    keys = load_keys()

    if key not in keys or keys[key]['credits'] <= 0:
        return jsonify({
            "error": "Rate limit exceeded or invalid key",
            "price": "ZMW 100/month = 10,000 requests",
            "buy": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679",
            "free_tier": "Email mulengwa6@gmail.com for 1000 free requests",
            "docs": "https://ua-parser-api-zsql.onrender.com/docs"
        }), 402

    if not ua_string:
        return jsonify({"error": "Missing ua parameter"}), 400

    if keys[key]['plan']!= 'free':
        keys[key]['credits'] -= 1
        save_keys(keys)

    parsed = user_agent_parser.Parse(ua_string)
    return jsonify({
        "browser": parsed['user_agent'],
        "os": parsed['os'],
        "device": parsed['device'],
        "credits_remaining": keys[key]['credits'] if keys[key]['plan']!= 'free' else "unlimited_free_tier"
    })

@app.route('/webhook', methods=['POST'])
def webhook():
    signature = request.headers.get('X-Signature', '')
    payload = request.get_data()

    if not verify_signature(payload, signature):
        return jsonify({"error": "Invalid signature"}), 401

    data = request.json
    event = data.get('meta', {}).get('event_name')

    if event == 'order_created':
        email = data['data']['attributes']['user_email']
        new_key = generate_key()

        keys = load_keys()
        keys[new_key] = {
            "credits": 10000,
            "plan": "pro",
            "email": email,
            "created": datetime.now().isoformat()
        }
        save_keys(keys)

        # TODO: Email the key to customer here
        print(f"NEW KEY GENERATED: {new_key} for {email}")

        return jsonify({"success": True, "key": new_key}), 200

    return jsonify({"success": True}), 200

if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 10000))
    serve(app, host='0.0.0.0', port=port)
    if not ua_string:
        return jsonify({"error": "Missing ua parameter"}), 400

    if key!= "FREE":
        KEYS[key] -= 1

    parsed = user_agent_parser.Parse(ua_string)
    return jsonify({
        "browser": parsed['user_agent'],
        "os": parsed['os'],
        "device": parsed['device'],
        "credits_remaining": KEYS[key] if key!= "FREE" else "unlimited_free_tier"
    })

if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 10000))
    serve(app, host='0.0.0.0', port=port)
