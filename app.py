from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
import uuid
import hmac
import hashlib
from datetime import datetime
from ua_parser import user_agent_parser

app = Flask(__name__)
CORS(app)

KEYS_FILE = 'keys.json'
LEMONSQUEEZY_SIGNING_SECRET = os.environ.get('LEMONSQUEEZY_SECRET', '')

def load_keys():
    if os.path.exists(KEYS_FILE):
        with open(KEYS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_keys(keys):
    with open(KEYS_FILE, 'w') as f:
        json.dump(keys, f, indent=2)

def verify_signature(payload, signature):
    if not LEMONSQUEEZY_SIGNING_SECRET:
        return True
    computed = hmac.new(
        LEMONSQUEEZY_SIGNING_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)

@app.route('/')
def home():
    return jsonify({"status": "UA Parser API Live", "endpoints": ["/parse", "/webhook", "/validate"]})

@app.route('/parse')
def parse_ua():
    ua_string = request.args.get('ua')
    if not ua_string:
        return jsonify({"error": "Missing ua parameter"}), 400

    parsed = user_agent_parser.Parse(ua_string)
    return jsonify({
        "user_agent": ua_string,
        "browser": {"name": parsed['user_agent']['family'], "version": parsed['user_agent']['major']},
        "os": {"name": parsed['os']['family'], "version": parsed['os']['major']},
        "device": {"type": parsed['device']['family']}
    })

@app.route('/webhook', methods=['POST'])
def lemonsqueezy_webhook():
    signature = request.headers.get('X-Signature', '')
    payload = request.data

    if not verify_signature(payload, signature):
        return jsonify({"error": "Invalid signature"}), 403

    data = request.json
    if data.get('meta', {}).get('event_name') == 'order_created':
        email = data['data']['attributes']['user_email']
        order_id = data['data']['id']
        
        keys = load_keys()
        new_key = f"PRO-{uuid.uuid4().hex[:12].upper()}"
        keys[new_key] = {"email": email, "order_id": order_id, "created": str(datetime.now())}
        save_keys(keys)
        
        print(f"NEW KEY GENERATED: {new_key} for {email}")
        return jsonify({"success": True, "key": new_key}), 200

    return jsonify({"success": True}), 200

@app.route('/validate')
def validate_key():
    user_key = request.args.get('key')
    if not user_key:
        return jsonify({"valid": False, "error": "Missing key"}), 400

    keys = load_keys()
    if user_key in keys:
        return jsonify({"valid": True, "tier": "pro", "data": keys[user_key]})
    return jsonify({"valid": False}), 404

if __name__ == '__main__':
    from waitress import serve
    port = int(os.environ.get('PORT', 10000))
    serve(app, host='0.0.0.0', port=port)
