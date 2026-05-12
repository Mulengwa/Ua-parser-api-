from flask import Flask, request, jsonify
from flask_cors import CORS
from ua_parser import user_agent_parser
import os

app = Flask(__name__)
CORS(app)

KEYS = {"FREE": 1000}

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

    if key not in KEYS or KEYS[key] <= 0:
        return jsonify({
            "error": "Rate limit exceeded or invalid key",
            "price": "ZMW 100/month = 10,000 requests",
            "buy": "https://uaparserapi.lemonsqueezy.com/checkout/buy/a7f42d10-e3e2-41e9-ad5f-f893a48f0679",
            "free_tier": "Email mulengwa6@gmail.com for 1000 free requests",
            "docs": "https://ua-parser-api-zsql.onrender.com/docs"
        }), 402

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
