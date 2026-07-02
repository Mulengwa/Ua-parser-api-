   if request.method == 'GET': return jsonify({"message": "POST JSON with {\"email\":\"you@example.com\"} to create order"})
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower() if data.get('email') else ''
    if not validate_email(email): return jsonify({"error": "Invalid email address"}), 400
    
    with get_db_cursor() as cur:
        cur.execute("UPDATE orders SET status = 'expired' WHERE email = %s AND status = 'pending' AND created_at < NOW() - INTERVAL '20 minutes'", (email,))
        
    with get_db_cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT order_id FROM orders WHERE email = %s AND status = 'pending' LIMIT 1", (email,))
        existing = cur.fetchone()
        if existing: return jsonify({"error": "You already have a pending order. Check your email or contact support."}), 409
        
    order_id = f"order_{email.replace('@','_').replace('.','_')}_{uuid.uuid4().hex[:6]}"
    api_key = "sk_live_" + secrets.token_urlsafe(16)
    create_or_update_key(api_key, 0)
    
    with get_db_cursor() as cur:
        cur.execute("INSERT INTO orders (order_id, api_key, email, amount, status, provider) VALUES (%s, %s, %s, %s, 'pending', 'nowpayments')", (order_id, api_key, email, USDT_PRICE_USD))
        
    if not NOWPAYMENTS_API_KEY: return jsonify({"error": "Payment not configured"}), 500
    
    # FIXED: Added customer_email parameter directly to pre-fill the checkout page seamlessly
    np_payload = {
        "price_amount": USDT_PRICE_USD, 
        "price_currency": "usd", 
        "order_id": order_id, 
        "order_description": "UA Parser API - 1000 credits", 
        "customer_email": email,
        "ipn_callback_url": f"{WEBHOOK_URL}/webhook/nowpayments", 
        "success_url": f"{BASE_URL}/thanks", 
        "cancel_url": f"{BASE_URL}/"
    }
    headers = {"x-api-key": NOWPAYMENTS_API_KEY, "Content-Type": "application/json"}
    r = requests.post("https://api.nowpayments.io/v1/invoice", json=np_payload, headers=headers, timeout=10)
    if r.status_code != 200: print(f"NowPayments error: {r.text}"); return jsonify({"error": "Payment provider error"}), 500
    
    invoice = r.json()
    return jsonify({"checkout_url": invoice['invoice_url'], "order_id": order_id, "message": "Customer sees $5 only. No memo needed."}), 200

@app.route('/webhook/nowpayments', methods=['POST'])
@limiter.exempt
def nowpayments_webhook():
    forwarded_for = request.headers.get('X-Forwarded-For', '')
    if not forwarded_for and request.remote_addr != '127.0.0.1': print("WARNING: Webhook from unknown IP")
    received_sig = request.headers.get('x-nowpayments-sig')
    if not received_sig: print("ERROR: Missing x-nowpayments-sig header"); return 'Invalid signature', 403
    
    payload = request.get_data()
    if not NOWPAYMENTS_IPN_SECRET: return 'IPN secret not set', 500
    calc_sig = hmac.new(NOWPAYMENTS_IPN_SECRET.encode(), payload, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(received_sig, calc_sig): print("ERROR: Signature mismatch"); return 'Invalid signature', 403
    
    try: data = request.get_json()
    except Exception as e: print(f"ERROR: Invalid JSON in webhook: {e}"); return 'Invalid payload', 400
    
    if data.get('payment_status') == 'finished':
        order_id = data.get('order_id')
        txid = data.get('txid')
        amount = float(data.get('price_amount', 0))
        
        with get_db_cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT order_id FROM orders WHERE idempotency_key = %s AND status = 'paid'", (txid,))
            if cur.fetchone(): return 'ok', 200
            
        with get_db_cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM orders WHERE order_id = %s", (order_id,))
            order = cur.fetchone()
            
        if order and order['status'] != 'paid' and amount >= USDT_PRICE_USD:
            with get_db_cursor() as cur:
                cur.execute("UPDATE orders SET status = 'paid', tx_hash = %s, idempotency_key = %s WHERE order_id = %s", (txid, txid, order_id))
            create_or_update_key(order['api_key'], 1000)
            send_api_key_email(order['email'], order['api_key'])
            print(f"NOWPAYMENTS FULFILLED {order_id} - TX: {txid}")
            
    return 'ok', 200

@app.route('/openapi.json')
@limiter.exempt
def openapi(): return send_from_directory('.', 'openapi.json')

@app.route('/llms.txt')
@limiter.exempt
def llms_txt(): return send_from_directory('.', 'llms.txt')

@app.route('/')
@limiter.exempt
def home():
    html = """<!DOCTYPE html><html><head><title>UA Parser API</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;line-height:1.6}h1{color:#111}.card{border:1px solid #e5e5e5;border-radius:12px;padding:24px;margin:20px 0}textarea{width:100%;height:80px;padding:10px;font-family:monospace;border:1px solid #ddd;border-radius:8px}button{background:#000;color:#fff;border:none;padding:12px 24px;border-radius:8px;cursor:pointer;font-size:16px;margin-top:10px}button:hover{background:#333}pre{background:#f6f8fa;padding:16px;border-radius:8px;overflow-x:auto}.badge{background:#e6f7ff;color:#0958d9;padding:4px 12px;border-radius:20px;font-size:14px;display:inline-block}a{color:#0969da;text-decoration:none}input{width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;margin:10px 0}</style></head><body><h1>UA Parser for Humans + AI Agents</h1><p class="badge">1000 free requests/day with key=test</p><p>Fast, accurate User-Agent parsing. 2ms avg latency. No signup needed to test.</p><div class="card"><h3>Try it now</h3><textarea id="ua" placeholder="Paste User-Agent here...">Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36</textarea><button onclick="testAPI()">Run Test</button><pre id="result">Result will appear here...</pre></div><div class="card"><h3>Ready to go beyond free?</h3><p>$5 for 1000 requests. Card or crypto. No memo needed.</p><input id="email" type="email" placeholder="Enter your email"><button onclick="buyAPI()">Buy $5</button></div><p><a href="/docs">📖 API Docs</a> | <a href="/openapi.json">OpenAPI Spec</a></p><script>async function testAPI(){const ua=document.getElementById('ua').value;const resultEl=document.getElementById('result');resultEl.textContent='Loading...';try{const res=await fetch(`/v1/parse?key=test&ua=${encodeURIComponent(ua)}`);const data=await res.json();resultEl.textContent=JSON.stringify(data,null,2)}catch(e){resultEl.textContent='Error: '+e.message}}async function buyAPI(){const email=document.getElementById('email').value;if(!email)return alert('Enter email first');const res=await fetch('/create-order',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})});const data=await res.json();console.log('NowPayments response:',data);if(data.checkout_url)window.open(data.checkout_url,'_self');else alert(data.error||'Error: '+JSON.stringify(data))}</script></body></html>"""
    return html

@app.route('/docs')
@limiter.exempt
def docs():
    html = """<!DOCTYPE html><html><head><title>UA Parser API Docs</title><link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="swagger-ui"></div><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/openapi.json',dom_id:'#swagger-ui',presets:[SwaggerUIBundle.presets.apis]})</script></body></html>"""
    return html

@app.route('/thanks')
@limiter.exempt
def thanks():
    html = f"""<!DOCTYPE html><html><head><title>Payment Successful - UA Parser API</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:600px;margin:60px auto;padding:0 20px;line-height:1.6;text-align:center}}h1{{color:#22c55e}}.card{{border:1px solid #e5e5e5;border-radius:12px;padding:24px;margin:20px 0}}p{{color:#666}}a{{color:#0969da;text-decoration:none}}a:hover{{text-decoration:underline}}</style></head><body><h1>✓ Payment Successful!</h1><div class="card"><p>Thank you for your purchase!</p><p>Your API key has been sent to your email. Check your inbox (and spam folder) in the next few minutes.</p><p>If you don't receive it within 15 minutes, <a href="mailto:{escape(SUPPORT_EMAIL)}">contact support</a>.</p><p><a href="/">Back to Home</a></p></div></body></html>"""
    return html

init_db()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 10000))
    serve(app, host="0.0.0.0", port=port)
