import sqlite3
import jwt
import datetime
import random
import os
import re
import hmac
import hashlib
import redis
import json
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load secrets from .env file
load_dotenv('secrets.env')
SECRET_KEY = os.getenv('SECRET_KEY')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.getenv('REDIS_PORT', 6379))

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

app = Flask(__name__)
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

OTP_TTL = 180  # 3 minutes
MAX_REQUESTS_PER_TTL = 3  # Max 3 OTP requests in 3 minutes
RESEND_INTERVAL = 60      # Cannot resend within 1 minute
MAX_VERIFY_ATTEMPTS = 3   # Max 3 OTP verifications per OTP

# Init SQLite DB
def init_db():
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# Generate numeric OTP
def generate_otp(length=6):
    return ''.join(str(random.randint(0, 9)) for _ in range(length))

# Hash the OTP
def hash_otp(otp):
    return hmac.new(SECRET_KEY.encode(), otp.encode(), hashlib.sha256).hexdigest()

# Create JWT Token
def create_jwt(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

# Register User
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')

    if not name or not email or not re.match(EMAIL_REGEX, email):
        return jsonify({'message': 'Invalid name or email format'}), 400

    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        return jsonify({'message': 'Email already registered'}), 400

    cursor.execute("INSERT INTO users (email, name) VALUES (?, ?)", (email, name))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Registration successful. Please verify your email.'})

# Request OTP
@app.route('/api/request-otp', methods=['GET'])
def request_otp():
    email = request.args.get('email')
    if not email or not re.match(EMAIL_REGEX, email):
        return jsonify({'message': 'Invalid email format'}), 400

    # Check if user exists
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if not cursor.fetchone():
        return jsonify({'message': 'Email not registered'}), 400
    conn.close()

    key = f"otpdata:{email}"
    raw_data = r.get(key)

    if raw_data:
        try:
            otp_data = json.loads(raw_data)
        except json.JSONDecodeError:
            r.delete(key)
            return jsonify({'message': 'Corrupted OTP data. Please try again.'}), 500

        if otp_data.get('count', 0) >= MAX_REQUESTS_PER_TTL:
            return jsonify({'message': 'Too many OTP requests. Please try again later.'}), 429

        if (datetime.datetime.utcnow() - datetime.datetime.fromtimestamp(otp_data['timestamp'])).total_seconds() < RESEND_INTERVAL:
            return jsonify({'message': 'OTP already sent recently. Please wait before requesting again.'}), 429

        otp = generate_otp()
        otp_data['otp'] = hash_otp(otp)
        otp_data['count'] += 1
        otp_data['verify_attempts'] = 0
        otp_data['timestamp'] = datetime.datetime.utcnow().timestamp()
        print(f"[MOCK EMAIL] OTP for {email} is {otp}")
    else:
        otp = generate_otp()
        otp_data = {
            'otp': hash_otp(otp),
            'count': 1,
            'verify_attempts': 0,
            'timestamp': datetime.datetime.utcnow().timestamp()
        }
        print(f"[MOCK EMAIL] OTP for {email} is {otp}")

    r.setex(key, OTP_TTL, json.dumps(otp_data))
    return jsonify({'message': 'OTP sent to your email.'})

# Verify OTP
@app.route('/api/verify-otp', methods=['GET'])
def verify_otp():
    email = request.args.get('email')
    otp = request.args.get('otp')

    if not email or not otp or not re.match(EMAIL_REGEX, email):
        return jsonify({'message': 'Missing or invalid email/otp'}), 400

    key = f"otpdata:{email}"
    raw_data = r.get(key)
    if not raw_data:
        return jsonify({'message': 'OTP expired or not requested'}), 401

    try:
        otp_data = json.loads(raw_data)
    except json.JSONDecodeError:
        r.delete(key)
        return jsonify({'message': 'Corrupted OTP data'}), 500

    if otp_data.get('verify_attempts', 0) >= MAX_VERIFY_ATTEMPTS:
        r.delete(key)
        return jsonify({'message': 'Too many incorrect OTP attempts.'}), 429

    if otp_data.get('otp') != hash_otp(otp):
        otp_data['verify_attempts'] += 1
        r.setex(key, OTP_TTL, json.dumps(otp_data))

        if otp_data['verify_attempts'] >= MAX_VERIFY_ATTEMPTS:
            r.delete(key)
            return jsonify({'message': 'Too many incorrect OTP attempts.'}), 429

        return jsonify({'message': 'Invalid OTP'}), 401

    token = create_jwt(email)
    r.delete(key)
    return jsonify({'message': 'Login successful.', 'token': token})

# Profile
@app.route('/api/profile', methods=['GET'])
def profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        email = decoded['email']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE email=?", (email,))
    row = cursor.fetchone()
    name = row[0] if row else 'User'

    return jsonify({'email': email, 'name': name, 'message': 'Welcome to your profile!'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
