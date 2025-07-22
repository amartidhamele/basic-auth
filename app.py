import sqlite3
import jwt
import datetime
import random
import os
import re
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load secrets from .env file
load_dotenv('secrets.env')
SECRET_KEY = os.getenv('SECRET_KEY')

EMAIL_REGEX = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            otp TEXT,
            otp_expiry INTEGER
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def generate_otp():
    return str(random.randint(100000, 999999))

def create_jwt(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')

    if not email or not re.match(EMAIL_REGEX, email):
        return jsonify({'message': 'Invalid email format'}), 400

    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if cursor.fetchone():
        return jsonify({'message': 'Email already registered'}), 400

    cursor.execute("INSERT INTO users (email, otp, otp_expiry) VALUES (?, ?, ?)", (email, '', 0))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Registration successful. Please verify your email.'})

@app.route('/api/request-otp', methods=['GET'])
def request_otp():
    email = request.args.get('email')

    if not email or not re.match(EMAIL_REGEX, email):
        return jsonify({'message': 'Invalid email format'}), 400

    otp = generate_otp()
    expiry = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=5)).timestamp())

    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    if not cursor.fetchone():
        return jsonify({'message': 'Email not registered'}), 400

    cursor.execute("UPDATE users SET otp=?, otp_expiry=? WHERE email=?", (otp, expiry, email))
    conn.commit()
    conn.close()

    print(f"[MOCK EMAIL] OTP for {email} is {otp}")
    return jsonify({'message': 'OTP sent to your email.'})

@app.route('/api/verify-otp', methods=['GET'])
def verify_otp():
    email = request.args.get('email')
    otp = request.args.get('otp')

    if not email or not re.match(EMAIL_REGEX, email) or not otp:
        return jsonify({'message': 'Missing or invalid email/otp'}), 400

    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute("SELECT otp, otp_expiry FROM users WHERE email=?", (email,))
    row = cursor.fetchone()

    if not row:
        return jsonify({'message': 'Email not registered'}), 400

    saved_otp, expiry = row
    now = int(datetime.datetime.utcnow().timestamp())

    if saved_otp != otp:
        return jsonify({'message': 'Invalid OTP'}), 401
    if now > expiry:
        return jsonify({'message': 'OTP expired'}), 401

    token = create_jwt(email)
    return jsonify({'message': 'Login successful.', 'token': token})

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

    return jsonify({'email': email, 'message': 'Welcome to your profile!'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
