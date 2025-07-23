# Flask OTP Authentication App

This is a simple authentication service using Flask, SQLite, Redis, and JWT. It supports user registration, OTP-based login, and JWT-protected profile access.

## Features
- User registration with email and name
- OTP (One-Time Password) login with rate limiting and security
- JWT-based authentication for protected endpoints
- SQLite for user storage
- Redis for OTP/session management

## Requirements
- Python 3.7+
- Redis server
- pip (Python package manager)

## Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/amartidhamele/basic-auth.git
   cd auth_app
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**
   Create a file named `secrets.env` in the project root:
   ```env
   SECRET_KEY=your_secret_key_here
   REDIS_HOST=localhost
   REDIS_PORT=6379
   ```

4. **Start Redis server**
   Make sure Redis is running locally (default: `localhost:6379`).

5. **Run the app**
   ```bash
   python app.py
   ```
   The app will be available at `http://localhost:8000`.

## API Endpoints

### 1. Register
- **POST** `/api/register`
- **Body:**
  ```json
  { "name": "John Doe", "email": "john@example.com" }
  ```
- **Response:**
  - `200 OK` on success
  - `400 Bad Request` if email/name is invalid or already registered

### 2. Request OTP
- **GET** `/api/request-otp?email=john@example.com`
- **Response:**
  - `200 OK` if OTP sent
  - `400 Bad Request` if email is invalid or not registered
  - `429 Too Many Requests` if rate limit exceeded

### 3. Verify OTP
- **GET** `/api/verify-otp?email=john@example.com&otp=123456`
- **Response:**
  - `200 OK` with JWT token on success
  - `401 Unauthorized` if OTP is invalid or expired
  - `429 Too Many Requests` if too many attempts

### 4. Profile (Protected)
- **GET** `/api/profile`
- **Headers:**
  - `Authorization: Bearer <JWT_TOKEN>`
- **Response:**
  - `200 OK` with user info
  - `401 Unauthorized` if token is missing/invalid/expired

## Environment Variables
- `SECRET_KEY`: Secret for JWT and OTP hashing
- `REDIS_HOST`: Redis server host (default: localhost)
- `REDIS_PORT`: Redis server port (default: 6379)

## Notes
- OTPs are valid for 3 minutes, max 3 requests per 3 minutes, and max 3 verification attempts per OTP.
- OTPs are printed to the console for testing (replace with email sending in production).

## License
MIT 