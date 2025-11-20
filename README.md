# EZ-DMS (Easy Direct Messaging System)

A secure, end-to-end encrypted messaging application built with Flask and JavaScript. EZ-DMS provides private conversations using RSA encryption, ensuring that only the intended recipients can read messages.

## Features

- **End-to-End Encryption**: All messages are encrypted using RSA-2048 before being stored
- **Secure PIN Authentication**: Login PINs are hashed using Werkzeug's password hashing
- **Real-Time Messaging**: WebSocket support via Flask-SocketIO for instant message delivery
- **Private Conversations**: Start secure conversations using search PINs
- **Encrypted Private Keys**: User private keys are encrypted at rest using AES-GCM with PBKDF2
- **Zero-Knowledge Architecture**: Server cannot read message contents
- **Input Validation**: Username validation (3-32 chars, alphanumeric), message length limits (500 chars)
- **Mobile-Friendly**: Responsive design that works on all devices
- **Modern UI**: Clean interface with Inter font, gradients, and smooth animations

## Security Features

### Encryption Details

- **Message Encryption**: RSA-2048 with OAEP padding and SHA-256
- **Private Key Storage**: AES-256-GCM encryption with PBKDF2-HMAC-SHA256 (200,000 iterations)
- **Key Derivation**: PBKDF2 with 200,000 iterations for password-based encryption
- **Per-User Encryption**: Each message is encrypted separately for both participants

### Authentication

- **Login PIN Hashing**: Werkzeug's generate_password_hash with secure defaults
- **Search PIN**: Unhashed for easy sharing between users
- **Session Management**: Flask session handling with secure secret key

### Privacy

- Messages are stored encrypted in the database
- Private keys are encrypted with user's login PIN
- No plaintext message content is ever stored on the server
- Each conversation participant has their own encrypted copy of each message
- Login PINs are hashed and never stored in plain text

### Rate Limiting

- **Registration**: Limited to 5 attempts per minute per IP
- **Login**: Limited to 10 attempts per minute per IP
- **Send Message**: Limited to 30 messages per minute per IP
- Prevents brute force attacks and spam

### Real-Time Communication

- **WebSockets**: Flask-SocketIO for instant message delivery
- **Room-Based Messaging**: Users only receive messages from their active conversations
- **Automatic Updates**: Messages appear instantly for both participants

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

1. Clone the repository:

```bash
git clone https://github.com/e17alonso/ez-dms.git
cd ez-dms
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the application:

```bash
cd backend
python app.py
```

4. Open your browser and navigate to:

```
http://localhost:5000
```

## Dependencies

```
Flask==3.0.0
Flask-CORS==4.0.0
Flask-SocketIO==5.3.6
Flask-Limiter==3.5.0
cryptography==41.0.7
werkzeug==3.0.1
```

Create a `requirements.txt` file with the above dependencies.

## Usage

### Registration

1. Enter a username (3-32 characters, alphanumeric only)
2. Click "Create account"
3. Save your **Login PIN** and **Search PIN** securely
   - **Login PIN**: Used to access your account (hashed in database)
   - **Search PIN**: Share this with others so they can start conversations with you

### Login

1. Enter your Login PIN
2. Click "Login"

### Starting a Conversation

1. Ask your contact for their Search PIN
2. Enter their Search PIN in the "Start new conversation" field
3. Click "Start"
4. Begin messaging

### Sending Messages

1. Select a conversation from the sidebar
2. Type your message in the input field (max 500 characters)
3. Click "Send" or press Enter
4. Messages are automatically decrypted using your Login PIN
5. Messages appear instantly for both participants via WebSocket

## Deployment with Ngrok (Public Access)

This guide shows how to deploy EZ-DMS with Ngrok for public access, following the exact steps used in this project setup with Nginx as a reverse proxy and SSL/TLS support.

### Why Ngrok?

- **No Domain Required**: Get a public URL instantly without registering a domain
- **HTTPS Included**: Automatic SSL/TLS encryption for secure communication
- **No Port Forwarding**: Works behind firewalls and NAT without router configuration
- **Easy Setup**: Single command to expose your server

### Architecture Overview

```
Internet → Ngrok (HTTPS) → Nginx (port 80/443) → Flask + SocketIO (port 5000)
```

### Complete Setup Steps (macOS)

#### Step 1: Install Dependencies

```bash
# Install Python dependencies
pip install -r backend/requirements.txt

# Install Nginx (if not already installed)
brew install nginx

# Install Ngrok
brew install ngrok
```

#### Step 2: Configure SSL Certificate (Self-Signed)

Generate a self-signed SSL certificate for Nginx:

```bash
# Create SSL directory
sudo mkdir -p /opt/homebrew/etc/nginx/ssl

# Generate self-signed certificate (valid for 1 year)
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /opt/homebrew/etc/nginx/ssl/cert.key \
  -out /opt/homebrew/etc/nginx/ssl/cert.pem \
  -subj "/C=MX/ST=CDMX/L=CDMX/O=EZ-DMS/CN=localhost"
```

#### Step 3: Configure Nginx

Edit the Nginx configuration file:

```bash
sudo nano /opt/homebrew/etc/nginx/nginx.conf
```

Add the following server blocks inside the `http {}` section:

```nginx
# HTTP server (port 80) - Proxy to Flask
server {
    listen 80;
    server_name localhost;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support for Socket.IO
    location /socket.io/ {
        proxy_pass http://127.0.0.1:5000/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
    }
}

# HTTPS server (port 443) - Proxy to Flask with SSL
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate      /opt/homebrew/etc/nginx/ssl/cert.pem;
    ssl_certificate_key  /opt/homebrew/etc/nginx/ssl/cert.key;
    ssl_session_cache    shared:SSL:1m;
    ssl_session_timeout  10m;
    ssl_ciphers  HIGH:!aNULL:!MD5:!RC4:!DES:!3DES;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support for Socket.IO
    location /socket.io/ {
        proxy_pass http://127.0.0.1:5000/socket.io/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
    }
}
```

Test and reload Nginx configuration:

```bash
# Test configuration
sudo nginx -t

# Start or reload Nginx
sudo nginx
# or if already running:
sudo nginx -s reload
```

#### Step 4: Initialize the Database

```bash
cd backend
python3 -c 'from app import init_db; init_db()'
```

#### Step 5: Start Flask Backend

```bash
cd backend
python3 app.py
```

The server will start on `http://0.0.0.0:5000` and you should see:

```
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
```

#### Step 6: Setup Ngrok

1. **Sign up** at [https://dashboard.ngrok.com/signup](https://dashboard.ngrok.com/signup)

2. **Get your authtoken** from [https://dashboard.ngrok.com/get-started/your-authtoken](https://dashboard.ngrok.com/get-started/your-authtoken)

3. **Configure authtoken** (only needed once):

```bash
ngrok config add-authtoken YOUR_AUTHTOKEN_HERE
```

#### Step 7: Start Ngrok Tunnel

Open a new terminal and run:

```bash
ngrok http 80
```

You'll see output like:

```
Session Status                online
Account                       your-account (Plan: Free)
Version                       3.x.x
Region                        United States (us)
Forwarding                    https://abc123.ngrok.io -> http://localhost:80

Connections                   ttl     opn     rt1     rt5     p50     p90
                              0       0       0.00    0.00    0.00    0.00
```

#### Step 8: Access Your App

Copy the HTTPS URL (e.g., `https://abc123.ngrok.io`) and share it with anyone. They can now access your messaging system from anywhere in the world!

### Verification Steps

1. **Check Flask is running**:

   ```bash
   curl http://localhost:5000/ping
   # Should return: {"status":"ok"}
   ```

2. **Check Nginx proxy**:

   ```bash
   curl http://localhost/ping
   # Should return: {"status":"ok"}
   ```

3. **Check Ngrok tunnel**:

   - Open the Ngrok URL in your browser
   - You should see the EZ-DMS login page

4. **Test WebSocket**:
   - Create two accounts
   - Start a conversation
   - Send messages from both sides
   - Messages should appear instantly without refresh

### Troubleshooting

**Problem: Ngrok shows "endpoint offline" (ERR_NGROK_3200)**

- Ensure Flask is running on port 5000
- Ensure Nginx is running and proxying port 80 to Flask
- Check Nginx logs: `tail -f /opt/homebrew/var/log/nginx/error.log`

**Problem: Messages don't update in real-time**

- Verify Flask-SocketIO is installed: `pip show Flask-SocketIO`
- Check browser console for WebSocket errors
- Ensure Nginx WebSocket proxy is configured for `/socket.io/`

**Problem: "Address already in use" on port 5000**

```bash
# Find and kill process using port 5000
sudo lsof -i :5000
sudo kill <PID>
```

**Problem: Nginx won't start**

```bash
# Check for syntax errors
sudo nginx -t

# Check if port 80/443 is already in use
sudo lsof -i :80
sudo lsof -i :443
```

### Important Notes

- **Keep terminals running**: You need 2 terminals active:
  1. Flask backend (`python3 app.py`)
  2. Ngrok tunnel (`ngrok http 80`)
- **URL changes**: Free Ngrok URLs change each restart (paid plans offer static URLs)
- **SSL Warning**: Users see a browser warning for self-signed certificates (safe to bypass for testing)
- **Session persistence**: Each user's session is tied to their browser
- **Database location**: SQLite database created at `backend/ez_dms.db`

## Architecture

### Backend (`app.py`)

- **Flask REST API** with SQLite database
- **Flask-SocketIO** for real-time WebSocket communication
- **Cryptography endpoints**:
  - User registration and authentication
  - Conversation management
  - Message encryption/decryption
- **Database schema**:
  - `users`: User credentials and encrypted keys
  - `conversations`: Chat sessions between users
  - `messages`: Encrypted message content

### Frontend

- **Vanilla JavaScript** (no frameworks)
- **Socket.IO Client** for real-time updates
- **Responsive CSS** with modern design (Inter font, gradients)
- **Dynamic UI** updates
- **Automatic message decryption**

### Encryption Flow

```
┌─────────────┐         ┌─────────────┐         ┌─────────────┐
│   Sender    │         │   Server    │         │  Recipient  │
└─────────────┘         └─────────────┘         └─────────────┘
       │                       │                       │
       │   1. Plain message    │                       │
       ├──────────────────────>│                       │
       │                       │                       │
       │   2. Encrypt with     │                       │
       │      both public keys │                       │
       │                       │                       │
       │   3. Store encrypted  │                       │
       │      copies           │                       │
       │                       │                       │
       │                       │   4. WebSocket emit   │
       │                       ├──────────────────────>│
       │                       │   (encrypted msg)     │
       │                       │                       │
       │                       │   5. Client decrypts  │
       │                       │      with private key │
       │                       │                       │
```

## Project Structure

```
ez-dms/
├── backend/
│   ├── app.py              # Flask application and API endpoints
│   ├── requirements.txt    # Python dependencies
│   ├── cert.pem           # SSL certificate (optional)
│   ├── key.pem            # SSL private key (optional)
│   ├── static/
│   │   ├── index.html      # Main HTML interface
│   │   ├── script.js       # Frontend logic with Socket.IO
│   │   └── style.css       # Modern styling
│   └── ez_dms.db           # SQLite database (created on first run)
└── README.md
```

## API Endpoints

### Authentication

- `POST /register` - Create new user account
- `POST /login` - Authenticate with login PIN

### Conversations

- `POST /start_conversation` - Initiate new conversation
- `GET /conversations/<user_id>` - List all user conversations

### Messages

- `POST /send_message` - Send encrypted message (triggers WebSocket broadcast)
- `GET /messages/<conversation_id>` - Get encrypted messages
- `POST /messages_decrypted` - Get decrypted messages with login PIN

### Health Check

- `GET /ping` - Server health check

## WebSocket Events

### Client → Server

- `connect` - Client connects to server
- `disconnect` - Client disconnects from server
- `join` - Join a conversation room
- `leave` - Leave a conversation room

### Server → Client

- `connected` - Connection confirmation with session ID
- `new_message` - New message broadcast to conversation participants

## Development

### Database Schema

**Users Table:**

```sql
- id: TEXT PRIMARY KEY
- username: TEXT
- login_pin: TEXT UNIQUE (hashed with Werkzeug)
- search_pin: TEXT UNIQUE
- public_key: TEXT
- private_key_enc: TEXT (encrypted private key)
- private_key_salt: TEXT
- private_key_nonce: TEXT
```

**Conversations Table:**

```sql
- id: TEXT PRIMARY KEY
- user_a: TEXT
- user_b: TEXT
- created_at: TEXT
- UNIQUE(user_a, user_b)
```

**Messages Table:**

```sql
- id: TEXT PRIMARY KEY
- conversation_id: TEXT
- sender_id: TEXT
- created_at: TEXT
- content_for_a: TEXT (encrypted for user_a)
- content_for_b: TEXT (encrypted for user_b)
```

### Input Validation

**Username:**

- Length: 3-32 characters
- Characters: Alphanumeric, hyphens, underscores only
- Regex: `^[a-zA-Z0-9_\-]+$`

**Messages:**

- Maximum length: 500 characters

**Login PIN:**

- Length: 4-16 characters (when logging in)

## Security Considerations

### Strengths

- End-to-end encryption ensures server cannot read messages
- Private keys are encrypted at rest
- Strong key derivation (PBKDF2 with 200K iterations)
- RSA-2048 with secure padding (OAEP)
- AES-256-GCM for symmetric encryption
- Login PINs are hashed using industry-standard methods
- WebSocket connections for secure real-time communication
- Input validation prevents injection attacks
- **Rate limiting** protects against brute force attacks and spam

### Limitations & Future Improvements

- PIN-based auth is simpler but less secure than passwords
- No forward secrecy (use Signal Protocol in future)
- No message deletion or expiration
- No user blocking or reporting features
- ~~Consider adding rate limiting~~ ✅ **Rate limiting implemented** (v1.1)
- Consider adding 2FA for additional security
- WebSocket authentication could be enhanced
- Add message read receipts
- Add typing indicators
- Implement message search functionality

## Running with SSL (Optional)

The project includes SSL certificates (`cert.pem` and `key.pem`) for HTTPS support. To run with SSL:

```python
if __name__ == '__main__':
    init_db()
    socketio.run(app,
                 debug=True,
                 host='0.0.0.0',
                 port=5000,
                 use_reloader=False,
                 ssl_context=('cert.pem', 'key.pem'))  # Add this line
```

## Troubleshooting

### WebSocket Connection Issues

- Ensure Flask-SocketIO is installed correctly
- Check that Socket.IO client version matches server version
- Verify network allows WebSocket connections

### Message Decryption Errors

- Verify Login PIN is correct
- Ensure private key was encrypted properly during registration
- Check that PBKDF2 iterations match (200,000)

## Authors

Josue Ruiz - [@josuer02](https://github.com/josuer02)

Esteban Alonso - [@e17alonso](https://github.com/e17alonso)

Steph Grotewold - [@stephgrotewold](https://github.com/stephgrotewold)

Project Link: [https://github.com/e17alonso/ez-dms.git](https://github.com/e17alonso/ez-dms.git)

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Real-time communication via [Flask-SocketIO](https://flask-socketio.readthedocs.io/)
- Encryption provided by [cryptography](https://cryptography.io/)
- Password hashing via [Werkzeug](https://werkzeug.palletsprojects.com/)
- Inspired by modern end-to-end encrypted messaging apps

---
