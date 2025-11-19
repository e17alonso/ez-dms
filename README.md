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

### Limitations & Future Improvements
- PIN-based auth is simpler but less secure than passwords
- No forward secrecy (use Signal Protocol in future)
- No message deletion or expiration
- No user blocking or reporting features
- Consider adding rate limiting
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
