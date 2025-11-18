# EZ-DMS (Easy Direct Messaging System)

A secure, end-to-end encrypted messaging application built with Flask and JavaScript. EZ-DMS provides private conversations using RSA encryption, ensuring that only the intended recipients can read messages.

## Features

- **End-to-End Encryption**: All messages are encrypted using RSA-2048 before being stored
- **PIN-Based Authentication**: Simple login system using unique PINs
- **Private Conversations**: Start secure conversations using search PINs
- **Encrypted Private Keys**: User private keys are encrypted at rest using AES-GCM with PBKDF2
- **Real-time Messaging**: Clean, responsive chat interface
- **Zero-Knowledge Architecture**: Server cannot read message contents
- **Mobile-Friendly**: Responsive design that works on all devices

## Security Features

### Encryption Details
- **Message Encryption**: RSA-2048 with OAEP padding and SHA-256
- **Private Key Storage**: AES-256-GCM encryption with PBKDF2-HMAC-SHA256 (200,000 iterations)
- **Key Derivation**: PBKDF2 with 200,000 iterations for password-based encryption
- **Per-User Encryption**: Each message is encrypted separately for both participants

### Privacy
- Messages are stored encrypted in the database
- Private keys are encrypted with user's login PIN
- No plaintext message content is ever stored on the server
- Each conversation participant has their own encrypted copy of each message

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
cryptography==41.0.7
```

Create a `requirements.txt` file with the above dependencies.

## Usage

### Registration

1. Enter a username
2. Click "Create account"
3. Save your **Login PIN** and **Search PIN** securely
   - **Login PIN**: Used to access your account
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
2. Type your message in the input field
3. Click "Send"
4. Messages are automatically decrypted using your Login PIN

## Architecture

### Backend (`app.py`)

- **Flask REST API** with SQLite database
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
- **Responsive CSS** with grid layout
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
       │                       │   4. Request messages │
       │                       │<──────────────────────┤
       │                       │                       │
       │                       │   5. Return encrypted │
       │                       ├──────────────────────>│
       │                       │                       │
       │                       │   6. Decrypt with     │
       │                       │      private key      │
       │                       │                       │
```

## Project Structure

```
ez-dms/
├── backend/
│   ├── app.py              # Flask application and API endpoints
│   ├── static/
│   │   ├── index.html      # Main HTML interface
│   │   ├── script.js       # Frontend logic
│   │   └── style.css       # Styling
│   └── ez_dms.db           # SQLite database
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
- `POST /send_message` - Send encrypted message
- `GET /messages/<conversation_id>` - Get encrypted messages
- `POST /messages_decrypted` - Get decrypted messages with login PIN

## Development

### Database Schema

**Users Table:**
```sql
- id: TEXT PRIMARY KEY
- username: TEXT
- login_pin: TEXT UNIQUE
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

## Security Considerations

### Strengths
- End-to-end encryption ensures server cannot read messages
- Private keys are encrypted at rest
- Strong key derivation (PBKDF2 with 200K iterations)
- RSA-2048 with secure padding (OAEP)
- AES-256-GCM for symmetric encryption

### Limitations & Future Improvements
- PIN-based auth is simpler but less secure than passwords
- No forward secrecy (use Signal Protocol in future)
- No message deletion or expiration
- No user blocking or reporting features
- Consider adding rate limiting
- Consider adding 2FA for additional security

## Author

Josue Ruiz - [@josuer02](https://github.com/josuer02)

Esteban Alonso - [@e17alonso](https://github.com/e17alonso)

Steph Grotewold - [@stephgrotewold](https://github.com/stephgrotewold)

Project Link: [https://github.com/e17alonso/ez-dms.git](https://github.com/e17alonso/ez-dms.git)

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Encryption provided by [cryptography](https://cryptography.io/)
- Inspired by modern end-to-end encrypted messaging apps

---
