from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes as kdf_hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, os
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3, uuid, datetime
from werkzeug.security import generate_password_hash, check_password_hash
import re
import logging

# ---------------------------
# Utilidades RSA / PEM
# ---------------------------
def _normalize_pem(pem_text: str) -> str:
    if not pem_text:
        return ""
    pem = pem_text.strip().replace("\r\n", "\n").replace("\\n", "\n")
    if (pem.startswith('"') and pem.endswith('"')) or (pem.startswith("'") and pem.endswith("'")):
        pem = pem[1:-1].strip()
    return pem

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    return public_key_pem, private_key_pem

def encrypt_with_public_key(plain_text: str, public_key_pem: str) -> str:
    pk = serialization.load_pem_public_key(_normalize_pem(public_key_pem).encode(), backend=default_backend())
    encrypted = pk.encrypt(
        plain_text.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted).decode()

def decrypt_with_private_key(encrypted_b64: str, private_key_pem: str) -> str:
    data = base64.b64decode(encrypted_b64)
    sk = serialization.load_pem_private_key(_normalize_pem(private_key_pem).encode(), password=None, backend=default_backend())
    plain = sk.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plain.decode("utf-8")

# ---------------------------
# Criptografía simétrica (Private Key cifrada)
# ---------------------------
PBKDF2_ITERATIONS = 200_000

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=kdf_hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_private_key_pem(private_key_pem: str, key_password: str):
    salt = os.urandom(16)
    key = _derive_key(key_password, salt)
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, private_key_pem.encode(), None)
    return (
        base64.b64encode(ct).decode(),
        base64.b64encode(salt).decode(),
        base64.b64encode(nonce).decode()
    )

def decrypt_private_key_pem(enc_b64: str, key_password: str, salt_b64: str, nonce_b64: str) -> str:
    ct = base64.b64decode(enc_b64)
    salt = base64.b64decode(salt_b64)
    nonce = base64.b64decode(nonce_b64)
    key = _derive_key(key_password, salt)
    aes = AESGCM(key)
    plain = aes.decrypt(nonce, ct, None)
    return plain.decode()

# ---------------------------
# App / DB
# ---------------------------
app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# Rate limiting (previene ataques de fuerza bruta)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ez-dms')

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(APP_ROOT, 'ez_dms.db')

def connect_db():
    return sqlite3.connect(DATABASE)

def _table_columns(con, table):
    return {row[1] for row in con.execute(f"PRAGMA table_info({table});").fetchall()}

def init_db():
    with connect_db() as con:
        # Usuarios
        con.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            login_pin TEXT UNIQUE NOT NULL,
            search_pin TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT,
            private_key_enc TEXT,
            private_key_salt TEXT,
            private_key_nonce TEXT
        )
        """)
        # Conversaciones
        con.execute("""
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            user_a TEXT NOT NULL,
            user_b TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE(user_a, user_b)
        )
        """)
        # Mensajes
        con.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            content_for_a TEXT NOT NULL,
            content_for_b TEXT NOT NULL
        )
        """)
        # Migraciones por si ya existe BD
        cols = _table_columns(con, "users")
        for col, ddl in {
            "private_key": "ALTER TABLE users ADD COLUMN private_key TEXT",
            "private_key_enc": "ALTER TABLE users ADD COLUMN private_key_enc TEXT",
            "private_key_salt": "ALTER TABLE users ADD COLUMN private_key_salt TEXT",
            "private_key_nonce": "ALTER TABLE users ADD COLUMN private_key_nonce TEXT",
        }.items():
            if col not in cols:
                con.execute(ddl)

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

# ---------------------------
# Auth / Usuarios
# ---------------------------
def _short_pin():
    return str(uuid.uuid4()).replace("-", "")[:8]

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Limita registros a 5 por minuto
def register():
    username = request.form.get('username', '').strip()
    # Validación básica
    if not username or len(username) < 3 or len(username) > 32:
        return jsonify({"error": "El nombre de usuario debe tener entre 3 y 32 caracteres"}), 400
    if not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        return jsonify({"error": "El nombre de usuario solo puede contener letras, números, guiones y guiones bajos"}), 400

    login_pin = _short_pin()
    search_pin = _short_pin()
    pub, priv = generate_key_pair()

    # Hash del login_pin
    login_pin_hash = generate_password_hash(login_pin)
    # Ciframos la private key usando el MISMO login_pin
    priv_enc, salt_b64, nonce_b64 = encrypt_private_key_pem(priv, login_pin)

    user_id = str(uuid.uuid4())
    with connect_db() as con:
        con.execute("""INSERT INTO users
            (id, username, login_pin, search_pin, public_key, private_key, private_key_enc, private_key_salt, private_key_nonce)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (user_id, username, login_pin_hash, search_pin, pub, "", priv_enc, salt_b64, nonce_b64))
        con.commit()

    return jsonify({
        "user_id": user_id, "username": username,
        "login_pin": login_pin, "search_pin": search_pin,
        "public_key": pub
    })

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")  # Limita intentos de login a 10 por minuto
def login():
    pin = request.form.get('login_pin', '').strip()
    if not pin or len(pin) < 4 or len(pin) > 16:
        return jsonify({"error": "login_pin inválido"}), 400
    with connect_db() as con:
        cur = con.execute("SELECT id, username, public_key, login_pin, search_pin FROM users")
        for row in cur.fetchall():
            if check_password_hash(row[3], pin):
                return jsonify({
                    "user_id": row[0],
                    "username": row[1],
                    "public_key": row[2],
                    "login_pin": pin,
                    "search_pin": row[4]
                })
        return jsonify({"error": "Invalid PIN"}), 401

# ---------------------------
# Conversaciones
# ---------------------------
def _ordered_pair(u1: str, u2: str):
    return (u1, u2) if u1 < u2 else (u2, u1)

@app.route('/start_conversation', methods=['POST'])
def start_conversation():
    user_id = request.form.get('user_id')
    partner_search_pin = request.form.get('partner_search_pin', '').strip()
    if not user_id or not partner_search_pin:
        return jsonify({"error": "user_id and partner_search_pin required"}), 400

    with connect_db() as con:
        cur = con.execute("SELECT id FROM users WHERE search_pin = ?", (partner_search_pin,))
        partner = cur.fetchone()
        if not partner:
            return jsonify({"error": "Partner not found"}), 404
        partner_id = partner[0]
        if partner_id == user_id:
            return jsonify({"error": "Cannot start conversation with yourself"}), 400

        a, b = _ordered_pair(user_id, partner_id)
        cur = con.execute("SELECT id FROM conversations WHERE user_a = ? AND user_b = ?", (a, b))
        row = cur.fetchone()
        if row:
            return jsonify({"conversation_id": row[0], "existing": True})

        conv_id = str(uuid.uuid4())
        con.execute("INSERT INTO conversations(id, user_a, user_b, created_at) VALUES(?,?,?,?)",
                    (conv_id, a, b, datetime.datetime.utcnow().isoformat()))
        con.commit()
        return jsonify({"conversation_id": conv_id, "existing": False})

@app.route('/conversations/<user_id>', methods=['GET'])
def list_conversations(user_id):
    with connect_db() as con:
        rows = con.execute("""
        SELECT c.id, u.username, u.search_pin, u.id
        FROM conversations c
        JOIN users u ON (CASE WHEN c.user_a=? THEN c.user_b ELSE c.user_a END) = u.id
        WHERE c.user_a = ? OR c.user_b = ?
        ORDER BY c.created_at DESC
        """, (user_id, user_id, user_id)).fetchall()
        data = []
        for cid, uname, spin, pid in rows:
            data.append({"conversation_id": cid, "partner_username": uname, "partner_search_pin": spin, "partner_id": pid})
        return jsonify(data)

# ---------------------------
# Mensajes
# ---------------------------
@app.route('/send_message', methods=['POST'])
@limiter.limit("30 per minute")  # Limita envío de mensajes a 30 por minuto
def send_message():
    conversation_id = request.form.get('conversation_id')
    sender_id = request.form.get('sender_id')
    content = request.form.get('content', '')
    # Validación básica de mensaje
    if not conversation_id or not sender_id or not content:
        return jsonify({"error": "conversation_id, sender_id y contenido requeridos"}), 400
    if len(content) > 500:
        return jsonify({"error": "El mensaje es demasiado largo (máx 500 caracteres)"}), 400

    with connect_db() as con:
        conv = con.execute("SELECT user_a, user_b FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if not conv:
            return jsonify({"error": "Conversation not found"}), 404

        user_a, user_b = conv[0], conv[1]
        if sender_id not in (user_a, user_b):
            return jsonify({"error": "Sender does not belong to this conversation"}), 403

        pub_a = con.execute("SELECT public_key FROM users WHERE id = ?", (user_a,)).fetchone()[0]
        pub_b = con.execute("SELECT public_key FROM users WHERE id = ?", (user_b,)).fetchone()[0]

        enc_a = encrypt_with_public_key(content, pub_a)
        enc_b = encrypt_with_public_key(content, pub_b)

        msg_id = str(uuid.uuid4())
        con.execute("""
            INSERT INTO messages(id, conversation_id, sender_id, created_at, content_for_a, content_for_b)
            VALUES(?,?,?,?,?,?)
        """, (msg_id, conversation_id, sender_id, datetime.datetime.utcnow().isoformat(), enc_a, enc_b))
        con.commit()

        # Emit event to room
        socketio.emit('new_message', {
            'message_id': msg_id,
            'conversation_id': conversation_id,
            'sender_id': sender_id,
            'created_at': datetime.datetime.utcnow().isoformat(),
            'encrypted_for_a': enc_a,
            'encrypted_for_b': enc_b,
            'user_a': user_a,
            'user_b': user_b
        }, room=conversation_id)

        return jsonify({"message_id": msg_id})

@app.route('/messages/<conversation_id>', methods=['GET'])
def get_messages(conversation_id):
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    with connect_db() as con:
        conv = con.execute("SELECT user_a, user_b FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if not conv:
            return jsonify({"error": "Conversation not found"}), 404
        user_a, user_b = conv[0], conv[1]
        if user_id not in (user_a, user_b):
            return jsonify({"error": "Unauthorized"}), 403

        is_a = (user_id == user_a)
        rows = con.execute("""
            SELECT id, sender_id, created_at, content_for_a, content_for_b
            FROM messages WHERE conversation_id = ?
            ORDER BY datetime(created_at) ASC
        """, (conversation_id,)).fetchall()

        out = []
        for mid, sender, ts, cfa, cfb in rows:
            enc = cfa if is_a else cfb
            out.append({"message_id": mid, "sender_id": sender, "created_at": ts, "encrypted": enc})
        return jsonify(out)

@app.route('/messages_decrypted', methods=['POST'])
def get_messages_decrypted():
    conversation_id = request.form.get('conversation_id')
    user_id = request.form.get('user_id')
    key_password = request.form.get('key_password') or request.form.get('login_pin')

    if not conversation_id or not user_id:
        return jsonify({"error": "conversation_id and user_id required"}), 400

    with connect_db() as con:
        conv = con.execute("SELECT user_a, user_b FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if not conv:
            return jsonify({"error": "Conversation not found"}), 404
        user_a, user_b = conv[0], conv[1]
        if user_id not in (user_a, user_b):
            return jsonify({"error": "Unauthorized"}), 403
        is_a = (user_id == user_a)

        rows = con.execute("""
            SELECT id, sender_id, created_at, content_for_a, content_for_b
            FROM messages WHERE conversation_id = ?
            ORDER BY datetime(created_at) ASC
        """, (conversation_id,)).fetchall()

        u = con.execute("""SELECT private_key_enc, private_key_salt, private_key_nonce, private_key
                           FROM users WHERE id=?""", (user_id,)).fetchone()
        if not u:
            return jsonify({"error": "User not found"}), 404
        enc, salt_b64, nonce_b64, legacy = u

        private_key_pem = None
        if enc and salt_b64 and nonce_b64 and key_password:
            try:
                private_key_pem = decrypt_private_key_pem(enc, key_password, salt_b64, nonce_b64)
            except Exception as e:
                return jsonify({"error": f"Failed to decrypt stored private key: {str(e)}"}), 400
        elif legacy:
            private_key_pem = legacy
        else:
            return jsonify({"error": "No private key available; try re-registering"}), 400

    out = []
    for mid, sender, ts, cfa, cfb in rows:
        enc_msg = cfa if is_a else cfb
        try:
            plain = decrypt_with_private_key(enc_msg, private_key_pem)
        except Exception as e:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 400
        out.append({"message_id": mid, "sender_id": sender, "created_at": ts, "content": plain})
    return jsonify(out)

# ---------------------------
# SocketIO events (real-time updates)
# ---------------------------
@socketio.on('connect')
def on_connect():
    logger.info(f"Socket connected: {request.sid}")
    emit('connected', {'sid': request.sid})

@socketio.on('disconnect')
def on_disconnect():
    logger.info(f"Socket disconnected: {request.sid}")

@socketio.on('join')
def on_join(data):
    conversation_id = data.get('conversation_id')
    user_id = data.get('user_id')
    if not conversation_id or not user_id:
        return
    # Validate that user is participant of the conversation
    with connect_db() as con:
        conv = con.execute("SELECT user_a, user_b FROM conversations WHERE id = ?", (conversation_id,)).fetchone()
        if not conv:
            return
        if user_id not in conv:
            return
    join_room(conversation_id)
    logger.info(f"User {user_id} joined room {conversation_id}")

@socketio.on('leave')
def on_leave(data):
    conversation_id = data.get('conversation_id')
    user_id = data.get('user_id')
    if not conversation_id:
        return
    leave_room(conversation_id)
    logger.info(f"User {user_id} left room {conversation_id}")

# health check
@app.route('/ping')
def ping():
    return jsonify({'status': 'ok'})

# ---------------------------
if __name__ == '__main__':
    init_db()
    # Use socketio.run with eventlet to support websockets
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, use_reloader=False)
