from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3
import uuid

# ---------------------------
# Helpers de claves / PEM
# ---------------------------

def _normalize_pem(pem_text: str) -> str:
    """
    Normaliza texto PEM pegado desde el portapapeles:
    - quita comillas y espacios extra
    - convierte '\\n' escapados a saltos reales
    - asegura headers si te llega solo el body base64 (caso raro)
    - elimina líneas tipo 'Public Key:' si las pegaron por error
    """
    if not pem_text:
        return ""
    pem = pem_text.strip()
    pem = pem.replace('\r\n', '\n').replace('\\n', '\n')

    if (pem.startswith('"') and pem.endswith('"')) or (pem.startswith("'") and pem.endswith("'")):
        pem = pem[1:-1].strip()

    lines = [ln for ln in pem.split('\n') if not ln.strip().lower().startswith('public key:')]
    pem = '\n'.join(lines).strip()

    has_pub_header = ("BEGIN PUBLIC KEY" in pem) or ("BEGIN RSA PUBLIC KEY" in pem)
    has_priv_header = ("BEGIN PRIVATE KEY" in pem) or ("BEGIN RSA PRIVATE KEY" in pem)

    if not has_pub_header and not has_priv_header:
        # Si parece un body base64 sin headers, lo envolvemos como PUBLIC KEY
        base64_body = pem.replace('\n', '')
        if base64_body:
            pem = "-----BEGIN PUBLIC KEY-----\n"
            pem += '\n'.join([base64_body[i:i+64] for i in range(0, len(base64_body), 64)])
            pem += "\n-----END PUBLIC KEY-----\n"

    return pem

def decrypt_message_with_private_key(encrypted_message, private_key_pem):
    try:
        encrypted_data = base64.b64decode(encrypted_message)
        priv_norm = _normalize_pem(private_key_pem)
        private_key = serialization.load_pem_private_key(
            priv_norm.encode(), password=None, backend=default_backend()
        )
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')
    except Exception as e:
        raise Exception(f"Decryption failed: {str(e)}")

def encrypt_message_with_public_key(message_content, public_key_pem):
    try:
        pk_norm = _normalize_pem(public_key_pem)
        public_key = serialization.load_pem_public_key(pk_norm.encode(), backend=default_backend())
        encrypted = public_key.encrypt(
            message_content.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print("Encryption failed; normalized PEM was:\n", _normalize_pem(public_key_pem))
        raise

# ---------------------------
# Generación de llaves demo
# ---------------------------

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    public_key = private_key.public_key()
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return public_key_pem, private_key_pem

public_key, private_key = generate_key_pair()
print(f"Public Key:\n{public_key}")
print(f"Private Key:\n{private_key}")

# ---------------------------
# Flask / DB
# ---------------------------

app = Flask(__name__, static_folder='static')
CORS(app)
DATABASE = 'ez_dms.db'

def connect_db():
    return sqlite3.connect(DATABASE)

def init_db():
    with connect_db() as con:
        con.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id TEXT PRIMARY KEY,
                        content TEXT)''')
        cur = con.execute("PRAGMA table_info(messages);")
        columns = [row[1] for row in cur.fetchall()]
        if 'is_encrypted' not in columns:
            con.execute("ALTER TABLE messages ADD COLUMN is_encrypted INTEGER DEFAULT 0")
            con.commit()

@app.route('/')
def home():
    return send_from_directory(app.static_folder, 'index.html')

# Mantener rutas relativas de assets como en tu original
@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

# CRUD messages
@app.route('/create', methods=['POST'])
def create_message():
    content = request.form.get('content')
    if not content:
        return jsonify({"error": "Content is required"}), 400
    message_id = str(uuid.uuid4())
    with connect_db() as con:
        con.execute("INSERT INTO messages (id, content, is_encrypted) VALUES (?, ?, 0)", (message_id, content))
        con.commit()
    return jsonify({"id": message_id})

@app.route('/message/<message_id>', methods=['GET'])
def get_message(message_id):
    with connect_db() as con:
        cur = con.execute("SELECT content, is_encrypted FROM messages WHERE id = ?", (message_id,))
        row = cur.fetchone()
        if row:
            content, is_encrypted = row
            return jsonify({"content": content, "is_encrypted": is_encrypted})
        else:
            return jsonify({"error": "Message not found"}), 404

@app.route('/message/<message_id>', methods=['PUT'])
def update_message(message_id):
    content = request.form.get('content')
    if not content:
        return jsonify({"error": "Content is required"}), 400
    with connect_db() as con:
        cur = con.execute("UPDATE messages SET content = ? WHERE id = ?", (content, message_id))
        con.commit()
        if cur.rowcount:
            return jsonify({"message": "Message updated"})
        else:
            return jsonify({"error": "Message not found"}), 404

@app.route('/message/<message_id>', methods=['DELETE'])
def delete_message(message_id):
    with connect_db() as con:
        cur = con.execute("DELETE FROM messages WHERE id = ?", (message_id,))
        con.commit()
        if cur.rowcount:
            return jsonify({"message": "Message deleted"})
        else:
            return jsonify({"error": "Message not found"}), 404

# ---------------------------
# Encrypt / Decrypt (alias)
# ---------------------------

# Aceptar ambas rutas para compatibilidad con tu front previo
@app.route('/encrypt_note', methods=['POST'])
@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    # Aceptar tanto 'note' como 'message' como 'message_content'
    message_content = (
        request.form.get('message') or
        request.form.get('note') or
        request.form.get('message_content')
    )
    public_key_pem = request.form.get('public_key')

    # Aceptar tanto 'note_id' como 'message_id'
    msg_id = request.form.get('message_id') or request.form.get('note_id')

    if not message_content or not public_key_pem or not msg_id:
        return jsonify({"error": "Message content, public key, and message ID are required"}), 400

    try:
        encrypted_message = encrypt_message_with_public_key(message_content, public_key_pem)
        with connect_db() as con:
            con.execute(
                "UPDATE messages SET content = ?, is_encrypted = 1 WHERE id = ?",
                (encrypted_message, msg_id)
            )
            con.commit()
        return jsonify({"encrypted_message": encrypted_message})
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

@app.route('/decrypt_note', methods=['POST'])
@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    encrypted_message = request.form.get('encrypted_message')
    private_key_pem = request.form.get('private_key')
    msg_id = request.form.get('message_id') or request.form.get('note_id')

    if not encrypted_message or not private_key_pem or not msg_id:
        return jsonify({"error": "Encrypted message, private key, and message ID are required"}), 400

    try:
        decrypted_message = decrypt_message_with_private_key(encrypted_message, private_key_pem)
        with connect_db() as con:
            con.execute(
                "UPDATE messages SET content = ?, is_encrypted = 0 WHERE id = ?",
                (decrypted_message, msg_id)
            )
            con.commit()
        return jsonify({"decrypted_message": decrypted_message})
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

# ---------------------------

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
