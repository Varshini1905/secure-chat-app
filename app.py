from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from werkzeug.security import generate_password_hash, check_password_hash
import json
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Serve the HTML file
@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

# In-memory user storage
users = {}
user_keys = {}
connected_users = {}
# Store session keys between users
session_keys = {}

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def decrypt_with_rsa(private_key, encrypted_data):
    """
    Decrypts data using the provided RSA private key.
    """
    try:
        # If encrypted_data is a string, convert it to bytes
        if isinstance(encrypted_data, str):
            encrypted_data = base64.b64decode(encrypted_data)
        
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
        print(f"RSA decryption error: {e}")
        return None

# HTTP endpoints for authentication
@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    print(f"Registering user: {username}")

    if username in users:
        return jsonify({'success': False, 'error': 'User already exists'}), 400
    
    users[username] = generate_password_hash(password)
    private_key, public_key = generate_rsa_keypair()
    user_keys[username] = {
        'private_key': private_key,
        'public_key': public_key
    }
    
    return jsonify({'success': True})

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    print(f"Login attempt for user: {username}")

    if username in users and check_password_hash(users[username], password):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    print(f'Client connected: {request.sid}')

@socketio.on('disconnect')
def handle_disconnect():
    print(f'Client disconnected: {request.sid}')
    # Remove user from connected users
    for username, sid in list(connected_users.items()):
        if sid == request.sid:
            del connected_users[username]
            break
    emit('user_list_update', list(connected_users.keys()), broadcast=True)

@socketio.on('user_connected')
def handle_user_connected(data):
    username = data['username']
    connected_users[username] = request.sid
    print(f'User {username} connected with session {request.sid}')
    emit('user_list_update', list(connected_users.keys()), broadcast=True)

@socketio.on('request_public_key')
def handle_request_public_key(data):
    recipient = data['to']
    sender = data['from']
    
    print(f"Public key request: {sender} -> {recipient}")
    
    if recipient in user_keys and recipient in connected_users:
        public_key = user_keys[recipient]['public_key']
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Send to the requesting user
        emit('public_key_response', {
            'from': recipient,
            'publicKey': public_key_pem
        }, room=request.sid)
        
        print(f"Sent public key from {recipient} to {sender}")

@socketio.on('send_aes_key')
def handle_send_aes_key(data):
    recipient = data['to']
    encrypted_aes_key = data['encryptedAesKey']
    sender = data['from']
    
    print(f"AES key exchange: {sender} -> {recipient}")
    
    # Store the session key for both users (simplified for demo)
    session_id = f"{sender}_{recipient}"
    reverse_session_id = f"{recipient}_{sender}"
    
    try:
        # In a real implementation, decrypt with recipient's private key
        # For demo, we'll parse the JSON directly
        key_data = json.loads(encrypted_aes_key)
        session_keys[session_id] = key_data
        session_keys[reverse_session_id] = key_data
        print(f"Stored session keys for {session_id}")
    except Exception as e:
        print(f"Error storing session key: {e}")
    
    if recipient in connected_users:
        # Forward the encrypted AES key to the recipient
        emit('aes_key_exchange', {
            'from': sender,
            'encryptedAesKey': encrypted_aes_key
        }, room=connected_users[recipient])
        
        print(f"Forwarded AES key from {sender} to {recipient}")

@socketio.on('aes_key_ack')
def handle_aes_key_ack(data):
    recipient = data['to']
    sender = data['from']
    
    if recipient in connected_users:
        emit('aes_key_ack', {
            'from': sender
        }, room=connected_users[recipient])

@socketio.on('send_message')
def handle_send_message(data):
    recipient = data['to']
    encrypted_message = data['message']
    sender = data['from']
    
    print(f"Message: {sender} -> {recipient}")
    
    if recipient in connected_users:
        emit('encrypted_message', {
            'from': sender,
            'message': encrypted_message,
            'timestamp': data.get('timestamp')
        }, room=connected_users[recipient])
        
        print(f"Forwarded message from {sender} to {recipient}")

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
