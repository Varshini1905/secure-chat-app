from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from werkzeug.security import generate_password_hash, check_password_hash
import json

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

    Args:
        private_key: The RSA private key used for decryption.
        encrypted_data: The data to be decrypted (in bytes).

    Returns:
        The decrypted data as a string.
    """
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')  # Decode bytes to string

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username in users:
        return jsonify({'success': False, 'error': 'User  already exists'}), 400
    
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
    
    if username in users and check_password_hash(users[username], password):
        return jsonify({'success': True})
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@socketio.on('request_public_key')
def handle_request_public_key(data):
    recipient = data['to']
    sender = data['from']
    
    if recipient in user_keys:
        public_key = user_keys[recipient]['public_key']
        emit('public_key_response', {
            'from': recipient,
            'publicKey': public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }, room=request.sid)

@socketio.on('send_aes_key')
def handle_send_aes_key(data):
    recipient = data['to']
    encrypted_aes_key = data['encryptedAesKey']
    sender = data['from']
    
    if recipient in user_keys:
        private_key = user_keys[recipient]['private_key']
        decrypted_key_data = decrypt_with_rsa(private_key, encrypted_aes_key)
        aes_key, aes_iv = json.loads(decrypted_key_data)
        
        emit('aes_key_exchange', {
            'from': sender,
            'encryptedAesKey': encrypted_aes_key
        }, room=request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    recipient = data['to']
    encrypted_message = data['message']
    sender = data['from']
    
    emit('encrypted_message', {
        'from': sender,
        'message': encrypted_message
    }, room=recipient)

if __name__ == '__main__':
    socketio.run(app, debug=True)
