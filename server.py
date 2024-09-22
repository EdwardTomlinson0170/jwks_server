# server.py

from flask import Flask, jsonify, request, make_response
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt
import datetime
import uuid
from key_generation import generate_rsa_key_pair, KEYS

app = Flask(__name__)
PORT = 8080

# Generate initial RSA keys
kid = str(uuid.uuid4())
private_pem, public_pem = generate_rsa_key_pair(kid)

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    keys = []
    for kid, key_data in KEYS.items():
        if key_data['expiry'] > datetime.datetime.utcnow():
            public_key = serialization.load_pem_public_key(key_data['public_key'], backend=default_backend())
            public_numbers = public_key.public_numbers()
            jwk = {
                'kid': kid,
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big').hex(),
                'e': public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big').hex(),
            }
            keys.append(jwk)
    return jsonify({'keys': keys})

@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    if not data or 'username' not in data or 'password' not in data:
        return make_response(jsonify({'message': 'Invalid request'}), 400)

    expired = request.args.get('expired', 'false').lower() == 'true'

    if expired:
        expired_kid = next((k for k, v in KEYS.items() if v['expiry'] < datetime.datetime.utcnow()), None)
        if not expired_kid:
            return make_response(jsonify({'message': 'No expired keys available'}), 400)
        kid = expired_kid
    else:
        kid = next((k for k, v in KEYS.items() if v['expiry'] > datetime.datetime.utcnow()), None)
        if not kid:
            kid = str(uuid.uuid4())
            private_pem, public_pem = generate_rsa_key_pair(kid)

    private_key = serialization.load_pem_private_key(KEYS[kid]['private_key'], password=None, backend=default_backend())

    token = jwt.encode(
        {
            'sub': data['username'],
            'iat': datetime.datetime.utcnow(),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30 if not expired else -30),
        },
        private_key,
        algorithm='RS256',
        headers={'kid': kid},
    )

    return jsonify({'token': token})

if __name__ == '__main__':
    app.run(port=PORT)
