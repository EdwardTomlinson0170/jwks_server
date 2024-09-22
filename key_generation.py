# key_generation.py

import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEYS = {}


def generate_rsa_key_pair(kid, expiry_minutes=30):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    expiry_time = (datetime.datetime.utcnow() + 
                   datetime.timedelta(minutes=expiry_minutes))
    KEYS[kid] = {
        'private_key': private_pem,
        'public_key': public_pem,
        'expiry': expiry_time,
    }

    return private_pem, public_pem
