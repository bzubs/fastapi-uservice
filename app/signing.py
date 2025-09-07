import os
import json
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature


# Key storage directory
KEY_DIR = Path("keys")
KEY_DIR.mkdir(parents=True, exist_ok=True)

PRIV_PEM = KEY_DIR / "private_key.pem"
PUB_PEM = KEY_DIR / "public_key.pem"



def get_private_key():
    priv_data = os.getenv("PRIVATE_KEY_PEM")
    key = None
    if priv_data:
        key = serialization.load_pem_private_key(priv_data.encode(), password=None)
    elif PRIV_PEM.exists():
        with open(PRIV_PEM, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        # Generate new key for local dev only
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIV_PEM, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        with open(PUB_PEM, "wb") as f:
            f.write(key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
    # Ensure key is RSA
    if not hasattr(key, 'sign') or not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Loaded private key is not an RSA key. Please check your environment variable or key file.")
    return key

def get_public_key():
    pub_data = os.getenv("PUBLIC_KEY_PEM")
    pub = None
    if pub_data:
        pub = serialization.load_pem_public_key(pub_data.encode())
    elif PUB_PEM.exists():
        with open(PUB_PEM, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
    else:
        pub = get_private_key().public_key()
    # Ensure key is RSA
    if not hasattr(pub, 'verify') or not isinstance(pub, rsa.RSAPublicKey):
        raise TypeError("Loaded public key is not an RSA key. Please check your environment variable or key file.")
    return pub



def sign_payload(payload: dict) -> dict:
    """Sign a JSON payload with private key and return payload + signature."""
    key = get_private_key()
    data = json.dumps(payload, sort_keys=True).encode()
    sig = key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return {
        "payload": payload,
        "signature": base64.b64encode(sig).decode()
    }



def verify_payload(signed: dict) -> bool:
    """Verify a signed payload using the stored public key."""
    pub = get_public_key()
    data = json.dumps(signed["payload"], sort_keys=True).encode()
    sig = base64.b64decode(signed["signature"])
    try:
        pub.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
