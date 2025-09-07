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


def ensure_keys():
    """Ensure private/public keypair exists (env or local)."""
    priv_data = os.getenv("PRIVATE_KEY_PEM")
    pub_data = os.getenv("PUBLIC_KEY_PEM")

    if priv_data and pub_data:
        # Write secrets from env vars
        PRIV_PEM.write_text(priv_data)
        PUB_PEM.write_text(pub_data)
    elif not PRIV_PEM.exists() or not PUB_PEM.exists():
        # Generate new keypair
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


def sign_payload(payload: dict) -> dict:
    """Sign a JSON payload with private key and return payload + signature."""
    ensure_keys()
    with open(PRIV_PEM, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)

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
    with open(PUB_PEM, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

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
