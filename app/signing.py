import base64, json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from .config import KEY_DIR

PRIV_PEM = KEY_DIR / "private_key.pem"
PUB_PEM = KEY_DIR / "public_key.pem"

def ensure_keys():
    if not PRIV_PEM.exists():
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
    return {"payload": payload, "signature": base64.b64encode(sig).decode()}

def verify_payload(signed: dict) -> bool:
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
