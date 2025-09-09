import os
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography import x509

from dotenv import load_dotenv

load_dotenv()


def get_private_key():
    priv_data = os.getenv("PRIVATE_KEY_PEM")
    if not priv_data:
        raise RuntimeError("Missing PRIVATE_KEY_PEM environment variable")

    key = serialization.load_pem_private_key(priv_data.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("Loaded private key is not an EC key.")
    return key


def get_cert_public_key():
    cert_data = os.getenv("CERTIFICATE_PEM")
    if not cert_data:
        raise RuntimeError("Missing CERTIFICATE_PEM environment variable")
    cert = x509.load_pem_x509_certificate(cert_data.encode())
    return cert.public_key()


def sign_payload(payload: dict) -> dict:
    """Sign a JSON payload with private ECDSA key and return payload + signature."""
    key = get_private_key()
    data = json.dumps(payload, sort_keys=True).encode()
    sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    return {
        "payload": payload,
        "signature": base64.b64encode(sig).decode(),
    }


def verify_payload(signed: dict) -> bool:
    """Verify a signed payload using the cert's public key."""
    pub = get_cert_public_key()
    data = json.dumps(signed["payload"], sort_keys=True).encode()
    sig = base64.b64decode(signed["signature"])
    try:
        pub.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
