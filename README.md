# SecureWipe Service

A FastAPI-based backend for secure drive wiping, certificate generation, and health prediction.

## Features

- Securely wipes folders and generates tamper-proof certificates
- Digital signing and PDF generation of certificates
- Predicts drive health using ML models
- REST API endpoints for all operations

## API Endpoints

- `POST /api/wipe` — Wipe a folder and generate certificate
- `GET /api/certificates/{cert_id}` — Get certificate JSON
- `GET /api/certificates/{cert_id}/pdf` — Get signed certificate PDF
- `POST /api/verify-cert` — Verify certificate JSON
- `POST /api/verify-pdf` — Verify signed PDF
- `POST /api/drive/health` — Predict drive health

## Setup

1. Clone the repository:
   ```sh
   git clone <your-repo-url>
   cd uservice
   ```
2. Create and activate a Python virtual environment:
   ```sh
   python -m venv venv
   venv\Scripts\activate
   ```
3. Install dependencies:

   ```sh
   pip install -r requirements.txt
   ```

4. Place your ML models in `models/` and keys in `keys/`.

## Generating ECDSA Keys

The service requires ECDSA private and public keys in the `keys/` directory. You can generate them using Python or OpenSSL:

### Using Python (recommended)

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

key = ec.generate_private_key(ec.SECP256R1())
with open("keys/private_key.pem", "wb") as f:
   f.write(key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption(),
   ))
with open("keys/public_key.pem", "wb") as f:
   f.write(key.public_key().public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo,
   ))
```

### Using OpenSSL

````sh

for private_key.pem
openssl ecparam -name prime256v1 -genkey -noout -out keys/private_key.pem

for certificate.pem
openssl req -x509 -newkey rsa:2048 -nodes \
-keyout keys/private_key.pem \
-out keys/certificate.pem \
-days 365 \
-subj "/CN=SecureWipe/O=MyOrg"```

## Deployment

- Run the FastAPI server:
  ```sh
  uvicorn app.main:app --reload
````

- For production, use a process manager (e.g., Gunicorn) and configure HTTPS.

## Notes

- Certificates and signed PDFs are stored in the `certificates/` folder.
- Logs are written to `logs/wipe_logs.jsonl`.
- Sensitive files (keys, models, logs) are excluded from git via `.gitignore`.

## License

MIT
