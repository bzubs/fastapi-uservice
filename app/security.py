# security.py
import os
from fastapi import Security, HTTPException
from fastapi.security.api_key import APIKeyHeader

# Header name for internal token
API_KEY_NAME = "Bzubs--Token"

# Get the token from environment / Railway secrets
API_KEY = os.getenv("INTERNAL_SERVICE_TOKEN")

# FastAPI dependency
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def require_internal_api_key(api_key: str = Security(api_key_header)):
    if not API_KEY or api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
