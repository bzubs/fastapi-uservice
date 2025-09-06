from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = BASE_DIR / "logs"
CERT_DIR = BASE_DIR / "certificates"
KEY_DIR = BASE_DIR / "keys"
LEDGER_DB = BASE_DIR / "ledger.db"

WIPE_LOG = LOG_DIR / "wipe_logs.jsonl"

for d in [LOG_DIR, CERT_DIR, KEY_DIR]:
    d.mkdir(parents=True, exist_ok=True)
