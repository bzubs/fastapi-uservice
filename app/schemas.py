from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class Device(BaseModel):
    id: str
    model: str
    firmware: str
    capacity_gb: int

class WipeRequest(BaseModel):
    device: Device
    dev_path: str
    method: Optional[str] = "zero-fill-1pass"
    policy: Optional[str] = "NIST SP 800-88"
    user_id: str
    username: str
    
class DriveHealthInput(BaseModel):
    drive_id: str

class Wipe(BaseModel):
    method: str
    policy: str
    started_at: datetime
    completed_at: datetime
    result: str
    log_hash: str


class Issuer(BaseModel):
    org: str
    signing_key_id: str


class Payload(BaseModel):
    certificate_id: str
    user_id: str
    username: Optional[str] = None
    device: Device
    wipe: Wipe
    issuer: Issuer
 

class GenerateRequest(BaseModel):
    payload: Payload
    signature: str    