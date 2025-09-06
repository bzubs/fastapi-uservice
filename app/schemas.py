from pydantic import BaseModel
from typing import Optional

class DeviceMeta(BaseModel):
    id: str
    model: str
    firmware: str
    capacity_gb: int

class WipeRequest(BaseModel):
    device: DeviceMeta
    dev_path: str
    method: Optional[str] = "zero-fill-1pass"
    user_id: str
    username: str
    

class DriveHealthInput(BaseModel):
    drive_id: str