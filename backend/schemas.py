from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    os: str | None = None
    os_accuracy: int | None = None
    first_seen: datetime
    last_seen: datetime


class ServiceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_id: int
    port: int
    protocol: str
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    cpe: str | None = None
    state: str
    first_seen: datetime
    last_seen: datetime
    last_scan_id: int | None = None


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    started_at: datetime
    target: str
    nmap_command: str
    scanner_ip: str | None = None
    created_at: datetime