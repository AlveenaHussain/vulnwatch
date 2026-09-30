from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """
    Base model for API input validation.

    Unknown fields are rejected instead of silently ignored,
    and surrounding whitespace is removed from string values.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )


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
    target_ip: str
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


class VulnerabilityImportItem(StrictModel):
    cve_id: str = Field(
        min_length=1,
        max_length=64,
    )

    description: str | None = Field(
        default=None,
        max_length=10000,
    )

    cvss_version: str | None = Field(
        default=None,
        max_length=32,
    )

    cvss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=10.0,
    )

    cvss_vector: str | None = Field(
        default=None,
        max_length=512,
    )

    cwe: str | None = Field(
        default=None,
        max_length=64,
    )

    published: datetime | None = None

    last_modified: datetime | None = None


class VulnerabilityFinding(StrictModel):
    target_ip: str = Field(
        min_length=1,
        max_length=64,
    )

    port: int = Field(
        ge=1,
        le=65535,
    )

    protocol: str = Field(
        min_length=1,
        max_length=16,
    )

    matched_cpe: str = Field(
        min_length=1,
        max_length=512,
    )

    vulnerabilities: list[VulnerabilityImportItem] = Field(
        max_length=1000,
    )


class VulnerabilityImportRequest(StrictModel):
    source: str = Field(
        min_length=1,
        max_length=100,
    )

    findings: list[VulnerabilityFinding] = Field(
        max_length=5000,
    )


class VulnerabilityImportResponse(BaseModel):
    vulnerabilities_created: int
    vulnerabilities_updated: int
    mappings_created: int
    mappings_updated: int
    services_not_found: int