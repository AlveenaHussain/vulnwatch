"""
Scan ingestion endpoint for VulnWatch.

A collector sends structured Nmap results as JSON. This endpoint validates
them with Pydantic and upserts them into the scans, assets and services
tables in ONE database transaction (all rows are saved, or none are).
"""

import logging
from typing import Literal

import psycopg
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, IPvAnyAddress

from database import get_connection
from security import require_api_key

logger = logging.getLogger("vulnwatch")

router = APIRouter(prefix="/api/v1", tags=["ingestion"])

MAC_PATTERN = r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$"

NmapState = Literal[
    "open", "closed", "filtered", "unfiltered", "open|filtered", "closed|filtered"
]


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------
class StrictModel(BaseModel):
    """Reject unknown fields instead of silently ignoring them."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ScanInfo(StrictModel):
    started_at: AwareDatetime  # must include a timezone, e.g. +05:30
    target: str = Field(min_length=1, max_length=255)
    nmap_command: str = Field(min_length=1, max_length=2000)
    scanner_ip: IPvAnyAddress


class ServiceIn(StrictModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    state: NmapState
    service_name: str | None = Field(default=None, max_length=100)
    product: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    cpe: str | None = Field(default=None, max_length=500)


class HostIn(StrictModel):
    ip_address: IPvAnyAddress
    mac_address: str | None = Field(default=None, pattern=MAC_PATTERN)
    hostname: str | None = Field(default=None, max_length=255)
    os: str | None = Field(default=None, max_length=255)
    os_accuracy: int | None = Field(default=None, ge=0, le=100)
    services: list[ServiceIn] = Field(default_factory=list, max_length=10000)


class ScanImportRequest(StrictModel):
    scan: ScanInfo
    hosts: list[HostIn] = Field(min_length=1, max_length=1024)


class ScanImportResponse(BaseModel):
    scan_id: int
    hosts_processed: int
    assets_created: int
    assets_updated: int
    services_created: int
    services_updated: int


# ---------------------------------------------------------------------------
# SQL (parameterised - user data is NEVER pasted into the SQL text)
# ---------------------------------------------------------------------------
INSERT_SCAN = """
    INSERT INTO scans (started_at, target, nmap_command, scanner_ip)
    VALUES (%(started_at)s, %(target)s, %(nmap_command)s, %(scanner_ip)s)
    RETURNING id
"""

UPSERT_ASSET = """
    INSERT INTO assets (ip_address, mac_address, hostname, os, os_accuracy,
                        first_seen, last_seen)
    VALUES (%(ip)s, %(mac)s, %(hostname)s, %(os)s, %(os_accuracy)s,
            %(seen)s, %(seen)s)
    ON CONFLICT (ip_address) DO UPDATE SET
        mac_address = COALESCE(EXCLUDED.mac_address, assets.mac_address),
        hostname    = COALESCE(EXCLUDED.hostname, assets.hostname),
        os          = COALESCE(EXCLUDED.os, assets.os),
        os_accuracy = CASE WHEN EXCLUDED.os IS NOT NULL
                           THEN EXCLUDED.os_accuracy
                           ELSE assets.os_accuracy END,
        first_seen  = LEAST(assets.first_seen, EXCLUDED.first_seen),
        last_seen   = GREATEST(assets.last_seen, EXCLUDED.last_seen)
    RETURNING id, (xmax = 0) AS inserted
"""

UPSERT_SERVICE = """
    INSERT INTO services (asset_id, port, protocol, service_name, product,
                          version, cpe, state, first_seen, last_seen, last_scan_id)
    VALUES (%(asset_id)s, %(port)s, %(protocol)s, %(service_name)s, %(product)s,
            %(version)s, %(cpe)s, %(state)s, %(seen)s, %(seen)s, %(scan_id)s)
    ON CONFLICT (asset_id, port, protocol) DO UPDATE SET
        service_name = EXCLUDED.service_name,
        product      = EXCLUDED.product,
        version      = EXCLUDED.version,
        cpe          = EXCLUDED.cpe,
        state        = EXCLUDED.state,
        first_seen   = LEAST(services.first_seen, EXCLUDED.first_seen),
        last_seen    = GREATEST(services.last_seen, EXCLUDED.last_seen),
        last_scan_id = EXCLUDED.last_scan_id
    RETURNING (xmax = 0) AS inserted
"""


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------
@router.post(
    "/scans/import",
    response_model=ScanImportResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
    summary="Import Nmap scan results (requires X-API-Key)",
)
def import_scan(payload: ScanImportRequest) -> ScanImportResponse:
    seen = payload.scan.started_at
    counts = {
        "assets_created": 0,
        "assets_updated": 0,
        "services_created": 0,
        "services_updated": 0,
    }

    try:
        # Leaving this block normally COMMITS; any exception ROLLS BACK everything.
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    INSERT_SCAN,
                    {
                        "started_at": seen,
                        "target": payload.scan.target,
                        "nmap_command": payload.scan.nmap_command,
                        "scanner_ip": str(payload.scan.scanner_ip),
                    },
                )
                scan_id = cur.fetchone()[0]

                for host in payload.hosts:
                    cur.execute(
                        UPSERT_ASSET,
                        {
                            "ip": str(host.ip_address),
                            "mac": host.mac_address,
                            "hostname": host.hostname,
                            "os": host.os,
                            "os_accuracy": host.os_accuracy,
                            "seen": seen,
                        },
                    )
                    asset_id, asset_inserted = cur.fetchone()
                    counts["assets_created" if asset_inserted else "assets_updated"] += 1

                    for svc in host.services:
                        cur.execute(
                            UPSERT_SERVICE,
                            {
                                "asset_id": asset_id,
                                "port": svc.port,
                                "protocol": svc.protocol,
                                "service_name": svc.service_name,
                                "product": svc.product,
                                "version": svc.version,
                                "cpe": svc.cpe,
                                "state": svc.state,
                                "seen": seen,
                                "scan_id": scan_id,
                            },
                        )
                        (svc_inserted,) = cur.fetchone()
                        counts["services_created" if svc_inserted else "services_updated"] += 1

    except psycopg.IntegrityError:
        # Data passed Pydantic but broke a database rule (CHECK/UNIQUE/FK).
        logger.exception("Scan import rejected by database constraints")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scan data violates database constraints",
        )
    except (psycopg.Error, RuntimeError):
        # Details go to server logs only - never to the client.
        logger.exception("Scan import failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

    return ScanImportResponse(
        scan_id=scan_id, hosts_processed=len(payload.hosts), **counts
    )
