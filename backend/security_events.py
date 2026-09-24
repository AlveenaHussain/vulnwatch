"""
Security event ingestion and retrieval APIs for VulnWatch.

Phase 10:
- Accept normalized SOC/security events
- Automatically link events to known assets
- Prevent duplicate events
- Store them in PostgreSQL
- Protect write access with X-API-Key
- Retrieve events with filtering and pagination
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Security, status
from pydantic import BaseModel, Field

from database import get_connection
from security import require_api_key

logger = logging.getLogger("vulnwatch")

router = APIRouter(
    prefix="/api/v1/security-events",
    tags=["Security Events"],
)


class SecurityEventCreate(BaseModel):
    asset_id: Optional[int] = None
    event_type: str = Field(min_length=1, max_length=100)
    event_time: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = Field(default=None, ge=1, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = None
    severity: str = "LOW"
    raw_log: Optional[str] = None
    source: str = "lab-log"


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_security_event(
    event: SecurityEventCreate,
    _: None = Security(require_api_key),
):
    allowed_severities = {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
        "UNKNOWN",
    }

    severity = event.severity.upper()

    if severity not in allowed_severities:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid severity. Use one of: "
                "CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN"
            ),
        )

    with get_connection() as conn:
        with conn.cursor() as cur:

            # ---------------------------------------------------------
            # 1. Automatically find the asset using destination IP
            # ---------------------------------------------------------
            asset_id = event.asset_id

            if asset_id is None and event.destination_ip:
                cur.execute(
                    """
                    SELECT id
                    FROM assets
                    WHERE ip_address = %(destination_ip)s::inet
                    LIMIT 1;
                    """,
                    {
                        "destination_ip": event.destination_ip,
                    },
                )

                asset_row = cur.fetchone()

                if asset_row:
                    asset_id = asset_row[0]

            # ---------------------------------------------------------
            # 2. Check whether this exact event already exists
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT id, created_at
                FROM security_events
                WHERE event_type = %(event_type)s
                  AND event_time = %(event_time)s
                  AND source_ip = %(source_ip)s::inet
                  AND destination_ip = %(destination_ip)s::inet
                  AND source_port IS NOT DISTINCT FROM %(source_port)s
                  AND destination_port IS NOT DISTINCT FROM %(destination_port)s
                  AND username IS NOT DISTINCT FROM %(username)s
                  AND raw_log IS NOT DISTINCT FROM %(raw_log)s
                LIMIT 1;
                """,
                {
                    "event_type": event.event_type,
                    "event_time": event.event_time,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "source_port": event.source_port,
                    "destination_port": event.destination_port,
                    "username": event.username,
                    "raw_log": event.raw_log,
                },
            )

            existing_row = cur.fetchone()

            # ---------------------------------------------------------
            # 3. If duplicate, return existing event instead of inserting
            # ---------------------------------------------------------
            if existing_row:
                logger.info(
                    "Duplicate security event ignored: id=%s event_type=%s",
                    existing_row[0],
                    event.event_type,
                )

                return {
                    "message": "Duplicate security event ignored",
                    "event": {
                        "id": existing_row[0],
                        "event_type": event.event_type,
                        "event_time": event.event_time,
                        "severity": severity,
                        "asset_id": asset_id,
                        "source": event.source,
                        "created_at": existing_row[1],
                    },
                }

            # ---------------------------------------------------------
            # 4. Insert new event
            # ---------------------------------------------------------
            cur.execute(
                """
                INSERT INTO security_events (
                    asset_id,
                    event_type,
                    event_time,
                    source_ip,
                    destination_ip,
                    protocol,
                    source_port,
                    destination_port,
                    username,
                    severity,
                    raw_log,
                    source
                )
                VALUES (
                    %(asset_id)s,
                    %(event_type)s,
                    %(event_time)s,
                    %(source_ip)s,
                    %(destination_ip)s,
                    %(protocol)s,
                    %(source_port)s,
                    %(destination_port)s,
                    %(username)s,
                    %(severity)s,
                    %(raw_log)s,
                    %(source)s
                )
                RETURNING id, created_at;
                """,
                {
                    "asset_id": asset_id,
                    "event_type": event.event_type,
                    "event_time": event.event_time,
                    "source_ip": event.source_ip,
                    "destination_ip": event.destination_ip,
                    "protocol": event.protocol,
                    "source_port": event.source_port,
                    "destination_port": event.destination_port,
                    "username": event.username,
                    "severity": severity,
                    "raw_log": event.raw_log,
                    "source": event.source,
                },
            )

            row = cur.fetchone()

    logger.info(
        "Security event imported: id=%s event_type=%s severity=%s asset_id=%s",
        row[0],
        event.event_type,
        severity,
        asset_id,
    )

    return {
        "message": "Security event imported successfully",
        "event": {
            "id": row[0],
            "event_type": event.event_type,
            "event_time": event.event_time,
            "severity": severity,
            "asset_id": asset_id,
            "source": event.source,
            "created_at": row[1],
        },
    }


@router.get("")
def list_security_events(
    source_ip: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    destination_ip: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """
    Retrieve security events with optional filtering and pagination.

    Results are ordered newest first.
    """

    filters = []
    params = {}

    if source_ip:
        filters.append("source_ip = %(source_ip)s")
        params["source_ip"] = source_ip

    if event_type:
        filters.append("event_type = %(event_type)s")
        params["event_type"] = event_type

    if destination_ip:
        filters.append("destination_ip = %(destination_ip)s")
        params["destination_ip"] = destination_ip

    if severity:
        normalized_severity = severity.upper()

        allowed_severities = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
            "UNKNOWN",
        }

        if normalized_severity not in allowed_severities:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Invalid severity. Use one of: "
                    "CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN"
                ),
            )

        filters.append("severity = %(severity)s")
        params["severity"] = normalized_severity

    where_clause = ""

    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    params["limit"] = limit
    params["offset"] = offset

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    id,
                    asset_id,
                    event_type,
                    event_time,
                    source_ip::text,
                    destination_ip::text,
                    protocol,
                    source_port,
                    destination_port,
                    username,
                    severity,
                    raw_log,
                    source,
                    created_at
                FROM security_events
                {where_clause}
                ORDER BY event_time DESC, id DESC
                LIMIT %(limit)s
                OFFSET %(offset)s;
                """,
                params,
            )

            rows = cur.fetchall()

    events = []

    for row in rows:
        events.append(
            {
                "id": row[0],
                "asset_id": row[1],
                "event_type": row[2],
                "event_time": row[3],
                "source_ip": row[4],
                "destination_ip": row[5],
                "protocol": row[6],
                "source_port": row[7],
                "destination_port": row[8],
                "username": row[9],
                "severity": row[10],
                "raw_log": row[11],
                "source": row[12],
                "created_at": row[13],
            }
        )

    return {
        "count": len(events),
        "limit": limit,
        "offset": offset,
        "events": events,
    }