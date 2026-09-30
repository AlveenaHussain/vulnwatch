"""
Investigation APIs for VulnWatch.

Phase 13:
- Build a complete investigation view from an existing correlation
- Include correlated alert
- Include affected asset
- Include related services
- Include vulnerability
- Include finding
- Include security events as timeline/evidence

Phase 15:
- Protect investigation data with API key authentication
"""

import logging

from fastapi import APIRouter, HTTPException, Security

from database import get_connection
from security import require_api_key


logger = logging.getLogger("vulnwatch")


router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["Investigations"],
)


@router.get(
    "/{correlation_id}",
)
def get_investigation(
    correlation_id: int,
    _: None = Security(require_api_key),
):
    """
    Return a complete investigation view for one correlation.

    Investigation chain:

    Correlation
        -> Alert
        -> Asset
        -> Service Vulnerability
        -> Vulnerability
        -> Finding
        -> Security Events
        -> Related Services
    """

    with get_connection() as conn:
        with conn.cursor() as cur:

            # ---------------------------------------------------------
            # 1. Load correlation + alert + asset + vulnerability
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT
                    c.id,
                    c.asset_id,
                    c.alert_id,
                    c.service_vulnerability_id,
                    c.finding_id,
                    c.correlation_type,
                    c.priority,
                    c.title,
                    c.description,
                    c.created_at,

                    a.ip_address::text,
                    a.hostname,
                    NULL::text AS mac_address,
                    NULL::text AS os_name,
                    a.first_seen,
                    a.last_seen,

                    al.alert_type,
                    al.severity,
                    al.status,
                    al.source_ip::text,
                    al.destination_ip::text,
                    al.title,
                    al.description,
                    al.event_count,
                    al.first_seen,
                    al.last_seen,
                    al.created_at,

                    v.id,
                    v.cve_id,
                    v.cve_id AS title,
                    v.description,
                    v.severity,
                    v.cvss_score,
                    v.cvss_vector,
                    v.cwe,
                    NULL::text AS remediation,

                    f.id,
                    f.severity,
                    f.risk_score,
                    f.status,
                    f.title,
                    f.description,
                    f.remediation,
                    f.first_seen,
                    f.last_seen,
                    f.resolved_at

                FROM correlations c

                JOIN assets a
                    ON a.id = c.asset_id

                JOIN alerts al
                    ON al.id = c.alert_id

                LEFT JOIN service_vulnerabilities sv
                    ON sv.id = c.service_vulnerability_id

                LEFT JOIN vulnerabilities v
                    ON v.id = sv.vulnerability_id

                LEFT JOIN findings f
                    ON f.id = c.finding_id

                WHERE c.id = %(correlation_id)s
                LIMIT 1;
                """,
                {
                    "correlation_id": correlation_id,
                },
            )

            row = cur.fetchone()

            if not row:
                raise HTTPException(
                    status_code=404,
                    detail="Investigation correlation not found",
                )

            # ---------------------------------------------------------
            # 2. Load services belonging to the affected asset
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT
                    s.id,
                    s.port,
                    s.protocol,
                    s.service_name,
                    s.product,
                    s.version,
                    s.state,
                    s.first_seen,
                    s.last_seen
                FROM services s
                WHERE s.asset_id = %(asset_id)s
                ORDER BY s.port, s.protocol;
                """,
                {
                    "asset_id": row[1],
                },
            )

            service_rows = cur.fetchall()

            # ---------------------------------------------------------
            # 3. Load security events for the affected asset
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT
                    id,
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
                WHERE asset_id = %(asset_id)s
                   OR destination_ip = %(asset_ip)s::inet
                ORDER BY event_time DESC, id DESC
                LIMIT 500;
                """,
                {
                    "asset_id": row[1],
                    "asset_ip": row[10],
                },
            )

            event_rows = cur.fetchall()

    # -------------------------------------------------------------
    # Build services response
    # -------------------------------------------------------------
    services = []

    for service in service_rows:
        services.append(
            {
                "id": service[0],
                "port": service[1],
                "protocol": service[2],
                "service_name": service[3],
                "product": service[4],
                "version": service[5],
                "state": service[6],
                "first_seen": service[7],
                "last_seen": service[8],
            }
        )

    # -------------------------------------------------------------
    # Build security events response
    # -------------------------------------------------------------
    events = []

    for event in event_rows:
        events.append(
            {
                "id": event[0],
                "event_type": event[1],
                "event_time": event[2],
                "source_ip": event[3],
                "destination_ip": event[4],
                "protocol": event[5],
                "source_port": event[6],
                "destination_port": event[7],
                "username": event[8],
                "severity": event[9],
                "raw_log": event[10],
                "source": event[11],
                "created_at": event[12],
            }
        )

    # -------------------------------------------------------------
    # Final investigation response
    # -------------------------------------------------------------
    return {
        "correlation": {
            "id": row[0],
            "asset_id": row[1],
            "alert_id": row[2],
            "service_vulnerability_id": row[3],
            "finding_id": row[4],
            "correlation_type": row[5],
            "priority": row[6],
            "title": row[7],
            "description": row[8],
            "created_at": row[9],
        },
        "asset": {
            "id": row[1],
            "ip_address": row[10],
            "hostname": row[11],
            "mac_address": row[12],
            "os_name": row[13],
            "first_seen": row[14],
            "last_seen": row[15],
        },
        "alert": {
            "id": row[2],
            "alert_type": row[16],
            "severity": row[17],
            "status": row[18],
            "source_ip": row[19],
            "destination_ip": row[20],
            "title": row[21],
            "description": row[22],
            "event_count": row[23],
            "first_seen": row[24],
            "last_seen": row[25],
            "created_at": row[26],
        },
        "vulnerability": (
            {
                "id": row[27],
                "cve_id": row[28],
                "title": row[29],
                "description": row[30],
                "severity": row[31],
                "cvss_score": (
                    float(row[32])
                    if row[32] is not None
                    else None
                ),
                "cvss_vector": row[33],
                "cwe_id": row[34],
                "remediation": row[35],
            }
            if row[27] is not None
            else None
        ),
        "finding": (
            {
                "id": row[36],
                "severity": row[37],
                "risk_score": row[38],
                "status": row[39],
                "title": row[40],
                "description": row[41],
                "remediation": row[42],
                "first_seen": row[43],
                "last_seen": row[44],
                "resolved_at": row[45],
            }
            if row[36] is not None
            else None
        ),
        "services": services,
        "events": events,
        "timeline": events,
        "evidence": [
            {
                "event_id": event["id"],
                "source": event["source"],
                "event_type": event["event_type"],
                "event_time": event["event_time"],
                "raw_log": event["raw_log"],
            }
            for event in events
            if event["raw_log"]
        ],
    }