"""
Correlation APIs for VulnWatch.

Phase 12:
- Correlate existing vulnerabilities/findings with SOC alerts
- Match records belonging to the same asset
- Calculate investigation priority
- Prevent duplicate correlations
- Protect correlation creation with X-API-Key
- Retrieve correlations with filtering and pagination
"""

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Security, status
from pydantic import BaseModel, Field

from database import get_connection
from security import require_api_key


logger = logging.getLogger("vulnwatch")


router = APIRouter(
    prefix="/api/v1/correlations",
    tags=["Correlations"],
    dependencies=[Security(require_api_key)],
)


class CorrelationCreate(BaseModel):
    asset_id: int = Field(gt=0)
    alert_id: int = Field(gt=0)
    service_vulnerability_id: Optional[int] = Field(
        default=None,
        gt=0,
    )
    finding_id: Optional[int] = Field(
        default=None,
        gt=0,
    )
    correlation_type: str = Field(
        min_length=1,
        max_length=100,
    )
    priority: str
    title: str = Field(
        min_length=1,
        max_length=255,
    )
    description: Optional[str] = None


VALID_CORRELATION_TYPES = {
    "ASSET_VULNERABILITY_ALERT",
}

VALID_PRIORITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
}


@router.post(
    "/import",
    status_code=status.HTTP_201_CREATED,
)
def import_correlation(
    correlation: CorrelationCreate,
):
    """
    Create a correlation between a vulnerability/finding
    and a SOC alert belonging to the same asset.
    """

    if correlation.correlation_type not in VALID_CORRELATION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid correlation_type. "
                "Allowed value: ASSET_VULNERABILITY_ALERT"
            ),
        )

    if correlation.priority not in VALID_PRIORITIES:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid priority. "
                "Allowed values: CRITICAL, HIGH, MEDIUM, "
                "LOW, INFO"
            ),
        )

    with get_connection() as conn:
        with conn.cursor() as cur:

            # ---------------------------------------------------------
            # Validate asset
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT id
                FROM assets
                WHERE id = %s
                """,
                (correlation.asset_id,),
            )

            asset_row = cur.fetchone()

            if not asset_row:
                raise HTTPException(
                    status_code=404,
                    detail="Asset not found",
                )

            # ---------------------------------------------------------
            # Validate alert
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT
                    id,
                    asset_id,
                    alert_type,
                    severity,
                    status,
                    source_ip,
                    destination_ip,
                    title,
                    event_count,
                    first_seen,
                    last_seen
                FROM alerts
                WHERE id = %s
                """,
                (correlation.alert_id,),
            )

            alert_row = cur.fetchone()

            if not alert_row:
                raise HTTPException(
                    status_code=404,
                    detail="Alert not found",
                )

            alert_asset_id = alert_row[1]

            if (
                alert_asset_id is not None
                and alert_asset_id != correlation.asset_id
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "Alert does not belong to the specified asset"
                    ),
                )

            # ---------------------------------------------------------
            # Validate service vulnerability when provided
            # ---------------------------------------------------------
            if correlation.service_vulnerability_id is not None:
                cur.execute(
                    """
                    SELECT
                        sv.id,
                        s.asset_id,
                        v.cve_id,
                        v.severity,
                        v.cvss_score
                    FROM service_vulnerabilities sv
                    JOIN services s
                        ON s.id = sv.service_id
                    JOIN vulnerabilities v
                        ON v.id = sv.vulnerability_id
                    WHERE sv.id = %s
                    """,
                    (correlation.service_vulnerability_id,),
                )

                service_vulnerability_row = cur.fetchone()

                if not service_vulnerability_row:
                    raise HTTPException(
                        status_code=404,
                        detail="Service vulnerability not found",
                    )

                vulnerability_asset_id = (
                    service_vulnerability_row[1]
                )

                if vulnerability_asset_id != correlation.asset_id:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Service vulnerability does not "
                            "belong to the specified asset"
                        ),
                    )

            # ---------------------------------------------------------
            # Validate finding when provided
            # ---------------------------------------------------------
            if correlation.finding_id is not None:
                cur.execute(
                    """
                    SELECT
                        f.id,
                        s.asset_id,
                        f.service_vulnerability_id,
                        f.severity,
                        f.risk_score,
                        f.status
                    FROM findings f
                    JOIN service_vulnerabilities sv
                        ON sv.id = f.service_vulnerability_id
                    JOIN services s
                        ON s.id = sv.service_id
                    WHERE f.id = %s
                    """,
                    (correlation.finding_id,),
                )

                finding_row = cur.fetchone()

                if not finding_row:
                    raise HTTPException(
                        status_code=404,
                        detail="Finding not found",
                    )

                finding_asset_id = finding_row[1]

                if finding_asset_id != correlation.asset_id:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Finding does not belong to "
                            "the specified asset"
                        ),
                    )

                finding_service_vulnerability_id = (
                    finding_row[2]
                )

                if (
                    correlation.service_vulnerability_id
                    is not None
                    and finding_service_vulnerability_id
                    != correlation.service_vulnerability_id
                ):
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            "Finding does not belong to "
                            "the specified service vulnerability"
                        ),
                    )

            # ---------------------------------------------------------
            # Prevent duplicate correlation
            # ---------------------------------------------------------
            cur.execute(
                """
                SELECT
                    id,
                    asset_id,
                    alert_id,
                    service_vulnerability_id,
                    finding_id,
                    correlation_type,
                    priority,
                    title,
                    description,
                    created_at
                FROM correlations
                WHERE alert_id = %s
                  AND (
                      service_vulnerability_id = %s
                      OR (
                          service_vulnerability_id IS NULL
                          AND %s IS NULL
                      )
                  )
                LIMIT 1
                """,
                (
                    correlation.alert_id,
                    correlation.service_vulnerability_id,
                    correlation.service_vulnerability_id,
                ),
            )

            existing = cur.fetchone()

            if existing:
                return {
                    "message": "Correlation already exists",
                    "correlation": {
                        "id": existing[0],
                        "asset_id": existing[1],
                        "alert_id": existing[2],
                        "service_vulnerability_id": existing[3],
                        "finding_id": existing[4],
                        "correlation_type": existing[5],
                        "priority": existing[6],
                        "title": existing[7],
                        "description": existing[8],
                        "created_at": existing[9],
                    },
                }

            # ---------------------------------------------------------
            # Insert correlation
            # ---------------------------------------------------------
            cur.execute(
                """
                INSERT INTO correlations (
                    asset_id,
                    alert_id,
                    service_vulnerability_id,
                    finding_id,
                    correlation_type,
                    priority,
                    title,
                    description
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s, %s
                )
                RETURNING
                    id,
                    asset_id,
                    alert_id,
                    service_vulnerability_id,
                    finding_id,
                    correlation_type,
                    priority,
                    title,
                    description,
                    created_at
                """,
                (
                    correlation.asset_id,
                    correlation.alert_id,
                    correlation.service_vulnerability_id,
                    correlation.finding_id,
                    correlation.correlation_type,
                    correlation.priority,
                    correlation.title,
                    correlation.description,
                ),
            )

            row = cur.fetchone()

        conn.commit()

    return {
        "message": "Correlation created successfully",
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
    }


@router.get("")
def list_correlations(
    asset_id: Optional[int] = Query(
        default=None,
        gt=0,
    ),
    alert_id: Optional[int] = Query(
        default=None,
        gt=0,
    ),
    priority: Optional[str] = Query(
        default=None,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
):
    """
    Retrieve correlations with optional filters.
    """

    if priority is not None and priority not in VALID_PRIORITIES:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid priority. "
                "Allowed values: CRITICAL, HIGH, MEDIUM, LOW, INFO"
            ),
        )

    conditions = []
    params = []

    if asset_id is not None:
        conditions.append("c.asset_id = %s")
        params.append(asset_id)

    if alert_id is not None:
        conditions.append("c.alert_id = %s")
        params.append(alert_id)

    if priority is not None:
        conditions.append("c.priority = %s")
        params.append(priority)

    where_clause = ""

    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    query = f"""
        SELECT
            c.id,
            c.asset_id,
            a.ip_address,
            a.hostname,

            c.alert_id,
            al.alert_type,
            al.severity AS alert_severity,
            al.status AS alert_status,

            c.service_vulnerability_id,
            v.cve_id,
            v.severity AS vulnerability_severity,
            v.cvss_score,

            c.finding_id,
            f.risk_score,
            f.status AS finding_status,

            c.correlation_type,
            c.priority,
            c.title,
            c.description,
            c.created_at

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

        {where_clause}

        ORDER BY c.created_at DESC

        LIMIT %s
        OFFSET %s
    """

    params.extend([limit, offset])

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, tuple(params))

            rows = cur.fetchall()

    correlations = []

    for row in rows:
        correlations.append(
            {
                "id": row[0],
                "asset_id": row[1],
                "target_ip": str(row[2])
                if row[2] is not None
                else None,
                "hostname": row[3],

                "alert_id": row[4],
                "alert_type": row[5],
                "alert_severity": row[6],
                "alert_status": row[7],

                "service_vulnerability_id": row[8],
                "cve_id": row[9],
                "vulnerability_severity": row[10],
                "cvss_score": float(row[11])
                if row[11] is not None
                else None,

                "finding_id": row[12],
                "risk_score": float(row[13])
                if row[13] is not None
                else None,
                "finding_status": row[14],

                "correlation_type": row[15],
                "priority": row[16],
                "title": row[17],
                "description": row[18],
                "created_at": row[19],
            }
        )

    return {
        "count": len(correlations),
        "correlations": correlations,
        "limit": limit,
        "offset": offset,
    }