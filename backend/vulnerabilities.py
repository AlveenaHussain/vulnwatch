"""
Vulnerability ingestion endpoint for VulnWatch.

This module:
- imports vulnerability findings,
- derives severity from CVSS,
- calculates risk score from CVSS,
- maps vulnerabilities to discovered services,
- creates security findings,
- updates finding status and remediation.
"""

import logging

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from database import get_connection
from schemas import (
    VulnerabilityImportRequest,
    VulnerabilityImportResponse,
)
from security import require_api_key

logger = logging.getLogger("vulnwatch")

router = APIRouter(
    prefix="/api/v1",
    tags=["vulnerabilities"],
)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------
def derive_severity(score: float | None) -> str:
    """Derive severity from CVSS score."""
    if score is None:
        return "UNKNOWN"

    if score == 0.0:
        return "NONE"

    if 0.1 <= score <= 3.9:
        return "LOW"

    if 4.0 <= score <= 6.9:
        return "MEDIUM"

    if 7.0 <= score <= 8.9:
        return "HIGH"

    if 9.0 <= score <= 10.0:
        return "CRITICAL"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Risk calculation
# ---------------------------------------------------------------------------
def calculate_risk_score(cvss_score: float | None) -> float | None:
    """Calculate normalized risk score from CVSS."""
    if cvss_score is None:
        return None

    return round(
        max(0.0, min(float(cvss_score), 10.0)),
        2,
    )


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------
UPSERT_VULNERABILITY = """
    INSERT INTO vulnerabilities (
        cve_id,
        description,
        cvss_version,
        cvss_score,
        cvss_vector,
        severity,
        cwe,
        published,
        last_modified,
        nvd_synced_at
    )
    VALUES (
        %(cve_id)s,
        %(description)s,
        %(cvss_version)s,
        %(cvss_score)s,
        %(cvss_vector)s,
        %(severity)s,
        %(cwe)s,
        %(published)s,
        %(last_modified)s,
        NOW()
    )
    ON CONFLICT (cve_id) DO UPDATE SET
        description   = EXCLUDED.description,
        cvss_version  = EXCLUDED.cvss_version,
        cvss_score    = EXCLUDED.cvss_score,
        cvss_vector   = EXCLUDED.cvss_vector,
        severity      = EXCLUDED.severity,
        cwe           = EXCLUDED.cwe,
        published     = EXCLUDED.published,
        last_modified = EXCLUDED.last_modified,
        nvd_synced_at = NOW()
    RETURNING id, (xmax = 0) AS inserted
"""


FIND_SERVICE = """
    SELECT s.id
    FROM services s
    JOIN assets a
        ON a.id = s.asset_id
    WHERE a.ip_address = %(target_ip)s
      AND s.port = %(port)s
      AND s.protocol = %(protocol)s
"""


UPSERT_MAPPING = """
    INSERT INTO service_vulnerabilities (
        service_id,
        vulnerability_id,
        matched_cpe,
        match_source,
        first_seen,
        last_seen
    )
    VALUES (
        %(service_id)s,
        %(vulnerability_id)s,
        %(matched_cpe)s,
        'nvd-cpe',
        NOW(),
        NOW()
    )
    ON CONFLICT (service_id, vulnerability_id) DO UPDATE SET
        matched_cpe = EXCLUDED.matched_cpe,
        match_source = EXCLUDED.match_source,
        last_seen = NOW()
    RETURNING (xmax = 0) AS inserted
"""


# ---------------------------------------------------------------------------
# Import vulnerabilities
# ---------------------------------------------------------------------------
@router.post(
    "/vulnerabilities/import",
    response_model=VulnerabilityImportResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
    summary="Import NVD vulnerability findings (requires X-API-Key)",
)
def import_vulnerabilities(
    payload: VulnerabilityImportRequest,
) -> VulnerabilityImportResponse:

    counts = {
        "vulnerabilities_created": 0,
        "vulnerabilities_updated": 0,
        "mappings_created": 0,
        "mappings_updated": 0,
        "services_not_found": 0,
    }

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                for finding in payload.findings:

                    cur.execute(
                        FIND_SERVICE,
                        {
                            "target_ip": finding.target_ip,
                            "port": finding.port,
                            "protocol": finding.protocol,
                        },
                    )

                    service_row = cur.fetchone()

                    if service_row is None:
                        counts["services_not_found"] += 1
                        continue

                    service_id = service_row[0]

                    for vulnerability in finding.vulnerabilities:

                        severity = derive_severity(
                            vulnerability.cvss_score
                        )

                        cur.execute(
                            UPSERT_VULNERABILITY,
                            {
                                "cve_id": vulnerability.cve_id,
                                "description": vulnerability.description,
                                "cvss_version": vulnerability.cvss_version,
                                "cvss_score": vulnerability.cvss_score,
                                "cvss_vector": vulnerability.cvss_vector,
                                "severity": severity,
                                "cwe": vulnerability.cwe,
                                "published": vulnerability.published,
                                "last_modified": vulnerability.last_modified,
                            },
                        )

                        vulnerability_id, vulnerability_inserted = (
                            cur.fetchone()
                        )

                        if vulnerability_inserted:
                            counts["vulnerabilities_created"] += 1
                        else:
                            counts["vulnerabilities_updated"] += 1

                        cur.execute(
                            UPSERT_MAPPING,
                            {
                                "service_id": service_id,
                                "vulnerability_id": vulnerability_id,
                                "matched_cpe": finding.matched_cpe,
                            },
                        )

                        (mapping_inserted,) = cur.fetchone()

                        if mapping_inserted:
                            counts["mappings_created"] += 1
                        else:
                            counts["mappings_updated"] += 1

    except psycopg.IntegrityError:
        logger.exception(
            "Vulnerability import rejected by database constraints"
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Vulnerability data violates database constraints",
        )

    except (psycopg.Error, RuntimeError):
        logger.exception("Vulnerability import failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

    return VulnerabilityImportResponse(**counts)


# ---------------------------------------------------------------------------
# Vulnerability list
# ---------------------------------------------------------------------------
@router.get(
    "/vulnerabilities",
    summary="List vulnerabilities",
)
def get_vulnerabilities(
    severity: str | None = Query(
        default=None,
        description=(
            "Filter by severity: "
            "CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN"
        ),
    ),
):
    severity_filter = ""
    params = []

    if severity:
        normalized_severity = severity.upper()

        allowed_severities = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "NONE",
            "UNKNOWN",
        }

        if normalized_severity not in allowed_severities:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Invalid severity. Use one of: "
                    "CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN"
                ),
            )

        severity_filter = "WHERE severity = %s"
        params.append(normalized_severity)

    query = f"""
        SELECT
            id,
            cve_id,
            description,
            cvss_version,
            cvss_score,
            cvss_vector,
            severity,
            cwe,
            published,
            last_modified,
            nvd_synced_at
        FROM vulnerabilities
        {severity_filter}
        ORDER BY cvss_score DESC NULLS LAST, cve_id;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

        return [
            {
                "id": row[0],
                "cve_id": row[1],
                "description": row[2],
                "cvss_version": row[3],
                "cvss_score": (
                    float(row[4]) if row[4] is not None else None
                ),
                "cvss_vector": row[5],
                "severity": row[6],
                "cwe": row[7],
                "published": row[8],
                "last_modified": row[9],
                "nvd_synced_at": row[10],
            }
            for row in rows
        ]

    except (psycopg.Error, RuntimeError):
        logger.exception("Failed to fetch vulnerabilities")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


# ---------------------------------------------------------------------------
# Service vulnerability mappings
# ---------------------------------------------------------------------------
@router.get(
    "/service-vulnerabilities",
    summary="List service vulnerability mappings",
)
def get_service_vulnerabilities():
    query = """
        SELECT
            sv.id,
            sv.service_id,
            a.ip_address::text AS target_ip,
            s.port,
            s.protocol,
            s.service_name,
            s.product,
            s.version,
            sv.vulnerability_id,
            v.cve_id,
            v.description,
            v.cvss_version,
            v.cvss_score,
            v.severity,
            v.cwe,
            sv.matched_cpe,
            sv.match_source,
            sv.first_seen,
            sv.last_seen
        FROM service_vulnerabilities sv
        JOIN services s
            ON s.id = sv.service_id
        JOIN assets a
            ON a.id = s.asset_id
        JOIN vulnerabilities v
            ON v.id = sv.vulnerability_id
        ORDER BY
            v.cvss_score DESC NULLS LAST,
            a.ip_address,
            s.port;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()

        return [
            {
                "id": row[0],
                "service_id": row[1],
                "target_ip": row[2],
                "port": row[3],
                "protocol": row[4],
                "service_name": row[5],
                "product": row[6],
                "version": row[7],
                "vulnerability_id": row[8],
                "cve_id": row[9],
                "description": row[10],
                "cvss_version": row[11],
                "cvss_score": (
                    float(row[12]) if row[12] is not None else None
                ),
                "severity": row[13],
                "cwe": row[14],
                "matched_cpe": row[15],
                "match_source": row[16],
                "first_seen": row[17],
                "last_seen": row[18],
            }
            for row in rows
        ]

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to fetch service vulnerability mappings"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


# ---------------------------------------------------------------------------
# Asset vulnerabilities
# ---------------------------------------------------------------------------
@router.get(
    "/assets/{asset_id}/vulnerabilities",
    summary="List vulnerabilities for an asset",
)
def get_asset_vulnerabilities(asset_id: int):
    query = """
        SELECT
            a.id AS asset_id,
            a.ip_address::text AS target_ip,
            a.hostname,
            s.id AS service_id,
            s.port,
            s.protocol,
            s.service_name,
            s.product,
            s.version,
            v.id AS vulnerability_id,
            v.cve_id,
            v.description,
            v.cvss_version,
            v.cvss_score,
            v.severity,
            v.cwe,
            sv.matched_cpe,
            sv.match_source,
            sv.first_seen,
            sv.last_seen
        FROM assets a
        JOIN services s
            ON s.asset_id = a.id
        JOIN service_vulnerabilities sv
            ON sv.service_id = s.id
        JOIN vulnerabilities v
            ON v.id = sv.vulnerability_id
        WHERE a.id = %s
        ORDER BY
            v.cvss_score DESC NULLS LAST,
            s.port,
            v.cve_id;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, (asset_id,))
                rows = cur.fetchall()

        return [
            {
                "asset_id": row[0],
                "target_ip": row[1],
                "hostname": row[2],
                "service_id": row[3],
                "port": row[4],
                "protocol": row[5],
                "service_name": row[6],
                "product": row[7],
                "version": row[8],
                "vulnerability_id": row[9],
                "cve_id": row[10],
                "description": row[11],
                "cvss_version": row[12],
                "cvss_score": (
                    float(row[13]) if row[13] is not None else None
                ),
                "severity": row[14],
                "cwe": row[15],
                "matched_cpe": row[16],
                "match_source": row[17],
                "first_seen": row[18],
                "last_seen": row[19],
            }
            for row in rows
        ]

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to fetch asset vulnerabilities: asset_id=%s",
            asset_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


# ---------------------------------------------------------------------------
# Vulnerability summary
# ---------------------------------------------------------------------------
@router.get(
    "/vulnerabilities/summary",
    summary="Get vulnerability severity summary",
)
def get_vulnerability_summary():
    query = """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE severity = 'CRITICAL') AS critical,
            COUNT(*) FILTER (WHERE severity = 'HIGH') AS high,
            COUNT(*) FILTER (WHERE severity = 'MEDIUM') AS medium,
            COUNT(*) FILTER (WHERE severity = 'LOW') AS low,
            COUNT(*) FILTER (WHERE severity = 'NONE') AS none,
            COUNT(*) FILTER (WHERE severity = 'UNKNOWN') AS unknown
        FROM vulnerabilities;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()

        return {
            "total": row[0],
            "critical": row[1],
            "high": row[2],
            "medium": row[3],
            "low": row[4],
            "none": row[5],
            "unknown": row[6],
        }

    except (psycopg.Error, RuntimeError):
        logger.exception("Failed to fetch vulnerability summary")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


# ---------------------------------------------------------------------------
# Findings - Create
# ---------------------------------------------------------------------------
class FindingCreateRequest(BaseModel):
    service_vulnerability_id: int
    title: str
    description: str | None = None
    remediation: str | None = None


@router.post(
    "/findings",
    status_code=status.HTTP_201_CREATED,
    summary="Create a security finding",
)
def create_finding(payload: FindingCreateRequest):

    lookup_query = """
        SELECT
            sv.id,
            v.severity,
            v.cvss_score
        FROM service_vulnerabilities sv
        JOIN vulnerabilities v
            ON v.id = sv.vulnerability_id
        WHERE sv.id = %s;
    """

    insert_query = """
        INSERT INTO findings (
            service_vulnerability_id,
            severity,
            risk_score,
            status,
            title,
            description,
            remediation
        )
        VALUES (
            %s,
            %s,
            %s,
            'OPEN',
            %s,
            %s,
            %s
        )
        RETURNING
            id,
            service_vulnerability_id,
            severity,
            risk_score,
            status,
            title,
            description,
            remediation,
            first_seen,
            last_seen,
            resolved_at;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                cur.execute(
                    lookup_query,
                    (payload.service_vulnerability_id,),
                )

                vulnerability_row = cur.fetchone()

                if vulnerability_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Service vulnerability not found",
                    )

                service_vulnerability_id = vulnerability_row[0]
                severity = vulnerability_row[1]
                cvss_score = vulnerability_row[2]

                risk_score = calculate_risk_score(cvss_score)

                cur.execute(
                    insert_query,
                    (
                        service_vulnerability_id,
                        severity,
                        risk_score,
                        payload.title,
                        payload.description,
                        payload.remediation,
                    ),
                )

                row = cur.fetchone()

        return {
            "id": row[0],
            "service_vulnerability_id": row[1],
            "severity": row[2],
            "risk_score": (
                float(row[3]) if row[3] is not None else None
            ),
            "status": row[4],
            "title": row[5],
            "description": row[6],
            "remediation": row[7],
            "first_seen": row[8],
            "last_seen": row[9],
            "resolved_at": row[10],
        }

    except HTTPException:
        raise

    except (psycopg.Error, RuntimeError):
        logger.exception("Failed to create finding")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


# ---------------------------------------------------------------------------
# Findings - List
# ---------------------------------------------------------------------------
@router.get(
    "/findings",
    summary="List security findings",
)
def get_findings(
    status_filter: str | None = Query(
        default=None,
        alias="status",
        description="Filter by status: OPEN, IN_PROGRESS, RESOLVED",
    ),
    severity: str | None = Query(
        default=None,
        description=(
            "Filter by severity: "
            "CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN"
        ),
    ),
):

    filters = []
    params = []

    if status_filter:
        normalized_status = status_filter.upper()

        allowed_statuses = {
            "OPEN",
            "IN_PROGRESS",
            "RESOLVED",
        }

        if normalized_status not in allowed_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Invalid status. Use one of: "
                    "OPEN, IN_PROGRESS, RESOLVED"
                ),
            )

        filters.append("f.status = %s")
        params.append(normalized_status)

    if severity:
        normalized_severity = severity.upper()

        allowed_severities = {
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "NONE",
            "UNKNOWN",
        }

        if normalized_severity not in allowed_severities:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Invalid severity. Use one of: "
                    "CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN"
                ),
            )

        filters.append("f.severity = %s")
        params.append(normalized_severity)

    where_clause = ""

    if filters:
        where_clause = "WHERE " + " AND ".join(filters)

    query = f"""
        SELECT
            f.id,
            f.service_vulnerability_id,
            a.ip_address::text AS target_ip,
            s.port,
            s.protocol,
            s.service_name,
            s.product,
            s.version,
            v.cve_id,
            f.severity,
            f.risk_score,
            f.status,
            f.title,
            f.description,
            f.remediation,
            f.first_seen,
            f.last_seen,
            f.resolved_at
        FROM findings f
        JOIN service_vulnerabilities sv
            ON sv.id = f.service_vulnerability_id
        JOIN services s
            ON s.id = sv.service_id
        JOIN assets a
            ON a.id = s.asset_id
        JOIN vulnerabilities v
            ON v.id = sv.vulnerability_id
        {where_clause}
        ORDER BY
            f.risk_score DESC NULLS LAST,
            f.severity,
            f.id;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

        return [
            {
                "id": row[0],
                "service_vulnerability_id": row[1],
                "target_ip": row[2],
                "port": row[3],
                "protocol": row[4],
                "service_name": row[5],
                "product": row[6],
                "version": row[7],
                "cve_id": row[8],
                "severity": row[9],
                "risk_score": (
                    float(row[10]) if row[10] is not None else None
                ),
                "status": row[11],
                "title": row[12],
                "description": row[13],
                "remediation": row[14],
                "first_seen": row[15],
                "last_seen": row[16],
                "resolved_at": row[17],
            }
            for row in rows
        ]

    except (psycopg.Error, RuntimeError):
        logger.exception("Failed to fetch findings")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )


# ---------------------------------------------------------------------------
# Findings - Update status and remediation
# ---------------------------------------------------------------------------
class FindingUpdateRequest(BaseModel):
    status: str | None = None
    remediation: str | None = None


@router.patch(
    "/findings/{finding_id}",
    summary="Update finding status or remediation",
)
def update_finding(
    finding_id: int,
    payload: FindingUpdateRequest,
):
    allowed_statuses = {
        "OPEN",
        "IN_PROGRESS",
        "RESOLVED",
    }

    normalized_status = None

    if payload.status is not None:
        normalized_status = payload.status.upper()

        if normalized_status not in allowed_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Invalid status. Use one of: "
                    "OPEN, IN_PROGRESS, RESOLVED"
                ),
            )

    if normalized_status is None and payload.remediation is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Provide at least one field: "
                "status or remediation"
            ),
        )

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                # Check that finding exists
                cur.execute(
                    """
                    SELECT id
                    FROM findings
                    WHERE id = %s
                    """,
                    (finding_id,),
                )

                finding = cur.fetchone()

                if finding is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Finding not found",
                    )

                # -------------------------------------------------------
                # Status + remediation
                # -------------------------------------------------------
                if (
                    normalized_status is not None
                    and payload.remediation is not None
                ):
                    cur.execute(
                        """
                        UPDATE findings
                        SET
                            status = %s,
                            remediation = %s,
                            last_seen = NOW(),
                            resolved_at = CASE
                                WHEN %s = 'RESOLVED'
                                    THEN NOW()
                                ELSE NULL
                            END
                        WHERE id = %s
                        RETURNING
                            id,
                            service_vulnerability_id,
                            severity,
                            risk_score,
                            status,
                            title,
                            description,
                            remediation,
                            first_seen,
                            last_seen,
                            resolved_at
                        """,
                        (
                            normalized_status,
                            payload.remediation,
                            normalized_status,
                            finding_id,
                        ),
                    )

                # -------------------------------------------------------
                # Status only
                # -------------------------------------------------------
                elif normalized_status is not None:
                    cur.execute(
                        """
                        UPDATE findings
                        SET
                            status = %s,
                            last_seen = NOW(),
                            resolved_at = CASE
                                WHEN %s = 'RESOLVED'
                                    THEN NOW()
                                ELSE NULL
                            END
                        WHERE id = %s
                        RETURNING
                            id,
                            service_vulnerability_id,
                            severity,
                            risk_score,
                            status,
                            title,
                            description,
                            remediation,
                            first_seen,
                            last_seen,
                            resolved_at
                        """,
                        (
                            normalized_status,
                            normalized_status,
                            finding_id,
                        ),
                    )

                # -------------------------------------------------------
                # Remediation only
                # -------------------------------------------------------
                else:
                    cur.execute(
                        """
                        UPDATE findings
                        SET
                            remediation = %s,
                            last_seen = NOW()
                        WHERE id = %s
                        RETURNING
                            id,
                            service_vulnerability_id,
                            severity,
                            risk_score,
                            status,
                            title,
                            description,
                            remediation,
                            first_seen,
                            last_seen,
                            resolved_at
                        """,
                        (
                            payload.remediation,
                            finding_id,
                        ),
                    )

                updated = cur.fetchone()

                conn.commit()

        return {
            "id": updated[0],
            "service_vulnerability_id": updated[1],
            "severity": updated[2],
            "risk_score": (
                float(updated[3])
                if updated[3] is not None
                else None
            ),
            "status": updated[4],
            "title": updated[5],
            "description": updated[6],
            "remediation": updated[7],
            "first_seen": updated[8],
            "last_seen": updated[9],
            "resolved_at": updated[10],
        }

    except HTTPException:
        raise

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to update finding: finding_id=%s",
            finding_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

# ---------------------------------------------------------------------------
# Dashboard - Security Summary
# ---------------------------------------------------------------------------
@router.get(
    "/dashboard/summary",
    summary="Get dashboard security summary",
)
def get_dashboard_summary():
    query = """
        SELECT
            (SELECT COUNT(*) FROM assets) AS total_assets,
            (SELECT COUNT(*) FROM services) AS total_services,
            (SELECT COUNT(*) FROM vulnerabilities) AS total_vulnerabilities,
            (SELECT COUNT(*) FROM findings) AS total_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE severity = 'CRITICAL'
            ) AS critical_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE severity = 'HIGH'
            ) AS high_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE severity = 'MEDIUM'
            ) AS medium_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE severity = 'LOW'
            ) AS low_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE severity = 'NONE'
            ) AS none_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE severity = 'UNKNOWN'
            ) AS unknown_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE status = 'OPEN'
            ) AS open_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE status = 'IN_PROGRESS'
            ) AS in_progress_findings,

            (
                SELECT COUNT(*)
                FROM findings
                WHERE status = 'RESOLVED'
            ) AS resolved_findings;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                row = cur.fetchone()

        return {
            "assets": {
                "total": row[0],
            },
            "services": {
                "total": row[1],
            },
            "vulnerabilities": {
                "total": row[2],
            },
            "findings": {
                "total": row[3],
                "severity": {
                    "critical": row[4],
                    "high": row[5],
                    "medium": row[6],
                    "low": row[7],
                    "none": row[8],
                    "unknown": row[9],
                },
                "status": {
                    "open": row[10],
                    "in_progress": row[11],
                    "resolved": row[12],
                },
            },
        }

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to fetch dashboard summary"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

# ---------------------------------------------------------------------------
# Dashboard - Risk Overview
# ---------------------------------------------------------------------------
@router.get(
    "/dashboard/risk-overview",
    summary="Get dashboard risk overview",
)
def get_dashboard_risk_overview():
    query = """
        SELECT
            COUNT(*) AS total_findings,

            COUNT(*) FILTER (
                WHERE status = 'OPEN'
            ) AS open_findings,

            COALESCE(
                SUM(risk_score),
                0
            ) AS total_risk_score,

            COALESCE(
                SUM(risk_score) FILTER (
                    WHERE status = 'OPEN'
                ),
                0
            ) AS open_risk_score,

            COALESCE(
                AVG(risk_score) FILTER (
                    WHERE status = 'OPEN'
                ),
                0
            ) AS average_open_risk,

            COALESCE(
                MAX(risk_score) FILTER (
                    WHERE status = 'OPEN'
                ),
                0
            ) AS highest_open_risk

        FROM findings;
    """

    highest_finding_query = """
        SELECT
            f.id,
            f.title,
            f.severity,
            f.risk_score,
            f.status,
            a.ip_address::text AS target_ip,
            s.port,
            s.protocol,
            v.cve_id
        FROM findings f
        JOIN service_vulnerabilities sv
            ON sv.id = f.service_vulnerability_id
        JOIN services s
            ON s.id = sv.service_id
        JOIN assets a
            ON a.id = s.asset_id
        JOIN vulnerabilities v
            ON v.id = sv.vulnerability_id
        WHERE f.status = 'OPEN'
        ORDER BY
            f.risk_score DESC NULLS LAST,
            f.id
        LIMIT 1;
    """

    asset_risk_query = """
        SELECT
            a.id,
            a.ip_address::text AS target_ip,
            a.hostname,
            COUNT(f.id) AS open_findings,
            COALESCE(
                SUM(f.risk_score),
                0
            ) AS open_risk_score
        FROM assets a
        LEFT JOIN services s
            ON s.asset_id = a.id
        LEFT JOIN service_vulnerabilities sv
            ON sv.service_id = s.id
        LEFT JOIN findings f
            ON f.service_vulnerability_id = sv.id
            AND f.status = 'OPEN'
        GROUP BY
            a.id,
            a.ip_address,
            a.hostname
        ORDER BY
            open_risk_score DESC,
            a.id;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                # Overall risk
                cur.execute(query)
                risk_row = cur.fetchone()

                # Highest-risk open finding
                cur.execute(highest_finding_query)
                highest_row = cur.fetchone()

                # Asset-wise risk
                cur.execute(asset_risk_query)
                asset_rows = cur.fetchall()

        highest_risk_finding = None

        if highest_row is not None:
            highest_risk_finding = {
                "id": highest_row[0],
                "title": highest_row[1],
                "severity": highest_row[2],
                "risk_score": (
                    float(highest_row[3])
                    if highest_row[3] is not None
                    else None
                ),
                "status": highest_row[4],
                "target_ip": highest_row[5],
                "port": highest_row[6],
                "protocol": highest_row[7],
                "cve_id": highest_row[8],
            }

        asset_risk = [
            {
                "asset_id": row[0],
                "target_ip": row[1],
                "hostname": row[2],
                "open_findings": row[3],
                "open_risk_score": (
                    float(row[4])
                    if row[4] is not None
                    else 0.0
                ),
            }
            for row in asset_rows
        ]

        return {
            "findings": {
                "total": risk_row[0],
                "open": risk_row[1],
            },
            "risk": {
                "total": float(risk_row[2]),
                "open": float(risk_row[3]),
                "average_open": round(float(risk_row[4]), 2),
                "highest_open": float(risk_row[5]),
            },
            "highest_risk_open_finding": highest_risk_finding,
            "assets": asset_risk,
        }

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to fetch dashboard risk overview"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

# ---------------------------------------------------------------------------
# Dashboard - Recent Findings
# ---------------------------------------------------------------------------
@router.get(
    "/dashboard/recent-findings",
    summary="Get recent security findings",
)
def get_dashboard_recent_findings():
    query = """
        SELECT
            f.id,
            f.title,
            f.severity,
            f.risk_score,
            f.status,
            f.first_seen,
            f.last_seen,
            a.ip_address::text AS target_ip,
            a.hostname,
            s.port,
            s.protocol,
            v.cve_id
        FROM findings f
        JOIN service_vulnerabilities sv
            ON sv.id = f.service_vulnerability_id
        JOIN services s
            ON s.id = sv.service_id
        JOIN assets a
            ON a.id = s.asset_id
        JOIN vulnerabilities v
            ON v.id = sv.vulnerability_id
        ORDER BY
            f.last_seen DESC,
            f.id DESC
        LIMIT 10;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()

        findings = [
            {
                "id": row[0],
                "title": row[1],
                "severity": row[2],
                "risk_score": (
                    float(row[3])
                    if row[3] is not None
                    else None
                ),
                "status": row[4],
                "first_seen": row[5],
                "last_seen": row[6],
                "target_ip": row[7],
                "hostname": row[8],
                "port": row[9],
                "protocol": row[10],
                "cve_id": row[11],
            }
            for row in rows
        ]

        return {
            "count": len(findings),
            "findings": findings,
        }

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to fetch recent dashboard findings"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )

# ---------------------------------------------------------------------------
# Dashboard - Severity Distribution
# ---------------------------------------------------------------------------
@router.get(
    "/dashboard/severity-distribution",
    summary="Get finding severity distribution",
)
def get_dashboard_severity_distribution():
    query = """
        SELECT
            severity,
            COUNT(*) AS finding_count
        FROM findings
        GROUP BY severity
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                WHEN 'NONE' THEN 5
                WHEN 'UNKNOWN' THEN 6
                ELSE 7
            END;
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()

        distribution = [
            {
                "severity": row[0],
                "count": row[1],
            }
            for row in rows
        ]

        return {
            "total_findings": sum(
                item["count"]
                for item in distribution
            ),
            "distribution": distribution,
        }

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to fetch dashboard severity distribution"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )