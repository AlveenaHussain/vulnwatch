"""
Security reporting APIs for VulnWatch.

Phase 15:
- Generate a professional security assessment report for an asset
- Use a Nessus-inspired vulnerability reporting structure
- Deduplicate vulnerabilities by CVE
- Keep multiple findings linked to the same vulnerability
- Include asset/target details
- Include scope and methodology
- Include scan information
- Include discovered services
- Include vulnerabilities/CVEs
- Include findings, risk and remediation
- Include evidence references from existing scan/service data
- Include security alerts
- Include correlations and SOC investigation context
- Include a final report summary
"""

import logging
from datetime import datetime, timezone

import psycopg
from fastapi import APIRouter, HTTPException, Security, status

from database import get_connection
from security import require_api_key

logger = logging.getLogger("vulnwatch")


router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
    dependencies=[Security(require_api_key)],
)


SEVERITY_ORDER = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "NONE": 5,
    "UNKNOWN": 6,
}


FINDING_STATUS_ORDER = {
    "OPEN": 1,
    "IN_PROGRESS": 2,
    "RESOLVED": 3,
}


def safe_float(value):
    """
    Convert a numeric database value to float safely.
    """
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def severity_rank(severity):
    """
    Return sorting priority for a severity value.
    """
    return SEVERITY_ORDER.get(
        str(severity).upper() if severity else "UNKNOWN",
        6,
    )


def finding_status_rank(finding_status):
    """
    Return sorting priority for a finding status.
    """
    return FINDING_STATUS_ORDER.get(
        str(finding_status).upper() if finding_status else "UNKNOWN",
        4,
    )


def build_evidence(service, vulnerability):
    """
    Build evidence from data that already exists in VulnWatch.

    We intentionally do not invent screenshots, HTTP requests,
    exploit output, or log excerpts that are not stored in the database.
    """

    evidence = []

    port = service.get("port")
    protocol = service.get("protocol")
    service_name = service.get("service_name")
    product = service.get("product")
    version = service.get("version")

    if port is not None:
        service_line = f"{port}/{protocol or 'tcp'}"

        if service_name:
            service_line += f" open {service_name}"

        if product:
            service_line += f" {product}"

        if version:
            service_line += f" {version}"

        evidence.append(
            {
                "type": "Nmap service discovery",
                "value": service_line,
            }
        )

    if vulnerability.get("cve_id"):
        evidence.append(
            {
                "type": "Vulnerability reference",
                "value": vulnerability["cve_id"],
            }
        )

    if service.get("cpe"):
        evidence.append(
            {
                "type": "CPE",
                "value": service["cpe"],
            }
        )

    if not evidence:
        evidence.append(
            {
                "type": "Reference",
                "value": "See associated vulnerability and service data.",
            }
        )

    return evidence


def build_impact(vulnerability, service):
    """
    Build a conservative impact statement using only information
    already available in the vulnerability data.

    We do not claim that exploitation actually occurred.
    """

    description = (
        vulnerability.get("description") or ""
    ).strip()

    normalized_description = description.lower()

    service_name = service.get("service_name")
    product = service.get("product")
    version = service.get("version")
    cve_id = vulnerability.get("cve_id")

    component_parts = []

    if service_name:
        component_parts.append(str(service_name))

    if product:
        component_parts.append(str(product))

    if version:
        component_parts.append(str(version))

    component = " ".join(component_parts).strip()

    if not component:
        component = "affected service"

    if (
        "remote command execution" in normalized_description
        or "command execution" in normalized_description
        or "remote code execution" in normalized_description
        or "code execution" in normalized_description
    ):
        return (
            f"Successful exploitation of the {component} vulnerability "
            "may allow remote command or code execution on the affected "
            "host, potentially compromising confidentiality, integrity, "
            "and availability."
        )

    if (
        "privilege escalation" in normalized_description
        or "elevation of privilege" in normalized_description
    ):
        return (
            f"Successful exploitation of the {component} vulnerability "
            "may allow an attacker to obtain unauthorized privileges on "
            "the affected host."
        )

    if (
        "authentication bypass" in normalized_description
        or "bypass authentication" in normalized_description
    ):
        return (
            f"Successful exploitation of the {component} vulnerability "
            "may allow unauthorized access by bypassing an authentication "
            "control."
        )

    if (
        "denial of service" in normalized_description
        or "denial-of-service" in normalized_description
    ):
        return (
            f"Successful exploitation of the {component} vulnerability "
            "may affect the availability of the affected service or host."
        )

    if (
        "information disclosure" in normalized_description
        or "information leakage" in normalized_description
        or "sensitive information" in normalized_description
    ):
        return (
            f"Successful exploitation of the {component} vulnerability "
            "may result in unauthorized disclosure of information."
        )

    if description:
        reference = cve_id or "the associated vulnerability"

        return (
            f"The affected {component} may be exposed to the security "
            f"impact documented for {reference}. The available vulnerability "
            "description is provided as the authoritative context for the "
            "specific impact."
        )

    return (
        f"The affected {component} is associated with a reported "
        "vulnerability. Refer to the associated vulnerability reference "
        "and vendor guidance for the documented security impact."
    )


def build_finding(
    row,
    vulnerability,
    service,
):
    """
    Convert a database finding row into the report finding format.
    """

    finding = {
        "id": row["finding_id"],
        "service_vulnerability_id": row[
            "service_vulnerability_id"
        ],
        "title": row["finding_title"],
        "severity": row["finding_severity"],
        "cvss_score": safe_float(
            vulnerability.get("cvss_score")
        ),
        "risk_score": safe_float(row["risk_score"]),
        "status": row["finding_status"],
        "affected_asset": {
            "asset_id": row["asset_id"],
            "target_ip": row["target_ip"],
            "hostname": row["hostname"],
        },
        "affected_service": {
            "service_id": service.get("id"),
            "port": service.get("port"),
            "protocol": service.get("protocol"),
            "service_name": service.get("service_name"),
            "product": service.get("product"),
            "version": service.get("version"),
        },
        "description": row["finding_description"],
        "impact": build_impact(
            vulnerability,
            service,
        ),
        "evidence": build_evidence(
            service,
            vulnerability,
        ),
        "remediation": row["remediation"],
        "first_seen": row["finding_first_seen"],
        "last_seen": row["finding_last_seen"],
        "resolved_at": row["resolved_at"],
    }

    return finding


@router.get(
    "/{asset_id}",
    summary="Generate complete professional security report for an asset",
)
def get_security_report(asset_id: int):
    """
    Generate a complete security assessment report for one asset.

    Report structure:

    1. Report Header / Metadata
    2. Executive Summary
    3. Scope & Methodology
    4. Risk Summary
    5. Target & Asset Information
    6. Open Ports & Services
    7. Vulnerabilities - Unique CVEs
    8. Detailed Findings
    9. Security Monitoring / SOC Intelligence
    10. Report Summary
    """

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:

                # =====================================================
                # 1. Asset details
                # =====================================================

                cur.execute(
                    """
                    SELECT
                        id,
                        ip_address::text,
                        mac_address::text,
                        hostname,
                        os,
                        os_accuracy,
                        first_seen,
                        last_seen
                    FROM assets
                    WHERE id = %(asset_id)s
                    LIMIT 1;
                    """,
                    {
                        "asset_id": asset_id,
                    },
                )

                asset_row = cur.fetchone()

                if asset_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail="Asset not found",
                    )

                asset = {
                    "id": asset_row[0],
                    "ip_address": asset_row[1],
                    "mac_address": asset_row[2],
                    "hostname": asset_row[3],
                    "os": asset_row[4],
                    "os_accuracy": asset_row[5],
                    "first_seen": asset_row[6],
                    "last_seen": asset_row[7],
                }

                target_ip = asset["ip_address"]

                # =====================================================
                # 2. Scan information
                # =====================================================

                cur.execute(
                    """
                    SELECT
                        s.id,
                        s.target::text,
                        s.scanner_ip::text,
                        s.nmap_command,
                        s.started_at,
                        s.created_at
                    FROM scans s
                    WHERE s.target = %(target_ip)s::inet
                    ORDER BY
                        s.started_at DESC,
                        s.id DESC;
                    """,
                    {
                        "target_ip": target_ip,
                    },
                )

                scan_rows = cur.fetchall()

                scans = [
                    {
                        "id": row[0],
                        "target": row[1],
                        "scanner_ip": row[2],
                        "nmap_command": row[3],
                        "started_at": row[4],
                        "created_at": row[5],
                    }
                    for row in scan_rows
                ]

                latest_scan = scans[0] if scans else None

                # =====================================================
                # 3. Services / Open Ports
                # =====================================================

                cur.execute(
                    """
                    SELECT
                        s.id,
                        s.port,
                        s.protocol,
                        s.state,
                        s.service_name,
                        s.product,
                        s.version,
                        s.cpe,
                        s.first_seen,
                        s.last_seen,
                        s.last_scan_id
                    FROM services s
                    WHERE s.asset_id = %(asset_id)s
                    ORDER BY
                        s.port,
                        s.protocol;
                    """,
                    {
                        "asset_id": asset_id,
                    },
                )

                service_rows = cur.fetchall()

                services = [
                    {
                        "id": row[0],
                        "port": row[1],
                        "protocol": row[2],
                        "state": row[3],
                        "service_name": row[4],
                        "product": row[5],
                        "version": row[6],
                        "cpe": row[7],
                        "first_seen": row[8],
                        "last_seen": row[9],
                        "last_scan_id": row[10],
                    }
                    for row in service_rows
                ]

                # =====================================================
                # 4. Vulnerabilities + Findings
                #
                # Important:
                # One CVE can have multiple findings.
                # We collect the raw rows first and deduplicate
                # vulnerabilities later by CVE.
                # =====================================================

                cur.execute(
                    """
                    SELECT
                        v.id,
                        v.cve_id,
                        v.description,
                        v.cvss_version,
                        v.cvss_score,
                        v.cvss_vector,
                        v.severity,
                        v.cwe,
                        v.published,
                        v.last_modified,

                        sv.id AS service_vulnerability_id,

                        s.id AS service_id,
                        s.port,
                        s.protocol,
                        s.service_name,
                        s.product,
                        s.version,
                        s.cpe,

                        f.id AS finding_id,
                        f.severity AS finding_severity,
                        f.risk_score,
                        f.status AS finding_status,
                        f.title AS finding_title,
                        f.description AS finding_description,
                        f.remediation,
                        f.first_seen AS finding_first_seen,
                        f.last_seen AS finding_last_seen,
                        f.resolved_at,

                        a.id AS asset_id,
                        a.ip_address::text AS target_ip,
                        a.hostname

                    FROM service_vulnerabilities sv

                    JOIN vulnerabilities v
                        ON v.id = sv.vulnerability_id

                    JOIN services s
                        ON s.id = sv.service_id

                    JOIN assets a
                        ON a.id = s.asset_id

                    LEFT JOIN findings f
                        ON f.service_vulnerability_id = sv.id

                    WHERE s.asset_id = %(asset_id)s

                    ORDER BY
                        CASE v.severity
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH' THEN 2
                            WHEN 'MEDIUM' THEN 3
                            WHEN 'LOW' THEN 4
                            WHEN 'NONE' THEN 5
                            ELSE 6
                        END,
                        v.cve_id,
                        f.id;
                    """,
                    {
                        "asset_id": asset_id,
                    },
                )

                vulnerability_rows = cur.fetchall()

                # =====================================================
                # 5. Security Alerts
                # =====================================================

                cur.execute(
                    """
                    SELECT
                        id,
                        alert_type,
                        severity,
                        status,
                        source_ip::text,
                        destination_ip::text,
                        title,
                        description,
                        event_count,
                        first_seen,
                        last_seen,
                        created_at
                    FROM alerts
                    WHERE asset_id = %(asset_id)s
                       OR destination_ip = %(target_ip)s::inet
                    ORDER BY
                        last_seen DESC,
                        id DESC;
                    """,
                    {
                        "asset_id": asset_id,
                        "target_ip": target_ip,
                    },
                )

                alert_rows = cur.fetchall()

                alerts = [
                    {
                        "id": row[0],
                        "alert_type": row[1],
                        "severity": row[2],
                        "status": row[3],
                        "source_ip": row[4],
                        "destination_ip": row[5],
                        "title": row[6],
                        "description": row[7],
                        "event_count": row[8],
                        "first_seen": row[9],
                        "last_seen": row[10],
                        "created_at": row[11],
                    }
                    for row in alert_rows
                ]

                # =====================================================
                # 6. Correlations
                #
                # Join CVE and alert details so the report is useful
                # without forcing the reader to resolve database IDs.
                # =====================================================

                cur.execute(
                    """
                    SELECT
                        c.id,
                        c.alert_id,
                        c.service_vulnerability_id,
                        c.finding_id,
                        c.correlation_type,
                        c.priority,
                        c.title,
                        c.description,
                        c.created_at,

                        v.cve_id,

                        al.alert_type,
                        al.severity AS alert_severity,
                        al.status AS alert_status,
                        al.source_ip::text AS source_ip,
                        al.destination_ip::text AS destination_ip

                    FROM correlations c

                    LEFT JOIN service_vulnerabilities sv
                        ON sv.id = c.service_vulnerability_id

                    LEFT JOIN vulnerabilities v
                        ON v.id = sv.vulnerability_id

                    LEFT JOIN alerts al
                        ON al.id = c.alert_id

                    WHERE c.asset_id = %(asset_id)s

                    ORDER BY
                        CASE c.priority
                            WHEN 'CRITICAL' THEN 1
                            WHEN 'HIGH' THEN 2
                            WHEN 'MEDIUM' THEN 3
                            WHEN 'LOW' THEN 4
                            WHEN 'INFO' THEN 5
                            ELSE 6
                        END,
                        c.created_at DESC;
                    """,
                    {
                        "asset_id": asset_id,
                    },
                )

                correlation_rows = cur.fetchall()

        # =============================================================
        # 7. Build UNIQUE vulnerability objects
        # =============================================================

        vulnerability_map = {}

        for row in vulnerability_rows:

            vulnerability_id = row[0]
            cve_id = row[1]

            # A CVE is the primary deduplication key.
            # If a vulnerability has no CVE, use its database ID.
            vulnerability_key = (
                cve_id
                if cve_id
                else f"VULNERABILITY-{vulnerability_id}"
            )

            service = {
                "id": row[11],
                "port": row[12],
                "protocol": row[13],
                "service_name": row[14],
                "product": row[15],
                "version": row[16],
                "cpe": row[17],
            }

            if vulnerability_key not in vulnerability_map:
                vulnerability_map[vulnerability_key] = {
                    "id": vulnerability_id,
                    "cve_id": cve_id,
                    "description": row[2],
                    "cvss_version": row[3],
                    "cvss_score": safe_float(row[4]),
                    "cvss_vector": row[5],
                    "severity": row[6],
                    "cwe": row[7],
                    "published": row[8],
                    "last_modified": row[9],
                    "affected_services": [],
                    "related_findings": [],
                }

            vulnerability = vulnerability_map[
                vulnerability_key
            ]

            # ---------------------------------------------------------
            # Add affected service only once
            # ---------------------------------------------------------

            service_key = (
                service["id"],
                service["port"],
                service["protocol"],
            )

            existing_service_keys = {
                (
                    item["id"],
                    item["port"],
                    item["protocol"],
                )
                for item in vulnerability[
                    "affected_services"
                ]
            }

            if service_key not in existing_service_keys:
                vulnerability["affected_services"].append(
                    service
                )

            # ---------------------------------------------------------
            # Add finding if one exists
            # ---------------------------------------------------------

            finding_id = row[18]

            if finding_id is not None:

                finding = build_finding(
                    {
                        "finding_id": row[18],
                        "service_vulnerability_id": row[10],
                        "finding_severity": row[19],
                        "risk_score": row[20],
                        "finding_status": row[21],
                        "finding_title": row[22],
                        "finding_description": row[23],
                        "remediation": row[24],
                        "finding_first_seen": row[25],
                        "finding_last_seen": row[26],
                        "resolved_at": row[27],
                        "asset_id": row[28],
                        "target_ip": row[29],
                        "hostname": row[30],
                    },
                    vulnerability,
                    service,
                )

                vulnerability["related_findings"].append(
                    finding
                )

        # =============================================================
        # 8. Sort unique vulnerabilities
        # =============================================================

        vulnerabilities = list(
            vulnerability_map.values()
        )

        vulnerabilities.sort(
            key=lambda item: (
                severity_rank(item["severity"]),
                item["cve_id"] or "",
            )
        )

        # =============================================================
        # 9. Flatten detailed findings
        # =============================================================

        findings = []

        for vulnerability in vulnerabilities:
            findings.extend(
                vulnerability["related_findings"]
            )

        findings.sort(
            key=lambda item: (
                severity_rank(item["severity"]),
                finding_status_rank(item["status"]),
                -(item["risk_score"] or 0),
                item["id"],
            )
        )

        # =============================================================
        # 10. Convert correlations
        # =============================================================

        correlations = []

        for row in correlation_rows:
            correlations.append(
                {
                    "id": row[0],
                    "alert_id": row[1],
                    "service_vulnerability_id": row[2],
                    "finding_id": row[3],
                    "correlation_type": row[4],
                    "priority": row[5],
                    "title": row[6],
                    "description": row[7],
                    "created_at": row[8],
                    "cve_id": row[9],
                    "alert": {
                        "alert_type": row[10],
                        "severity": row[11],
                        "status": row[12],
                        "source_ip": row[13],
                        "destination_ip": row[14],
                    },
                }
            )

        # =============================================================
        # 11. Risk / severity summary
        # =============================================================

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "NONE": 0,
            "UNKNOWN": 0,
        }

        finding_status_counts = {
            "OPEN": 0,
            "IN_PROGRESS": 0,
            "RESOLVED": 0,
        }

        total_risk = 0.0

        for finding in findings:

            severity = (
                str(finding["severity"]).upper()
                if finding["severity"]
                else "UNKNOWN"
            )

            if severity not in severity_counts:
                severity = "UNKNOWN"

            severity_counts[severity] += 1

            finding_status = (
                str(finding["status"]).upper()
                if finding["status"]
                else None
            )

            if finding_status in finding_status_counts:
                finding_status_counts[
                    finding_status
                ] += 1

            if finding["risk_score"] is not None:
                total_risk += finding["risk_score"]

        # =============================================================
        # 12. Executive summary
        # =============================================================

        critical_count = severity_counts["CRITICAL"]
        high_count = severity_counts["HIGH"]
        medium_count = severity_counts["MEDIUM"]
        low_count = severity_counts["LOW"]

        if critical_count > 0:
            overall_risk_level = "CRITICAL"
        elif high_count > 0:
            overall_risk_level = "HIGH"
        elif medium_count > 0:
            overall_risk_level = "MEDIUM"
        elif low_count > 0:
            overall_risk_level = "LOW"
        else:
            overall_risk_level = "NO_REPORTED_RISK"

        executive_summary = {
            "target": target_ip,
            "hostname": asset["hostname"],
            "overall_risk_level": overall_risk_level,
            "unique_vulnerabilities": len(vulnerabilities),
            "total_findings": len(findings),
            "open_findings": finding_status_counts["OPEN"],
            "in_progress_findings": finding_status_counts[
                "IN_PROGRESS"
            ],
            "resolved_findings": finding_status_counts[
                "RESOLVED"
            ],
            "critical_findings": critical_count,
            "high_findings": high_count,
            "medium_findings": medium_count,
            "low_findings": low_count,
            "security_alerts": len(alerts),
            "correlations": len(correlations),
            "total_risk_score": round(total_risk, 2),
        }

        # =============================================================
        # 13. Scope & Methodology
        # =============================================================

        scope_methodology = {
            "authorization": (
                "Authorized internal laboratory assessment."
            ),
            "authorized_network": "192.168.57.0/24",
            "target": target_ip,
            "assessment_type": (
                "Vulnerability assessment and security monitoring"
            ),
            "discovery_method": (
                "Nmap service/version discovery"
            ),
            "scanner": (
                latest_scan["scanner_ip"]
                if latest_scan
                else None
            ),
            "primary_tool": "Nmap",
            "methodology_note": (
                "Assessment data is generated from the "
                "VulnWatch authorized lab environment."
            ),
        }

        # =============================================================
        # 14. Risk Summary
        # =============================================================

        risk_summary = {
            "overall_risk_level": overall_risk_level,
            "severity": severity_counts,
            "finding_status": finding_status_counts,
            "total_risk_score": round(total_risk, 2),
            "unique_vulnerabilities": len(
                vulnerabilities
            ),
            "total_findings": len(findings),
            "open_findings": finding_status_counts["OPEN"],
        }

        # =============================================================
        # 15. Report Summary / Action Items
        # =============================================================

        open_action_items = []

        for finding in findings:
            if finding["status"] in {
                "OPEN",
                "IN_PROGRESS",
            }:
                open_action_items.append(
                    {
                        "finding_id": finding["id"],
                        "title": finding["title"],
                        "severity": finding["severity"],
                        "status": finding["status"],
                        "remediation": finding["remediation"],
                    }
                )

        report_summary = {
            "total_services": len(services),
            "unique_vulnerabilities": len(
                vulnerabilities
            ),
            "total_findings": len(findings),
            "security_alerts": len(alerts),
            "correlations": len(correlations),
            "findings_by_severity": severity_counts,
            "findings_by_status": finding_status_counts,
            "total_risk_score": round(total_risk, 2),
            "open_action_items": open_action_items,
        }

        # =============================================================
        # 16. Final report
        # =============================================================

        generated_at = datetime.now(timezone.utc)

        return {
            "report": {
                "title": (
                    "VulnWatch Security Assessment Report"
                ),
                "version": "1.0",
                "asset_id": asset_id,
                "target": target_ip,
                "report_date": generated_at,
                "classification": "Lab / Internal",
                "prepared_by": (
                    "VulnWatch automated assessment"
                ),
            },

            "executive_summary": executive_summary,

            "scope_and_methodology": (
                scope_methodology
            ),

            "risk_summary": risk_summary,

            "target": {
                "asset": asset,
                "latest_scan": latest_scan,
                "scan_count": len(scans),
            },

            "open_ports_and_services": {
                "count": len(services),
                "items": services,
            },

            "vulnerabilities": {
                "count": len(vulnerabilities),
                "items": vulnerabilities,
            },

            "detailed_findings": {
                "count": len(findings),
                "items": findings,
            },

            "security_monitoring": {
                "alert_count": len(alerts),
                "alerts": alerts,
                "correlation_count": len(
                    correlations
                ),
                "correlations": correlations,
            },

            "scan_information": {
                "count": len(scans),
                "items": scans,
            },

            "report_summary": report_summary,
        }

    except HTTPException:
        raise

    except (psycopg.Error, RuntimeError):
        logger.exception(
            "Failed to generate security report for asset_id=%s",
            asset_id,
        )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database unavailable",
        )