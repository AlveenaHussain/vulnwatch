"""
VulnWatch correlation engine.

Phase 12:
- Reads existing SOC alerts
- Reads existing service vulnerabilities/findings
- Matches them on the same asset
- Calculates investigation priority
- Creates correlations through the protected API
"""

import argparse
import os
import sys

import requests


DEFAULT_ALERTS_URL = (
    "http://127.0.0.1:8000/api/v1/alerts"
)

DEFAULT_VULNERABILITIES_URL = (
    "http://127.0.0.1:8000/api/v1/service-vulnerabilities"
)

DEFAULT_FINDINGS_URL = (
    "http://127.0.0.1:8000/api/v1/findings"
)

DEFAULT_CORRELATIONS_URL = (
    "http://127.0.0.1:8000/api/v1/correlations/import"
)


PRIORITY_ORDER = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def get_json(
    api_url,
    api_key,
    params=None,
):
    """GET JSON data from a VulnWatch API endpoint."""

    response = requests.get(
        api_url,
        headers={
            "X-API-Key": api_key,
        },
        params=params or {},
        timeout=15,
    )

    response.raise_for_status()

    return response.json()


def import_correlation(
    api_url,
    api_key,
    correlation,
):
    """POST a correlation to the protected API."""

    response = requests.post(
        api_url,
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        json=correlation,
        timeout=15,
    )

    response.raise_for_status()

    return response.status_code, response.json()


def normalize_severity(value):
    """Normalize severity text."""

    if not value:
        return "INFO"

    value = str(value).upper()

    if value in PRIORITY_ORDER:
        return value

    return "INFO"


def severity_to_priority(
    vulnerability_severity,
    vulnerability_cvss,
    alert_severity,
):
    """
    Calculate correlation priority.

    Priority considers both:
    - vulnerability severity/CVSS
    - SOC alert severity

    The higher security signal becomes the baseline,
    while CRITICAL/HIGH vulnerabilities remain important
    when paired with a SOC alert.
    """

    vuln_severity = normalize_severity(
        vulnerability_severity
    )

    alert_severity = normalize_severity(
        alert_severity
    )

    vuln_priority = PRIORITY_ORDER[vuln_severity]
    alert_priority = PRIORITY_ORDER[alert_severity]

    priority = max(
        vuln_priority,
        alert_priority,
    )

    if (
        vulnerability_cvss is not None
        and float(vulnerability_cvss) >= 9.0
    ):
        priority = max(priority, 5)

    elif (
        vulnerability_cvss is not None
        and float(vulnerability_cvss) >= 7.0
    ):
        priority = max(priority, 4)

    priority_map = {
        5: "CRITICAL",
        4: "HIGH",
        3: "MEDIUM",
        2: "LOW",
        1: "INFO",
    }

    return priority_map[priority]


def build_correlation(
    alert,
    service_vulnerability,
    finding=None,
):
    """Build a correlation payload."""

    priority = severity_to_priority(
        vulnerability_severity=(
            service_vulnerability.get("severity")
        ),
        vulnerability_cvss=(
            service_vulnerability.get("cvss_score")
        ),
        alert_severity=(
            alert.get("severity")
        ),
    )

    target_ip = (
        service_vulnerability.get("target_ip")
        or alert.get("destination_ip")
    )

    cve_id = service_vulnerability.get("cve_id")

    alert_type = alert.get("alert_type")

    title = (
        f"Vulnerability and {alert_type} correlated"
    )

    description_parts = []

    if cve_id:
        description_parts.append(
            f"Vulnerability {cve_id}"
        )

    if target_ip:
        description_parts.append(
            f"affects asset {target_ip}"
        )

    if alert_type:
        description_parts.append(
            f"and is associated with "
            f"{alert_type} activity"
        )

    description = " ".join(
        description_parts
    )

    return {
        "asset_id": service_vulnerability["asset_id"],
        "alert_id": alert["id"],
        "service_vulnerability_id": (
            service_vulnerability["id"]
        ),
        "finding_id": (
            finding.get("id")
            if finding
            else None
        ),
        "correlation_type": (
            "ASSET_VULNERABILITY_ALERT"
        ),
        "priority": priority,
        "title": title,
        "description": description,
    }


def find_matching_findings(
    findings,
    service_vulnerability_id,
):
    """Find existing findings for a service vulnerability."""

    return [
        finding
        for finding in findings
        if finding.get(
            "service_vulnerability_id"
        ) == service_vulnerability_id
    ]


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Run VulnWatch vulnerability-alert "
            "correlation engine"
        )
    )

    parser.add_argument(
        "--alerts-url",
        default=DEFAULT_ALERTS_URL,
        help="Alerts API URL",
    )

    parser.add_argument(
        "--vulnerabilities-url",
        default=DEFAULT_VULNERABILITIES_URL,
        help="Service vulnerabilities API URL",
    )

    parser.add_argument(
        "--findings-url",
        default=DEFAULT_FINDINGS_URL,
        help="Findings API URL",
    )

    parser.add_argument(
        "--correlations-url",
        default=DEFAULT_CORRELATIONS_URL,
        help="Correlation import API URL",
    )

    parser.add_argument(
        "--api-key",
        default=os.getenv(
            "VULNWATCH_API_KEY"
        ),
        help=(
            "VulnWatch API key. "
            "Prefer VULNWATCH_API_KEY environment variable."
        ),
    )

    args = parser.parse_args()

    api_key = (
        args.api_key or ""
    ).strip()

    if not api_key:
        print(
            "[ERROR] VULNWATCH_API_KEY is not set."
        )
        sys.exit(1)

    print(
        "[INFO] Fetching SOC alerts..."
    )

    try:
        alerts_result = get_json(
            api_url=args.alerts_url,
            api_key=api_key,
            params={
                "limit": 500,
                "offset": 0,
            },
        )
    except requests.RequestException as exc:
        print(
            "[ERROR] Failed to retrieve alerts: "
            f"{exc}"
        )
        sys.exit(1)

    alerts = alerts_result.get(
        "alerts",
        [],
    )

    print(
        f"[INFO] Alerts received: {len(alerts)}"
    )

    print(
        "[INFO] Fetching service vulnerabilities..."
    )

    try:
        vulnerabilities_result = get_json(
            api_url=args.vulnerabilities_url,
            api_key=api_key,
            params={
                "limit": 500,
                "offset": 0,
            },
        )
    except requests.RequestException as exc:
        print(
            "[ERROR] Failed to retrieve "
            f"service vulnerabilities: {exc}"
        )
        sys.exit(1)

    service_vulnerabilities = (
        vulnerabilities_result.get(
            "service_vulnerabilities",
            vulnerabilities_result.get(
                "items",
                [],
            ),
        )
    )

    print(
        "[INFO] Service vulnerabilities received: "
        f"{len(service_vulnerabilities)}"
    )

    print(
        "[INFO] Fetching findings..."
    )

    try:
        findings_result = get_json(
            api_url=args.findings_url,
            api_key=api_key,
            params={
                "limit": 500,
                "offset": 0,
            },
        )
    except requests.RequestException as exc:
        print(
            "[ERROR] Failed to retrieve findings: "
            f"{exc}"
        )
        sys.exit(1)

    findings = findings_result.get(
        "findings",
        [],
    )

    print(
        f"[INFO] Findings received: {len(findings)}"
    )

    detected = 0
    imported = 0
    existing = 0
    failed = 0

    # ---------------------------------------------------------
    # Correlate alerts with vulnerabilities on same asset
    # ---------------------------------------------------------
    for alert in alerts:

        alert_asset_id = alert.get(
            "asset_id"
        )

        if alert_asset_id is None:
            continue

        for vulnerability in service_vulnerabilities:

            vulnerability_asset_id = (
                vulnerability.get(
                    "asset_id"
                )
            )

            if (
                vulnerability_asset_id
                != alert_asset_id
            ):
                continue

            detected += 1

            matching_findings = (
                find_matching_findings(
                    findings,
                    vulnerability.get("id"),
                )
            )

            # Prefer an OPEN/IN_PROGRESS finding.
            selected_finding = None

            for finding in matching_findings:
                if finding.get("status") in {
                    "OPEN",
                    "IN_PROGRESS",
                }:
                    selected_finding = finding
                    break

            if selected_finding is None:
                if matching_findings:
                    selected_finding = (
                        matching_findings[0]
                    )

            correlation = build_correlation(
                alert=alert,
                service_vulnerability=vulnerability,
                finding=selected_finding,
            )

            try:
                status_code, result = (
                    import_correlation(
                        api_url=args.correlations_url,
                        api_key=api_key,
                        correlation=correlation,
                    )
                )

                if status_code == 201:
                    imported += 1

                    correlation_data = (
                        result.get(
                            "correlation",
                            {},
                        )
                    )

                    correlation_id = (
                        correlation_data.get("id")
                    )

                    print(
                        f"[CORRELATED] "
                        f"alert={alert['id']} "
                        f"| cve="
                        f"{vulnerability.get('cve_id')} "
                        f"| priority="
                        f"{correlation['priority']} "
                        f"| correlation_id="
                        f"{correlation_id}"
                    )

                elif status_code == 200:
                    existing += 1

                    correlation_data = (
                        result.get(
                            "correlation",
                            {},
                        )
                    )

                    correlation_id = (
                        correlation_data.get("id")
                    )

                    print(
                        f"[EXISTING] "
                        f"alert={alert['id']} "
                        f"| cve="
                        f"{vulnerability.get('cve_id')} "
                        f"| correlation_id="
                        f"{correlation_id}"
                    )

                else:
                    imported += 1

            except requests.RequestException as exc:
                failed += 1

                print(
                    "[ERROR] Failed to create "
                    "correlation: "
                    f"{exc}"
                )

    print()
    print(
        "========== Correlation Summary =========="
    )
    print(
        f"Alerts              : {len(alerts)}"
    )
    print(
        "Service vulnerabilities: "
        f"{len(service_vulnerabilities)}"
    )
    print(
        f"Potential matches    : {detected}"
    )
    print(
        f"New correlations     : {imported}"
    )
    print(
        f"Existing correlations: {existing}"
    )
    print(
        f"Failed               : {failed}"
    )
    print(
        "=========================================="
    )


if __name__ == "__main__":
    main()