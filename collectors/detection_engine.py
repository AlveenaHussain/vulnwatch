"""
VulnWatch detection engine.

Phase 11:
- Reads normalized security events from the VulnWatch API
- Detects repeated failed SSH logins
- Detects port scanning activity
- Calculates alert severity
- Sends alerts to the protected Alerts API
"""

import argparse
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

import requests


DEFAULT_EVENTS_URL = (
    "http://127.0.0.1:8000/api/v1/security-events"
)

DEFAULT_ALERTS_URL = (
    "http://127.0.0.1:8000/api/v1/alerts/import"
)


SSH_BRUTE_FORCE_RULES = [
    (10, "CRITICAL"),
    (5, "HIGH"),
    (2, "MEDIUM"),
]


def get_severity_for_ssh(event_count):
    """Return SSH brute-force severity based on failed-login count."""

    for threshold, severity in SSH_BRUTE_FORCE_RULES:
        if event_count >= threshold:
            return severity

    return None


def get_events(api_url, api_key, limit=500):
    """Retrieve security events from the VulnWatch API."""

    response = requests.get(
        api_url,
        headers={
            "X-API-Key": api_key,
        },
        params={
            "limit": limit,
            "offset": 0,
        },
        timeout=15,
    )

    response.raise_for_status()

    result = response.json()

    return result.get("events", [])


def import_alert(api_url, api_key, alert):
    """Send a detected alert to the VulnWatch Alerts API."""

    response = requests.post(
        api_url,
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        json=alert,
        timeout=15,
    )

    response.raise_for_status()

    return response.status_code, response.json()


def detect_ssh_brute_force(events):
    """
    Detect repeated failed SSH logins.

    Grouping:
    source_ip + destination_ip

    Thresholds:
    2-4  -> MEDIUM
    5-9  -> HIGH
    10+  -> CRITICAL
    """

    grouped = defaultdict(list)

    for event in events:
        if event.get("event_type") != "FAILED_SSH_LOGIN":
            continue

        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")

        if not source_ip or not destination_ip:
            continue

        grouped[
            (source_ip, destination_ip)
        ].append(event)

    alerts = []

    for (source_ip, destination_ip), matched_events in grouped.items():
        event_count = len(matched_events)

        severity = get_severity_for_ssh(event_count)

        if not severity:
            continue

        event_times = [
            event["event_time"]
            for event in matched_events
            if event.get("event_time")
        ]

        first_seen = min(event_times)
        last_seen = max(event_times)

        asset_id = next(
            (
                event.get("asset_id")
                for event in matched_events
                if event.get("asset_id") is not None
            ),
            None,
        )

        alert = {
            "alert_type": "SSH_BRUTE_FORCE",
            "severity": severity,
            "status": "OPEN",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "asset_id": asset_id,
            "title": "Repeated failed SSH login attempts",
            "description": (
                f"Detected {event_count} failed SSH login attempts "
                f"from {source_ip} against {destination_ip}."
            ),
            "event_count": event_count,
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

        alerts.append(alert)

    return alerts


def detect_port_scans(events):
    """
    Detect port scanning activity.

    Grouping:
    source_ip + destination_ip

    Rule:
    10 or more unique destination ports -> HIGH
    """

    grouped_ports = defaultdict(set)
    grouped_events = defaultdict(list)

    for event in events:
        source_ip = event.get("source_ip")
        destination_ip = event.get("destination_ip")
        destination_port = event.get("destination_port")

        if not source_ip or not destination_ip:
            continue

        if destination_port is None:
            continue

        key = (source_ip, destination_ip)

        grouped_ports[key].add(destination_port)
        grouped_events[key].append(event)

    alerts = []

    for (source_ip, destination_ip), matched_events in grouped_events.items():
        unique_ports = grouped_ports[
            (source_ip, destination_ip)
        ]

        if len(unique_ports) < 10:
            continue

        event_times = [
            event["event_time"]
            for event in matched_events
            if event.get("event_time")
        ]

        if not event_times:
            continue

        first_seen = min(event_times)
        last_seen = max(event_times)

        asset_id = next(
            (
                event.get("asset_id")
                for event in matched_events
                if event.get("asset_id") is not None
            ),
            None,
        )

        alert = {
            "alert_type": "PORT_SCAN",
            "severity": "HIGH",
            "status": "OPEN",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "asset_id": asset_id,
            "title": "Potential port scanning activity detected",
            "description": (
                f"Detected scanning activity from {source_ip} "
                f"against {destination_ip} across "
                f"{len(unique_ports)} unique destination ports."
            ),
            "event_count": len(matched_events),
            "first_seen": first_seen,
            "last_seen": last_seen,
        }

        alerts.append(alert)

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Run VulnWatch SOC detection rules"
    )

    parser.add_argument(
        "--events-url",
        default=DEFAULT_EVENTS_URL,
        help="Security events API URL",
    )

    parser.add_argument(
        "--alerts-url",
        default=DEFAULT_ALERTS_URL,
        help="Alerts import API URL",
    )

    parser.add_argument(
        "--api-key",
        default=os.getenv("VULNWATCH_API_KEY"),
        help=(
            "VulnWatch API key. "
            "Prefer VULNWATCH_API_KEY environment variable."
        ),
    )

    args = parser.parse_args()

    if not args.api_key:
        print("[ERROR] VULNWATCH_API_KEY is not set.")
        sys.exit(1)

    print("[INFO] Fetching security events...")

    try:
        events = get_events(
            api_url=args.events_url,
            api_key=args.api_key,
        )
    except requests.RequestException as exc:
        print(f"[ERROR] Failed to retrieve security events: {exc}")
        sys.exit(1)

    print(f"[INFO] Security events received: {len(events)}")

    ssh_alerts = detect_ssh_brute_force(events)
    port_scan_alerts = detect_port_scans(events)

    detected_alerts = ssh_alerts + port_scan_alerts

    print(
        f"[INFO] Alerts detected: {len(detected_alerts)}"
    )

    imported = 0
    updated = 0
    failed = 0

    for alert in detected_alerts:
        try:
            status_code, result = import_alert(
                api_url=args.alerts_url,
                api_key=args.api_key,
                alert=alert,
            )

            message = result.get("message", "")
            alert_data = result.get("alert", {})
            alert_id = alert_data.get("id")

            if status_code == 201:
                imported += 1

                print(
                    f"[ALERT] {alert['alert_type']} "
                    f"| severity={alert['severity']} "
                    f"| events={alert['event_count']} "
                    f"| alert_id={alert_id}"
                )

            elif status_code == 200:
                updated += 1

                print(
                    f"[UPDATED] {alert['alert_type']} "
                    f"| severity={alert['severity']} "
                    f"| events={alert['event_count']} "
                    f"| alert_id={alert_id}"
                )

            else:
                imported += 1

                print(
                    f"[ALERT] {message} "
                    f"| alert_id={alert_id}"
                )

        except requests.RequestException as exc:
            failed += 1

            print(
                f"[ERROR] Failed to import "
                f"{alert['alert_type']}: {exc}"
            )

    print()
    print("========== Detection Summary ==========")
    print(f"Security events : {len(events)}")
    print(f"SSH alerts      : {len(ssh_alerts)}")
    print(f"Port scan alerts: {len(port_scan_alerts)}")
    print(f"Imported alerts : {imported}")
    print(f"Updated alerts  : {updated}")
    print(f"Failed alerts   : {failed}")
    print("=======================================")


if __name__ == "__main__":
    main()