"""
VulnWatch auth.log collector.

Phase 10:
- Reads a copied Metasploitable auth.log
- Extracts failed SSH login events
- Normalizes the events
- Sends them to VulnWatch security-events API
- Clearly separates new imports from duplicates
"""

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests


FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+)\s+"
    r"from\s+(?P<source_ip>\S+)\s+"
    r"port\s+(?P<source_port>\d+)\s+ssh2"
)


def parse_event_time(month, day, time_value):
    current_year = datetime.now().year

    value = datetime.strptime(
        f"{current_year} {month} {day} {time_value}",
        "%Y %b %d %H:%M:%S",
    )

    return value.replace(tzinfo=timezone.utc).isoformat()


def parse_auth_log(log_path, destination_ip):
    events = []

    with log_path.open(
        "r",
        encoding="utf-8",
        errors="replace",
    ) as log_file:

        for line_number, line in enumerate(log_file, start=1):
            line = line.rstrip("\n")

            match = FAILED_PASSWORD_PATTERN.search(line)

            if not match:
                continue

            event = {
                "event_type": "FAILED_SSH_LOGIN",
                "event_time": parse_event_time(
                    match.group("month"),
                    match.group("day"),
                    match.group("time"),
                ),
                "source_ip": match.group("source_ip"),
                "destination_ip": destination_ip,
                "protocol": "SSH",
                "source_port": int(match.group("source_port")),
                "destination_port": 22,
                "username": match.group("username"),
                "severity": "MEDIUM",
                "raw_log": line,
                "source": "metasploitable-auth.log",
            }

            events.append(
                {
                    "line_number": line_number,
                    "event": event,
                }
            )

    return events


def import_event(api_url, api_key, event):
    response = requests.post(
        api_url,
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        },
        json=event,
        timeout=15,
    )

    response.raise_for_status()

    return response.status_code, response.json()


def main():
    parser = argparse.ArgumentParser(
        description="Import failed SSH events from Metasploitable auth.log"
    )

    parser.add_argument(
        "--log-file",
        required=True,
        help="Path to copied auth.log file",
    )

    parser.add_argument(
        "--destination-ip",
        required=True,
        help="Metasploitable destination IP",
    )

    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:8000/api/v1/security-events/import",
        help="VulnWatch security event import API URL",
    )

    parser.add_argument(
        "--api-key",
        default=os.getenv("VULNWATCH_API_KEY"),
        help="VulnWatch API key. Prefer VULNWATCH_API_KEY environment variable.",
    )

    args = parser.parse_args()

    log_path = Path(args.log_file)

    if not log_path.exists():
        print(f"[ERROR] Log file not found: {log_path}")
        sys.exit(1)

    if not args.api_key:
        print("[ERROR] VULNWATCH_API_KEY is not set.")
        sys.exit(1)

    events = parse_auth_log(
        log_path=log_path,
        destination_ip=args.destination_ip,
    )

    print(f"[INFO] Parsed failed SSH events: {len(events)}")

    imported = 0
    duplicates = 0
    failed = 0

    for item in events:
        try:
            status_code, result = import_event(
                api_url=args.api_url,
                api_key=args.api_key,
                event=item["event"],
            )

            message = result.get("message", "")
            event_data = result.get("event", {})
            event_id = event_data.get("id")

            if status_code == 201 and "imported successfully" in message.lower():
                imported += 1

                print(
                    f"[IMPORTED] line={item['line_number']} "
                    f"event_id={event_id}"
                )

            elif status_code == 200 and "duplicate" in message.lower():
                duplicates += 1

                print(
                    f"[DUPLICATE] line={item['line_number']} "
                    f"existing_event_id={event_id}"
                )

            else:
                imported += 1

                print(
                    f"[IMPORTED] line={item['line_number']} "
                    f"event_id={event_id}"
                )

        except requests.RequestException as exc:
            failed += 1

            print(
                f"[ERROR] Failed to import line "
                f"{item['line_number']}: {exc}"
            )

    print()
    print("========== Collector Summary ==========")
    print(f"Parsed events : {len(events)}")
    print(f"Imported      : {imported}")
    print(f"Duplicates    : {duplicates}")
    print(f"Failed        : {failed}")
    print("=======================================")


if __name__ == "__main__":
    main()