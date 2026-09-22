import argparse
import os
import sys
from datetime import datetime, timezone

import requests
from defusedxml import ElementTree as ET
from dotenv import load_dotenv


load_dotenv()


def parse_nmap_xml(xml_path: str) -> dict:
    """Parse an Nmap XML file into the VulnWatch scan-import format."""

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except FileNotFoundError:
        raise RuntimeError(f"Nmap XML file not found: {xml_path}")
    except ET.ParseError as exc:
        raise RuntimeError(f"Invalid Nmap XML file: {exc}")

    scan_element = root.find("scaninfo")

    nmap_command = root.get("args", "")
    if not nmap_command and scan_element is not None:
        nmap_command = scan_element.get("type", "")

    scanner_ip = os.getenv("VULNWATCH_SCANNER_IP", "192.168.57.102")

    hosts = []

    for host in root.findall("host"):
        status = host.find("status")

        # Ignore hosts that Nmap did not report as up.
        if status is not None and status.get("state") != "up":
            continue

        addresses = host.findall("address")

        ip_address = None
        mac_address = None

        for address in addresses:
            address_type = address.get("addrtype")

            if address_type == "ipv4":
                ip_address = address.get("addr")

            elif address_type == "mac":
                mac_address = address.get("addr")

        if not ip_address:
            continue

        hostname = None
        hostname_element = host.find("./hostnames/hostname")

        if hostname_element is not None:
            hostname = hostname_element.get("name")

        os_name = None
        os_accuracy = None

        os_match = host.find("./os/osmatch")

        if os_match is not None:
            os_name = os_match.get("name")

            accuracy = os_match.get("accuracy")

            if accuracy is not None:
                try:
                    os_accuracy = int(accuracy)
                except ValueError:
                    os_accuracy = None

        services = []

        for port in host.findall("./ports/port"):
            port_number = port.get("portid")
            protocol = port.get("protocol")

            if not port_number or not protocol:
                continue

            try:
                port_number = int(port_number)
            except ValueError:
                continue

            state_element = port.find("state")
            service_element = port.find("service")

            state = (
                state_element.get("state")
                if state_element is not None
                else "unknown"
            )

            service_name = None
            product = None
            version = None
            cpe = None

            if service_element is not None:
                service_name = service_element.get("name")
                product = service_element.get("product")
                version = service_element.get("version")

                cpe_element = service_element.find("cpe")

                if cpe_element is not None:
                    cpe = cpe_element.text

            services.append(
                {
                    "port": port_number,
                    "protocol": protocol,
                    "state": state,
                    "service_name": service_name,
                    "product": product,
                    "version": version,
                    "cpe": cpe,
                }
            )

        hosts.append(
            {
                "ip_address": ip_address,
                "mac_address": mac_address,
                "hostname": hostname,
                "os": os_name,
                "os_accuracy": os_accuracy,
                "services": services,
            }
        )

    target = ",".join(host["ip_address"] for host in hosts)

    started_at = root.get("startstr")

    if started_at:
        try:
            started_at = datetime.fromtimestamp(
                int(root.get("start", "0")),
                tz=timezone.utc,
            ).isoformat()
        except (ValueError, TypeError):
            started_at = datetime.now(timezone.utc).isoformat()
    else:
        started_at = datetime.now(timezone.utc).isoformat()

    return {
        "scan": {
            "started_at": started_at,
            "target": target,
            "nmap_command": nmap_command,
            "scanner_ip": scanner_ip,
        },
        "hosts": hosts,
    }


def import_scan(api_url: str, api_key: str, payload: dict) -> dict:
    """Send parsed Nmap data to the VulnWatch API."""

    endpoint = f"{api_url.rstrip('/')}/api/v1/scans/import"

    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    try:
        response = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise RuntimeError(f"Could not connect to VulnWatch API: {exc}")

    if not response.ok:
        try:
            error_details = response.json()
        except ValueError:
            error_details = response.text

        raise RuntimeError(
            f"API returned HTTP {response.status_code}: {error_details}"
        )

    try:
        return response.json()
    except ValueError:
        raise RuntimeError("API returned an invalid JSON response.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import an Nmap XML scan into VulnWatch."
    )

    parser.add_argument(
        "xml_file",
        help="Path to the Nmap XML file",
    )

    parser.add_argument(
        "--api-url",
        default=os.getenv(
            "VULNWATCH_API_URL",
            "http://127.0.0.1:8000",
        ),
        help="VulnWatch API base URL",
    )

    args = parser.parse_args()

    api_key = os.getenv("VULNWATCH_API_KEY")

    if not api_key:
        print(
            "ERROR: VULNWATCH_API_KEY environment variable is not set.",
            file=sys.stderr,
        )
        return 1

    try:
        payload = parse_nmap_xml(args.xml_file)

        result = import_scan(
            api_url=args.api_url,
            api_key=api_key,
            payload=payload,
        )

    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("Scan imported successfully")
    print(f"Target: {payload['scan']['target']}")
    print(f"Hosts processed: {result.get('hosts_processed', 0)}")
    print(f"Assets created: {result.get('assets_created', 0)}")
    print(f"Assets updated: {result.get('assets_updated', 0)}")
    print(f"Services created: {result.get('services_created', 0)}")
    print(f"Services updated: {result.get('services_updated', 0)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())