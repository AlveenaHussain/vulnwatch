import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


AUTHORIZED_NETWORK = ipaddress.ip_network(
    "192.168.57.0/24"
)

DEFAULT_BACKEND_URL = "http://192.168.57.1:8000"

SCANNER_BIND_HOST = "192.168.57.102"
SCANNER_PORT = 9000


def load_api_key() -> str:
    environment_key = os.getenv("VULNWATCH_API_KEY")

    if environment_key:
        return environment_key.strip()

    env_file = Path.home() / "vulnwatch" / ".env"

    if env_file.exists():
        for line in env_file.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines():

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("VULNWATCH_API_KEY="):
                value = line.split("=", 1)[1].strip()

                if (
                    len(value) >= 2
                    and value[0] == value[-1]
                    and value[0] in ("'", '"')
                ):
                    value = value[1:-1]

                return value.strip()

    raise RuntimeError(
        "VULNWATCH_API_KEY was not found in the environment or ~/vulnwatch/.env."
    )


def resolve_authorized_target(target: str) -> tuple[str, str]:
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    if "://" in target or "/" in target:
        raise ValueError(
            "Only an IPv4 address or domain name is allowed."
        )

    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise ValueError(
                "Only IPv4 targets are supported."
            )

        if ip not in AUTHORIZED_NETWORK:
            raise ValueError(
                f"Target {target} is outside the authorized lab network "
                f"{AUTHORIZED_NETWORK}."
            )

        return target, str(ip)

    except ValueError:
        pass

    if len(target) > 253 or "." not in target:
        raise ValueError(
            "Enter a valid IPv4 address or domain name."
        )

    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(
            "Could not resolve the supplied domain."
        )

    resolved = ipaddress.ip_address(resolved_ip)

    if resolved not in AUTHORIZED_NETWORK:
        raise ValueError(
            f"Resolved IP {resolved_ip} is outside the authorized "
            f"lab network {AUTHORIZED_NETWORK}."
        )

    return target, resolved_ip


def run_scan(target_ip: str, output_file: Path) -> None:
    command = [
        "nmap",
        "-sV",
        "-oX",
        str(output_file),
        target_ip,
    ]

    print(f"[*] Authorized lab target: {target_ip}")
    print("[*] Running Nmap service detection...")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "Nmap is not installed on Kali."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            "Nmap scan timed out after 180 seconds."
        )

    if result.returncode != 0:
        error = result.stderr.strip()

        raise RuntimeError(
            f"Nmap failed: {error or 'unknown error'}"
        )

    if not output_file.exists() or output_file.stat().st_size == 0:
        raise RuntimeError(
            "Nmap completed but produced no XML output."
        )

    print("[+] Nmap scan completed successfully.")
    print(f"[+] XML generated: {output_file}")


def upload_xml(
    xml_file: Path,
    backend_url: str,
    api_key: str,
) -> dict:

    endpoint = (
        backend_url.rstrip("/")
        + "/api/v1/target-scan/import-xml"
    )

    xml_data = xml_file.read_bytes()

    request = urllib.request.Request(
        endpoint,
        data=xml_data,
        headers={
            "X-API-Key": api_key,
            "Content-Type": "application/xml",
            "Accept": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=60,
        ) as response:

            response_body = response.read().decode(
                "utf-8",
                errors="replace",
            )

            if not response_body:
                return {
                    "status": response.status,
                }

            return json.loads(response_body)

    except urllib.error.HTTPError as exc:
        body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"Backend rejected scan XML "
            f"(HTTP {exc.code}): {body}"
        )

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not connect to VulnWatch backend: {exc}"
        )


def perform_scan(
    target: str,
    backend_url: str,
) -> dict:

    original_target, resolved_ip = resolve_authorized_target(
        target
    )

    api_key = load_api_key()

    with tempfile.NamedTemporaryFile(
        suffix=".xml",
        prefix="vulnwatch-target-",
        delete=False,
    ) as temp_file:

        output_file = Path(temp_file.name)

    try:
        run_scan(
            target_ip=resolved_ip,
            output_file=output_file,
        )

        print("[*] Uploading Nmap XML to VulnWatch...")

        result = upload_xml(
            xml_file=output_file,
            backend_url=backend_url,
            api_key=api_key,
        )

        print("[+] Scan imported into VulnWatch.")

        return {
            "target": original_target,
            "resolved_ip": resolved_ip,
            "result": result,
        }

    finally:
        output_file.unlink(
            missing_ok=True
        )


class ScannerHandler(BaseHTTPRequestHandler):

    def _send_json(
        self,
        status_code: int,
        payload: dict,
    ) -> None:

        body = json.dumps(
            payload
        ).encode("utf-8")

        self.send_response(status_code)

        self.send_header(
            "Content-Type",
            "application/json",
        )

        self.send_header(
            "Content-Length",
            str(len(body)),
        )

        self.send_header(
            "Access-Control-Allow-Origin",
            "http://localhost:5173",
        )

        self.send_header(
            "Access-Control-Allow-Methods",
            "POST, OPTIONS",
        )

        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type",
        )

        self.end_headers()

        self.wfile.write(body)

    def do_OPTIONS(self):

        self.send_response(204)

        self.send_header(
            "Access-Control-Allow-Origin",
            "http://localhost:5173",
        )

        self.send_header(
            "Access-Control-Allow-Methods",
            "POST, OPTIONS",
        )

        self.send_header(
            "Access-Control-Allow-Headers",
            "Content-Type",
        )

        self.end_headers()

    def do_POST(self):

        if self.path != "/scan":
            self._send_json(
                404,
                {
                    "detail": "Not found.",
                },
            )
            return

        try:
            content_length = int(
                self.headers.get(
                    "Content-Length",
                    "0",
                )
            )
        except ValueError:
            content_length = 0

        if content_length <= 0:
            self._send_json(
                400,
                {
                    "detail": "Request body is empty.",
                },
            )
            return

        if content_length > 10 * 1024:
            self._send_json(
                413,
                {
                    "detail": "Request body is too large.",
                },
            )
            return

        try:
            body = self.rfile.read(
                content_length
            )

            data = json.loads(
                body.decode("utf-8")
            )

            target = str(
                data.get("target", "")
            ).strip()

            authorized = bool(
                data.get("authorized", False)
            )

            if not authorized:
                self._send_json(
                    403,
                    {
                        "detail": (
                            "Authorization confirmation is required."
                        ),
                    },
                )
                return

            result = perform_scan(
                target=target,
                backend_url=DEFAULT_BACKEND_URL,
            )

            self._send_json(
                200,
                {
                    "message": (
                        "Authorized target scan completed."
                    ),
                    **result,
                },
            )

        except (ValueError, RuntimeError) as exc:

            self._send_json(
                400,
                {
                    "detail": str(exc),
                },
            )

        except Exception as exc:

            self._send_json(
                500,
                {
                    "detail": (
                        f"Scanner agent error: {exc}"
                    ),
                },
            )

    def log_message(
        self,
        format_string,
        *args,
    ):
        print(
            f"[scanner-agent] {format_string % args}"
        )


def start_server() -> None:

    server = ThreadingHTTPServer(
        (
            SCANNER_BIND_HOST,
            SCANNER_PORT,
        ),
        ScannerHandler,
    )

    print(
        "============================================"
    )
    print(
        " VulnWatch Authorized Scanner Agent"
    )
    print(
        "============================================"
    )
    print(
        f"Scanner: http://{SCANNER_BIND_HOST}:{SCANNER_PORT}"
    )
    print(
        "Endpoint: POST /scan"
    )
    print(
        f"Authorized network: {AUTHORIZED_NETWORK}"
    )
    print(
        "Press Ctrl+C to stop."
    )
    print(
        "============================================"
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Scanner agent stopped.")
    finally:
        server.server_close()


def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "VulnWatch authorized lab target scanner."
        )
    )

    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "IPv4 address or domain resolving inside "
            "the authorized lab network."
        ),
    )

    parser.add_argument(
        "--api-url",
        default=DEFAULT_BACKEND_URL,
        help="VulnWatch backend URL.",
    )

    parser.add_argument(
        "--serve",
        action="store_true",
        help="Start the HTTP scanner agent.",
    )

    args = parser.parse_args()

    if args.serve:
        start_server()
        return 0

    if not args.target:
        parser.error(
            "Provide a target or use --serve."
        )

    try:
        result = perform_scan(
            target=args.target,
            backend_url=args.api_url,
        )

        print(
            json.dumps(
                result,
                indent=2,
            )
        )

        return 0

    except (ValueError, RuntimeError) as exc:

        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )