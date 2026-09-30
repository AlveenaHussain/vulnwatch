"""
VulnWatch Phase 14 — Authorized Target Scan Workflow.

Architecture:

Browser
    ↓
POST /target-scan/start
    ↓
scan_jobs table
    ↓
Kali agent polls backend
    ↓
Kali runs Nmap
    ↓
Kali POSTs XML to backend
    ↓
Backend parses XML
    ↓
Reusable scan_import function
    ↓
PostgreSQL
"""

import ipaddress
import os
import socket
from datetime import datetime, timezone

from defusedxml import ElementTree as ET
from fastapi import (
    APIRouter,
    HTTPException,
    Request,
    Security,
    status,
)
from pydantic import BaseModel, ConfigDict, Field

from database import get_connection
from scan_import import (
    HostIn,
    ScanImportRequest,
    ServiceIn,
    import_scan_payload,
)
from security import require_api_key


router = APIRouter(
    prefix="/api/v1",
    tags=["target-scan"],
)


AUTHORIZED_NETWORK = ipaddress.ip_network(
    os.getenv(
        "VULNWATCH_AUTHORIZED_NETWORK",
        "192.168.57.0/24",
    )
)


SCANNER_IP = os.getenv(
    "VULNWATCH_SCANNER_IP",
    "192.168.57.102",
)


# A RUNNING job older than this is considered stale.
# This prevents a crashed/offline Kali agent from leaving
# a scan permanently stuck in RUNNING state.
STALE_JOB_MINUTES = int(
    os.getenv(
        "VULNWATCH_STALE_JOB_MINUTES",
        "15",
    )
)


class TargetScanStartRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    target: str = Field(
        min_length=1,
        max_length=255,
    )


class TargetScanFailureRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    error: str = Field(
        min_length=1,
        max_length=2000,
    )


def normalize_ip(value: str) -> str:
    """
    Normalize PostgreSQL INET values such as:
    192.168.57.101/32
    into:
    192.168.57.101
    """
    return str(
        ipaddress.ip_interface(value).ip
    )


def recover_stale_running_jobs(
    cursor,
) -> None:
    """
    Mark abandoned RUNNING jobs as FAILED.

    A job is considered stale when its updated_at timestamp
    is older than VULNWATCH_STALE_JOB_MINUTES.

    This recovery is intentionally performed during normal
    target-scan API activity, so no separate scheduler/cron
    process is required for the current lab architecture.
    """

    cursor.execute(
        """
        UPDATE scan_jobs
        SET
            status = 'FAILED',
            error_message = %s,
            updated_at = NOW()
        WHERE status = 'RUNNING'
          AND updated_at < (
              NOW() - (%s * INTERVAL '1 minute')
          )
        """,
        (
            (
                "Scan job automatically marked as FAILED "
                "because the scanner did not report activity "
                f"for {STALE_JOB_MINUTES} minutes."
            ),
            STALE_JOB_MINUTES,
        ),
    )


def resolve_authorized_target(
    target: str,
) -> tuple[str, str]:

    target = target.strip()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target cannot be empty.",
        )

    if "://" in target or "/" in target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter only an IPv4 address or domain name.",
        )

    try:
        ip = ipaddress.ip_address(target)

        if ip.version != 4:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only IPv4 targets are supported.",
            )

        if ip not in AUTHORIZED_NETWORK:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Target {target} is outside the "
                    f"authorized lab network "
                    f"{AUTHORIZED_NETWORK}."
                ),
            )

        return target, str(ip)

    except ValueError:
        pass

    if len(target) > 253 or "." not in target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter a valid IPv4 address or domain name.",
        )

    try:
        resolved_ip = socket.gethostbyname(target)

    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve the supplied domain.",
        )

    resolved = ipaddress.ip_address(resolved_ip)

    if resolved not in AUTHORIZED_NETWORK:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Resolved target {resolved_ip} is outside "
                f"the authorized lab network "
                f"{AUTHORIZED_NETWORK}."
            ),
        )

    return target, resolved_ip


def parse_nmap_xml(
    xml_content: bytes,
    expected_target_ip: str | None = None,
) -> ScanImportRequest:

    try:
        root = ET.fromstring(xml_content)

    except ET.ParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid Nmap XML: {exc}",
        )

    if root.tag != "nmaprun":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is not a valid Nmap XML document.",
        )

    start_timestamp = root.get("start")

    start_time = datetime.now(timezone.utc)

    if start_timestamp:
        try:
            start_time = datetime.fromtimestamp(
                int(start_timestamp),
                tz=timezone.utc,
            )
        except (TypeError, ValueError):
            pass

    nmap_command = root.get(
        "args",
        "nmap",
    )

    expected_ip = None

    if expected_target_ip:
        try:
            expected_ip = normalize_ip(expected_target_ip)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid assigned scan target IP.",
            )

    hosts: list[HostIn] = []

    for host in root.findall("host"):

        ipv4_address = None
        mac_address = None

        for address in host.findall("address"):

            address_type = address.get("addrtype")

            if address_type == "ipv4":
                ipv4_address = address.get("addr")

            elif address_type == "mac":
                mac_address = address.get("addr")

        if not ipv4_address:
            continue

        try:
            normalized_host_ip = normalize_ip(
                ipv4_address
            )
        except ValueError:
            continue

        if expected_ip:
            if normalized_host_ip != expected_ip:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Nmap XML target does not match "
                        "the assigned scan job target."
                    ),
                )

        hostname = None

        hostnames_node = host.find("hostnames")

        if hostnames_node is not None:
            for hostname_node in hostnames_node.findall(
                "hostname"
            ):
                name = hostname_node.get("name")

                if name:
                    hostname = name
                    break

        services: list[ServiceIn] = []

        ports_node = host.find("ports")

        if ports_node is not None:

            for port_node in ports_node.findall("port"):

                protocol = port_node.get("protocol")
                port_id = port_node.get("portid")

                if protocol not in {"tcp", "udp"}:
                    continue

                if not port_id:
                    continue

                try:
                    port_number = int(port_id)
                except ValueError:
                    continue

                if not 1 <= port_number <= 65535:
                    continue

                state_node = port_node.find("state")

                state = (
                    state_node.get("state")
                    if state_node is not None
                    else "unknown"
                )

                allowed_states = {
                    "open",
                    "closed",
                    "filtered",
                    "unfiltered",
                    "open|filtered",
                    "closed|filtered",
                }

                if state not in allowed_states:
                    state = "unknown"

                service_node = port_node.find("service")

                service_name = None
                product = None
                version = None
                cpe = None

                if service_node is not None:

                    service_name = service_node.get("name")
                    product = service_node.get("product")
                    version = service_node.get("version")

                    cpe_node = service_node.find("cpe")

                    if cpe_node is not None:
                        cpe = (
                            cpe_node.text
                            if cpe_node.text
                            else None
                        )

                services.append(
                    ServiceIn(
                        port=port_number,
                        protocol=protocol,
                        state=state,
                        service_name=service_name,
                        product=product,
                        version=version,
                        cpe=cpe,
                    )
                )

        hosts.append(
            HostIn(
                ip_address=normalized_host_ip,
                mac_address=mac_address,
                hostname=hostname,
                services=services,
            )
        )

    if not hosts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nmap XML contains no usable hosts.",
        )

    target_ip = expected_ip or str(
        hosts[0].ip_address
    )

    return ScanImportRequest(
        scan={
            "started_at": start_time,
            "target": target_ip,
            "nmap_command": nmap_command,
            "scanner_ip": SCANNER_IP,
        },
        hosts=hosts,
    )


@router.post(
    "/target-scan/start",
)
def start_target_scan(
    payload: TargetScanStartRequest,
    _: None = Security(require_api_key),
):

    target_input, target_ip = resolve_authorized_target(
        payload.target
    )

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Recover abandoned jobs before checking whether
            # the requested target is currently busy.
            recover_stale_running_jobs(cursor)

            # Existing duplicate-scan protection is preserved.
            cursor.execute(
                """
                SELECT id
                FROM scan_jobs
                WHERE target_ip = %s
                  AND status IN ('PENDING', 'RUNNING')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (target_ip,),
            )

            existing_job = cursor.fetchone()

            if existing_job:
                return {
                    "message": "A scan is already running for this target.",
                    "job_id": existing_job[0],
                    "status": "ALREADY_RUNNING",
                    "target": target_ip,
                }

            cursor.execute(
                """
                INSERT INTO scan_jobs (
                    target_input,
                    target_ip,
                    scanner_ip,
                    status
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    'PENDING'
                )
                RETURNING
                    id,
                    created_at
                """,
                (
                    target_input,
                    target_ip,
                    SCANNER_IP,
                ),
            )

            row = cursor.fetchone()

    return {
        "message": "Target scan job created.",
        "job_id": row[0],
        "target": target_ip,
        "status": "PENDING",
        "created_at": row[1],
    }


@router.get(
    "/target-scan/jobs/{job_id:int}",
)
def get_target_scan_job(
    job_id: int,
    _: None = Security(require_api_key),
):

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Also recover stale jobs when the frontend polls
            # an existing job.
            recover_stale_running_jobs(cursor)

            cursor.execute(
                """
                SELECT
                    sj.id,
                    sj.target_input,
                    sj.target_ip::text,
                    sj.scanner_ip::text,
                    sj.status,
                    sj.nmap_command,
                    sj.error_message,
                    sj.created_at,
                    sj.started_at,
                    sj.completed_at,
                    sj.updated_at,
                    asset_match.asset_id,
                    scan_match.scan_id
                FROM scan_jobs AS sj

                LEFT JOIN LATERAL (
                    SELECT
                        a.id AS asset_id
                    FROM assets AS a
                    WHERE a.ip_address = sj.target_ip
                    ORDER BY
                        a.last_seen DESC NULLS LAST,
                        a.id DESC
                    LIMIT 1
                ) AS asset_match
                    ON TRUE

                LEFT JOIN LATERAL (
                    SELECT
                        s.id AS scan_id
                    FROM scans AS s
                    WHERE s.target = sj.target_ip
                      AND s.created_at >= sj.created_at
                      AND (
                          sj.completed_at IS NULL
                          OR s.created_at <= sj.completed_at
                      )
                    ORDER BY
                        s.created_at DESC,
                        s.id DESC
                    LIMIT 1
                ) AS scan_match
                    ON TRUE

                WHERE sj.id = %s
                """,
                (job_id,),
            )

            row = cursor.fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found.",
        )

    return {
        "id": row[0],
        "job_id": row[0],
        "target_input": row[1],
        "target_ip": row[2],
        "scanner_ip": row[3],
        "status": row[4],
        "nmap_command": row[5],
        "error_message": row[6],
        "created_at": row[7],
        "started_at": row[8],
        "completed_at": row[9],
        "updated_at": row[10],
        "asset_id": row[11],
        "scan_id": row[12],
    }


@router.get(
    "/target-scan/jobs/next",
    dependencies=[
        Security(require_api_key)
    ],
)
def get_next_target_scan_job():

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Recover abandoned RUNNING jobs before selecting
            # the next pending job for Kali.
            recover_stale_running_jobs(cursor)

            cursor.execute(
                """
                WITH next_job AS (
                    SELECT id
                    FROM scan_jobs
                    WHERE status = 'PENDING'
                    ORDER BY created_at ASC, id ASC
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE scan_jobs
                SET
                    status = 'RUNNING',
                    started_at = NOW(),
                    updated_at = NOW()
                WHERE id = (
                    SELECT id
                    FROM next_job
                )
                RETURNING
                    id,
                    target_input,
                    target_ip::text,
                    scanner_ip::text,
                    status,
                    created_at,
                    started_at
                """
            )

            row = cursor.fetchone()

    if not row:
        return {
            "job": None
        }

    return {
        "job": {
            "id": row[0],
            "target_input": row[1],
            "target_ip": row[2],
            "scanner_ip": row[3],
            "status": row[4],
            "created_at": row[5],
            "started_at": row[6],
        }
    }


@router.post(
    "/target-scan/jobs/{job_id}/result",
    dependencies=[
        Security(require_api_key)
    ],
)
async def submit_target_scan_result(
    job_id: int,
    request: Request,
):

    xml_content = await request.body()

    if not xml_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nmap XML body is empty.",
        )

    if len(xml_content) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Nmap XML file is too large.",
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Recover stale jobs before validating the result.
            recover_stale_running_jobs(cursor)

            cursor.execute(
                """
                SELECT
                    target_ip::text,
                    status
                FROM scan_jobs
                WHERE id = %s
                """,
                (job_id,),
            )

            job = cursor.fetchone()

    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found.",
        )

    target_ip, job_status = job

    if job_status != "RUNNING":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Scan job is not RUNNING. "
                f"Current status: {job_status}"
            ),
        )

    try:

        scan_payload = parse_nmap_xml(
            xml_content,
            expected_target_ip=target_ip,
        )

        import_result = import_scan_payload(
            scan_payload
        )

    except HTTPException as exc:

        error_message = str(
            exc.detail
        )[:2000]

        with get_connection() as connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE scan_jobs
                    SET
                        status = 'FAILED',
                        error_message = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        error_message,
                        job_id,
                    ),
                )

        raise

    except Exception:

        with get_connection() as connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE scan_jobs
                    SET
                        status = 'FAILED',
                        error_message = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (
                        "Scan import failed.",
                        job_id,
                    ),
                )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan result could not be imported.",
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                UPDATE scan_jobs
                SET
                    status = 'COMPLETED',
                    nmap_command = %s,
                    completed_at = NOW(),
                    updated_at = NOW(),
                    error_message = NULL
                WHERE id = %s
                """,
                (
                    scan_payload.scan.nmap_command,
                    job_id,
                ),
            )

    return {
        "message": "Target scan completed successfully.",
        "job_id": job_id,
        "status": "COMPLETED",
        "target": target_ip,
        "scan": import_result.model_dump(),
    }


@router.post(
    "/target-scan/jobs/{job_id}/failed",
    dependencies=[
        Security(require_api_key)
    ],
)
def report_target_scan_failure(
    job_id: int,
    payload: TargetScanFailureRequest,
):

    error_message = payload.error[:2000]

    with get_connection() as connection:
        with connection.cursor() as cursor:

            # Recover other abandoned jobs before processing
            # the current failure report.
            recover_stale_running_jobs(cursor)

            cursor.execute(
                """
                SELECT status
                FROM scan_jobs
                WHERE id = %s
                """,
                (job_id,),
            )

            row = cursor.fetchone()

            if not row:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Scan job not found.",
                )

            if row[0] == "COMPLETED":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Completed scan jobs cannot be marked as failed.",
                )

            cursor.execute(
                """
                UPDATE scan_jobs
                SET
                    status = 'FAILED',
                    error_message = %s,
                    updated_at = NOW()
                WHERE id = %s
                """,
                (
                    error_message,
                    job_id,
                ),
            )

    return {
        "message": "Target scan marked as failed.",
        "job_id": job_id,
        "status": "FAILED",
        "error_message": error_message,
    }