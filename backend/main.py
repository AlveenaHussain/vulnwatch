import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from database import check_database, get_connection
from scan_import import router as scan_import_router
from vulnerabilities import router as vulnerability_router

logger = logging.getLogger("vulnwatch")

app = FastAPI(
    title="VulnWatch API",
    description="Vulnerability Assessment and Security Monitoring platform",
    version="0.1.0",
)

app.include_router(scan_import_router)
app.include_router(vulnerability_router)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/health/db")
def health_db():
    """Check whether the API can reach PostgreSQL."""
    try:
        if check_database():
            return {"database": "connected"}
    except Exception:
        logger.exception("Database health check failed")

    return JSONResponse(
        status_code=503,
        content={"database": "unavailable"},
    )


@app.get("/api/v1/assets")
def get_assets():
    """Return discovered assets from PostgreSQL."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
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
                ORDER BY id;
            """)

            columns = [desc.name for desc in cur.description]
            rows = cur.fetchall()

    return {
        "assets": [
            dict(zip(columns, row))
            for row in rows
        ]
    }


@app.get("/api/v1/services")
def get_services():
    """Return discovered services with their target IP."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    s.id,
                    s.asset_id,
                    a.ip_address::text AS target_ip,
                    s.port,
                    s.protocol,
                    s.service_name,
                    s.product,
                    s.version,
                    s.cpe,
                    s.state,
                    s.first_seen,
                    s.last_seen,
                    s.last_scan_id
                FROM services s
                JOIN assets a
                    ON a.id = s.asset_id
                ORDER BY s.asset_id, s.port;
            """)

            columns = [desc.name for desc in cur.description]
            rows = cur.fetchall()

    return {
        "services": [
            dict(zip(columns, row))
            for row in rows
        ]
    }


@app.get("/api/v1/scans")
def get_scans():
    """Return recorded Nmap scans from PostgreSQL."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    started_at,
                    target::text,
                    nmap_command,
                    scanner_ip::text,
                    created_at
                FROM scans
                ORDER BY started_at DESC;
            """)

            columns = [desc.name for desc in cur.description]
            rows = cur.fetchall()

    return {
        "scans": [
            dict(zip(columns, row))
            for row in rows
        ]
    }