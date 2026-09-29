import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from database import check_database, get_connection
from scan_import import router as scan_import_router
from vulnerabilities import router as vulnerability_router
from security_events import router as security_events_router
from alerts import router as alerts_router
from correlations import router as correlations_router


logger = logging.getLogger("vulnwatch")


app = FastAPI(
    title="VulnWatch API",
    description="Vulnerability Assessment and Security Monitoring platform",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# API Routers
# ---------------------------------------------------------------------------

app.include_router(scan_import_router)
app.include_router(vulnerability_router)
app.include_router(security_events_router)
app.include_router(alerts_router)
app.include_router(correlations_router)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "vulnwatch-backend",
    }


@app.get("/health/db")
def health_db():
    try:
        if check_database():
            return {
                "status": "ok",
                "database": "connected",
            }

        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "database": "unavailable",
            },
        )

    except Exception:
        logger.exception("Database health check failed")

        return JSONResponse(
            status_code=503,
            content={
                "status": "error",
                "database": "unavailable",
            },
        )


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@app.get("/api/v1/assets")
def get_assets():
    query = """
        SELECT
            id,
            ip_address::text,
            hostname,
            mac_address,
            os_name,
            first_seen,
            last_seen
        FROM assets
        ORDER BY last_seen DESC NULLS LAST, id DESC;
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()

    return {
        "count": len(rows),
        "assets": [
            {
                "id": row[0],
                "ip_address": row[1],
                "hostname": row[2],
                "mac_address": row[3],
                "os_name": row[4],
                "first_seen": row[5],
                "last_seen": row[6],
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------

@app.get("/api/v1/services")
def get_services():
    query = """
        SELECT
            s.id,
            s.asset_id,
            a.ip_address::text AS target_ip,
            a.hostname,
            s.port,
            s.protocol,
            s.service_name,
            s.product,
            s.version,
            s.state,
            s.first_seen,
            s.last_seen
        FROM services s
        JOIN assets a
            ON a.id = s.asset_id
        ORDER BY
            a.ip_address,
            s.port,
            s.protocol;
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()

    return {
        "count": len(rows),
        "services": [
            {
                "id": row[0],
                "asset_id": row[1],
                "target_ip": row[2],
                "hostname": row[3],
                "port": row[4],
                "protocol": row[5],
                "service_name": row[6],
                "product": row[7],
                "version": row[8],
                "state": row[9],
                "first_seen": row[10],
                "last_seen": row[11],
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@app.get("/api/v1/scans")
def get_scans():
    query = """
        SELECT
            id,
            asset_id,
            scanner_ip::text,
            scan_type,
            started_at,
            completed_at,
            status,
            source_file
        FROM scans
        ORDER BY started_at DESC NULLS LAST, id DESC;
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()

    return {
        "count": len(rows),
        "scans": [
            {
                "id": row[0],
                "asset_id": row[1],
                "scanner_ip": row[2],
                "scan_type": row[3],
                "started_at": row[4],
                "completed_at": row[5],
                "status": row[6],
                "source_file": row[7],
            }
            for row in rows
        ],
    }