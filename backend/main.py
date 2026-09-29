from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import get_connection
from scan_import import router as scan_import_router
from vulnerabilities import router as vulnerabilities_router
from security_events import router as security_events_router
from alerts import router as alerts_router
from correlations import router as correlations_router
from investigations import router as investigations_router


app = FastAPI(
    title="VulnWatch API",
    version="0.1.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(scan_import_router)
app.include_router(vulnerabilities_router)
app.include_router(security_events_router)
app.include_router(alerts_router)
app.include_router(correlations_router)
app.include_router(investigations_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/db")
def health_db():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            cur.fetchone()

    return {
        "status": "ok",
        "database": "connected",
    }


@app.get("/api/v1/assets")
def get_assets():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    ip_address::text,
                    hostname,
                    NULL::text AS os_name,
                    NULL::text AS mac_address,
                    first_seen,
                    last_seen
                FROM assets
                ORDER BY id;
                """
            )
            rows = cur.fetchall()

    return {
        "count": len(rows),
        "assets": [
            {
                "id": row[0],
                "ip_address": row[1],
                "hostname": row[2],
                "os_name": row[3],
                "mac_address": row[4],
                "first_seen": row[5],
                "last_seen": row[6],
            }
            for row in rows
        ],
    }


@app.get("/api/v1/services")
def get_services():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    s.id,
                    s.asset_id,
                    a.ip_address::text,
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
            )
            rows = cur.fetchall()

    return {
        "count": len(rows),
        "services": [
            {
                "id": row[0],
                "asset_id": row[1],
                "target_ip": row[2],
                "port": row[3],
                "protocol": row[4],
                "service_name": row[5],
                "product": row[6],
                "version": row[7],
                "state": row[8],
                "first_seen": row[9],
                "last_seen": row[10],
            }
            for row in rows
        ],
    }


@app.get("/api/v1/scans")
def get_scans():
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    target::text,
                    scanner_ip::text,
                    nmap_command,
                    started_at,
                    created_at
                FROM scans
                ORDER BY
                    started_at DESC,
                    id DESC;
                """
            )
            rows = cur.fetchall()

    return {
        "count": len(rows),
        "scans": [
            {
                "id": row[0],
                "target": row[1],
                "scanner_ip": row[2],
                "nmap_command": row[3],
                "started_at": row[4],
                "created_at": row[5],
            }
            for row in rows
        ],
    }