import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from database import check_database, get_connection
from security import require_api_key
from scan_import import router as scan_import_router
from vulnerabilities import router as vulnerabilities_router
from security_events import router as security_events_router
from alerts import router as alerts_router
from correlations import router as correlations_router
from investigations import router as investigations_router
from target_scan import router as target_scan_router


app = FastAPI(
    title="VulnWatch API",
    version="1.0.0",
    description="Vulnerability management and security monitoring API",
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
app.include_router(target_scan_router)


@app.get("/health", tags=["health"])
def health():
    return {
        "status": "ok",
        "service": "vulnwatch-backend",
    }


@app.get("/health/db", tags=["health"])
def database_health():
    try:
        if check_database():
            return {
                "status": "ok",
                "database": "connected",
            }

        return {
            "status": "error",
            "database": "unavailable",
        }

    except Exception as exc:
        return {
            "status": "error",
            "database": "unavailable",
            "detail": str(exc),
        }


@app.get("/api/v1/assets", tags=["assets"])
def get_assets():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    ip_address::text,
                    mac_address,
                    hostname,
                    os AS os_name,
                    os_accuracy,
                    first_seen,
                    last_seen
                FROM assets
                ORDER BY id
                """
            )

            rows = cursor.fetchall()

    assets = []

    for row in rows:
        assets.append(
            {
                "id": row[0],
                "ip_address": row[1],
                "mac_address": row[2],
                "hostname": row[3],
                "os_name": row[4],
                "os_accuracy": row[5],
                "first_seen": row[6],
                "last_seen": row[7],
            }
        )

    return {
        "count": len(assets),
        "assets": assets,
    }


@app.get("/api/v1/services", tags=["services"])
def get_services():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    s.id,
                    s.asset_id,
                    a.ip_address::text AS target_ip,
                    a.hostname,
                    s.port,
                    s.protocol,
                    s.state,
                    s.service_name,
                    s.product,
                    s.version,
                    s.cpe,
                    s.first_seen,
                    s.last_seen
                FROM services s
                JOIN assets a
                    ON a.id = s.asset_id
                ORDER BY s.id
                """
            )

            rows = cursor.fetchall()

    services = []

    for row in rows:
        services.append(
            {
                "id": row[0],
                "asset_id": row[1],
                "target_ip": row[2],
                "hostname": row[3],
                "port": row[4],
                "protocol": row[5],
                "state": row[6],
                "service_name": row[7],
                "product": row[8],
                "version": row[9],
                "cpe": row[10],
                "first_seen": row[11],
                "last_seen": row[12],
            }
        )

    return {
        "count": len(services),
        "services": services,
    }


@app.get("/api/v1/scans", tags=["scans"])
def get_scans():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    target::text,
                    scanner_ip::text,
                    nmap_command,
                    started_at,
                    created_at
                FROM scans
                ORDER BY started_at DESC, id DESC
                """
            )

            rows = cursor.fetchall()

    scans = []

    for row in rows:
        scans.append(
            {
                "id": row[0],
                "target": row[1],
                "scanner_ip": row[2],
                "nmap_command": row[3],
                "started_at": row[4],
                "created_at": row[5],
            }
        )

    return {
        "count": len(scans),
        "scans": scans,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
    )