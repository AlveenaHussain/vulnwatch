import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from database import check_database

logger = logging.getLogger("vulnwatch")

app = FastAPI()


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

    return JSONResponse(status_code=503, content={"database": "unavailable"})