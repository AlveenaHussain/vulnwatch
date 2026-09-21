"""
Database connection helpers for VulnWatch.

Connection settings come from environment variables
(provided by Docker Compose from the .env file).
Secrets are never hard-coded in source code.
"""

import os

import psycopg

REQUIRED_SETTINGS = [
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "POSTGRES_DB",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
]


def get_connection() -> psycopg.Connection:
    """Open and return a new connection to PostgreSQL."""
    missing = [name for name in REQUIRED_SETTINGS if not os.getenv(name)]
    if missing:
        raise RuntimeError(f"Missing database settings: {', '.join(missing)}")

    return psycopg.connect(
        host=os.getenv("POSTGRES_HOST"),
        port=os.getenv("POSTGRES_PORT"),
        dbname=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        connect_timeout=5,
    )


def check_database() -> bool:
    """Run a tiny test query. Returns True if PostgreSQL answers correctly."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1;")
            result = cur.fetchone()
    return result == (1,)