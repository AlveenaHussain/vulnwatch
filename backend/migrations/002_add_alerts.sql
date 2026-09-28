-- Phase 11: Detection & Alerts
-- Creates the alerts table and its indexes.

CREATE TABLE IF NOT EXISTS alerts (
    id BIGSERIAL PRIMARY KEY,

    alert_type TEXT NOT NULL
        CHECK (alert_type IN ('SSH_BRUTE_FORCE', 'PORT_SCAN')),

    severity TEXT NOT NULL
        CHECK (severity IN (
            'CRITICAL',
            'HIGH',
            'MEDIUM',
            'LOW',
            'INFO',
            'UNKNOWN'
        )),

    status TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN (
            'OPEN',
            'IN_PROGRESS',
            'RESOLVED'
        )),

    source_ip INET,

    destination_ip INET,

    asset_id BIGINT
        REFERENCES assets(id)
        ON DELETE SET NULL,

    title TEXT NOT NULL,

    description TEXT,

    event_count INTEGER NOT NULL DEFAULT 0
        CHECK (event_count >= 0),

    first_seen TIMESTAMPTZ NOT NULL,

    last_seen TIMESTAMPTZ NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_alerts_alert_type
    ON alerts(alert_type);


CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON alerts(status);


CREATE INDEX IF NOT EXISTS idx_alerts_severity
    ON alerts(severity);


CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
    ON alerts(source_ip);


CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip
    ON alerts(destination_ip);


CREATE INDEX IF NOT EXISTS idx_alerts_asset_id
    ON alerts(asset_id);


CREATE INDEX IF NOT EXISTS idx_alerts_last_seen
    ON alerts(last_seen);


-- Prevent duplicate OPEN alerts for the same
-- detection type and source/destination pair.
CREATE UNIQUE INDEX IF NOT EXISTS uq_open_alert_source_destination
    ON alerts(
        alert_type,
        source_ip,
        destination_ip
    )
    WHERE status = 'OPEN';