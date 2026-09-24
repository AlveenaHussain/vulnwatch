-- ==========================================
-- VulnWatch Phase 10
-- Add SOC Security Events
-- ==========================================

CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT
        REFERENCES assets(id)
        ON DELETE SET NULL,

    event_type TEXT NOT NULL,

    event_time TIMESTAMPTZ NOT NULL,

    source_ip INET,

    destination_ip INET,

    protocol TEXT,

    source_port INTEGER
        CHECK (
            source_port IS NULL
            OR source_port BETWEEN 1 AND 65535
        ),

    destination_port INTEGER
        CHECK (
            destination_port IS NULL
            OR destination_port BETWEEN 1 AND 65535
        ),

    username TEXT,

    severity TEXT NOT NULL DEFAULT 'LOW'
        CHECK (
            severity IN (
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW',
                'INFO',
                'UNKNOWN'
            )
        ),

    raw_log TEXT,

    source TEXT NOT NULL DEFAULT 'lab-log',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_events_asset_id
    ON security_events(asset_id);

CREATE INDEX IF NOT EXISTS idx_security_events_event_time
    ON security_events(event_time);

CREATE INDEX IF NOT EXISTS idx_security_events_event_type
    ON security_events(event_type);

CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
    ON security_events(source_ip);

CREATE INDEX IF NOT EXISTS idx_security_events_destination_ip
    ON security_events(destination_ip);