-- Phase 12: Correlation Engine
-- Links existing vulnerabilities/findings with SOC alerts
-- belonging to the same asset.

CREATE TABLE IF NOT EXISTS correlations (
    id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL
        REFERENCES assets(id)
        ON DELETE CASCADE,

    alert_id BIGINT NOT NULL
        REFERENCES alerts(id)
        ON DELETE CASCADE,

    service_vulnerability_id BIGINT
        REFERENCES service_vulnerabilities(id)
        ON DELETE SET NULL,

    finding_id BIGINT
        REFERENCES findings(id)
        ON DELETE SET NULL,

    correlation_type TEXT NOT NULL
        CHECK (
            correlation_type IN (
                'ASSET_VULNERABILITY_ALERT'
            )
        ),

    priority TEXT NOT NULL
        CHECK (
            priority IN (
                'CRITICAL',
                'HIGH',
                'MEDIUM',
                'LOW',
                'INFO'
            )
        ),

    title TEXT NOT NULL,

    description TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_correlations_asset_id
    ON correlations(asset_id);


CREATE INDEX IF NOT EXISTS idx_correlations_alert_id
    ON correlations(alert_id);


CREATE INDEX IF NOT EXISTS idx_correlations_service_vulnerability_id
    ON correlations(service_vulnerability_id);


CREATE INDEX IF NOT EXISTS idx_correlations_finding_id
    ON correlations(finding_id);


CREATE INDEX IF NOT EXISTS idx_correlations_priority
    ON correlations(priority);


CREATE INDEX IF NOT EXISTS idx_correlations_created_at
    ON correlations(created_at);


-- Prevent the same alert and vulnerability
-- from creating duplicate correlation records.
CREATE UNIQUE INDEX IF NOT EXISTS uq_correlations_alert_vulnerability
    ON correlations(alert_id, service_vulnerability_id);