-- ==========================================
-- VulnWatch Database Schema
-- Phase 3D: Asset Discovery
-- ==========================================

-- Stores each Nmap scan
CREATE TABLE scans (
    id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    target INET NOT NULL,
    nmap_command TEXT NOT NULL,
    scanner_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stores discovered hosts/assets
CREATE TABLE assets (
    id BIGSERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    mac_address MACADDR,
    hostname TEXT,
    os TEXT,
    os_accuracy SMALLINT CHECK (os_accuracy BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Stores ports/services discovered on each asset
CREATE TABLE services (
    id BIGSERIAL PRIMARY KEY,

    asset_id BIGINT NOT NULL
        REFERENCES assets(id)
        ON DELETE CASCADE,

    port INTEGER NOT NULL
        CHECK (port BETWEEN 1 AND 65535),

    protocol TEXT NOT NULL
        CHECK (protocol IN ('tcp', 'udp')),

    service_name TEXT,
    product TEXT,
    version TEXT,
    cpe TEXT,

    state TEXT NOT NULL DEFAULT 'open'
        CHECK (state IN ('open', 'closed', 'filtered', 'unknown')),

    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    last_scan_id BIGINT
        REFERENCES scans(id)
        ON DELETE SET NULL,

    CONSTRAINT unique_asset_service
        UNIQUE (asset_id, port, protocol)
);

-- Indexes for faster lookups
CREATE INDEX idx_services_asset_id
    ON services(asset_id);

CREATE INDEX idx_services_last_scan_id
    ON services(last_scan_id);

CREATE INDEX idx_scans_started_at
    ON scans(started_at);