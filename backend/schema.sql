-- ==========================================
-- VulnWatch Database Schema
-- Phase 4: Vulnerability Management
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

-- ==========================================
-- Vulnerability Management
-- ==========================================

-- Stores each CVE only once
CREATE TABLE vulnerabilities (
    id BIGSERIAL PRIMARY KEY,

    cve_id TEXT NOT NULL UNIQUE,

    description TEXT,

    cvss_version TEXT
        CHECK (cvss_version IN ('2.0', '3.0', '3.1')),

    cvss_score NUMERIC(3,1)
        CHECK (cvss_score BETWEEN 0.0 AND 10.0),

    cvss_vector TEXT,

    severity TEXT NOT NULL
        CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),

    cwe TEXT,

    published TIMESTAMPTZ,

    last_modified TIMESTAMPTZ,

    nvd_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Maps vulnerabilities to discovered services
CREATE TABLE service_vulnerabilities (
    id BIGSERIAL PRIMARY KEY,

    service_id BIGINT NOT NULL
        REFERENCES services(id)
        ON DELETE CASCADE,

    vulnerability_id BIGINT NOT NULL
        REFERENCES vulnerabilities(id)
        ON DELETE CASCADE,

    matched_cpe TEXT,

    match_source TEXT NOT NULL DEFAULT 'nvd-cpe',

    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_service_vulnerability
        UNIQUE (service_id, vulnerability_id)
);

-- ==========================================
-- Indexes
-- ==========================================

CREATE INDEX idx_services_asset_id
    ON services(asset_id);

CREATE INDEX idx_services_last_scan_id
    ON services(last_scan_id);

CREATE INDEX idx_services_cpe
    ON services(cpe);

CREATE INDEX idx_scans_started_at
    ON scans(started_at);

CREATE INDEX idx_vulnerabilities_severity
    ON vulnerabilities(severity);

CREATE INDEX idx_vulnerabilities_cve_id
    ON vulnerabilities(cve_id);

CREATE INDEX idx_service_vulnerabilities_service_id
    ON service_vulnerabilities(service_id);

CREATE INDEX idx_service_vulnerabilities_vulnerability_id
    ON service_vulnerabilities(vulnerability_id);