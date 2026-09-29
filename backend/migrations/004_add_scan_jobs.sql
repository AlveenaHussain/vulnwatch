-- ==========================================
-- PHASE 14: TARGET SCAN JOBS
-- ==========================================

CREATE TABLE IF NOT EXISTS scan_jobs (
    id BIGSERIAL PRIMARY KEY,

    target_input TEXT NOT NULL,

    target_ip INET NOT NULL,

    scanner_ip INET NOT NULL,

    status TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (
            status IN (
                'PENDING',
                'RUNNING',
                'COMPLETED',
                'FAILED'
            )
        ),

    nmap_command TEXT,

    error_message TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    started_at TIMESTAMPTZ,

    completed_at TIMESTAMPTZ,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status
    ON scan_jobs(status);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created_at
    ON scan_jobs(created_at);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_target_ip
    ON scan_jobs(target_ip);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_scanner_ip
    ON scan_jobs(scanner_ip);