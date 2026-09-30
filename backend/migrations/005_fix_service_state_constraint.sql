-- ==========================================
-- PHASE 15: FIX SERVICE STATE CONSTRAINT
-- ==========================================
--
-- Keeps the database validation consistent with
-- backend/scan_import.py NmapState values.
--
-- Existing valid data is preserved.
-- ==========================================

BEGIN;

-- Find and remove the existing CHECK constraint on
-- services.state, regardless of its automatically
-- generated PostgreSQL constraint name.
DO $$
DECLARE
    existing_constraint TEXT;
BEGIN
    SELECT conname
    INTO existing_constraint
    FROM pg_constraint
    WHERE conrelid = 'public.services'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) LIKE '%state%'
      AND pg_get_constraintdef(oid) LIKE '%open%'
      AND pg_get_constraintdef(oid) LIKE '%closed%'
      AND pg_get_constraintdef(oid) LIKE '%filtered%'
    LIMIT 1;

    IF existing_constraint IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE public.services DROP CONSTRAINT %I',
            existing_constraint
        );
    END IF;
END
$$;


-- Add the corrected service-state constraint.
--
-- These values match the NmapState validation
-- used by backend/scan_import.py.
ALTER TABLE public.services
ADD CONSTRAINT services_state_check
CHECK (
    state IN (
        'open',
        'closed',
        'filtered',
        'unfiltered',
        'open|filtered',
        'closed|filtered',
        'unknown'
    )
);


COMMIT;