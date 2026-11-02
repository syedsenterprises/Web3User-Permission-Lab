-- Web3User Permission Lab - Milestone 13-D Phase D3: Consensus State & Quarantine Foundation Migration
-- Idempotent, reversible, non-destructive schema migration.

BEGIN TRANSACTION;

-- ============================================================================
-- 1. Pre-Migration Validation & Legacy State Backfill
-- ============================================================================

-- Fail-closed validation for unrecognized or NULL states before augmenting
DO $$
DECLARE
    v_invalid_count INT;
BEGIN
    SELECT COUNT(*) INTO v_invalid_count
    FROM witness_epochs
    WHERE state IS NULL OR state NOT IN ('ACTIVE', 'QUARANTINED', 'TERMINATED', 'ARCHIVED', 'CLOSED');

    IF v_invalid_count > 0 THEN
        RAISE EXCEPTION 'Migration 003 pre-check failed: found % epoch(s) with unrecognized or NULL state', v_invalid_count;
    END IF;
END $$;

ALTER TABLE witness_epochs
ADD COLUMN IF NOT EXISTS is_quarantined BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS quarantined_at_seconds BIGINT NULL,
ADD COLUMN IF NOT EXISTS quarantine_reason VARCHAR(255) NULL,
ADD COLUMN IF NOT EXISTS quarantine_details JSONB NULL;

-- Backfill / synchronize existing quarantined epochs with required metadata
UPDATE witness_epochs
SET is_quarantined = true,
    is_active = false,
    quarantined_at_seconds = COALESCE(quarantined_at_seconds, updated_at_seconds, created_at_seconds),
    quarantine_reason = COALESCE(quarantine_reason, 'LEGACY_D2_QUARANTINE')
WHERE state = 'QUARANTINED';

-- Backfill active epochs
UPDATE witness_epochs
SET is_quarantined = false,
    is_active = true,
    quarantined_at_seconds = NULL,
    quarantine_reason = NULL,
    quarantine_details = NULL
WHERE state = 'ACTIVE';

-- Backfill terminated / archived / closed epochs
UPDATE witness_epochs
SET is_quarantined = false,
    is_active = false,
    quarantined_at_seconds = NULL,
    quarantine_reason = NULL,
    quarantine_details = NULL
WHERE state IN ('TERMINATED', 'ARCHIVED', 'CLOSED');

-- Ensure consistency and quarantine invariants on witness_epochs
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_epochs_quarantine_consistency'
    ) THEN
        ALTER TABLE witness_epochs
        ADD CONSTRAINT chk_epochs_quarantine_consistency
        CHECK (NOT (is_quarantined = true AND is_active = true));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_epochs_state_quarantine_parity'
    ) THEN
        ALTER TABLE witness_epochs
        ADD CONSTRAINT chk_epochs_state_quarantine_parity
        CHECK (
            (is_quarantined = true AND state = 'QUARANTINED') OR
            (is_quarantined = false AND state != 'QUARANTINED')
        );
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_epochs_quarantine_metadata'
    ) THEN
        ALTER TABLE witness_epochs
        ADD CONSTRAINT chk_epochs_quarantine_metadata
        CHECK (
            (is_quarantined = true AND quarantined_at_seconds IS NOT NULL AND quarantine_reason IS NOT NULL) OR
            (is_quarantined = false AND quarantined_at_seconds IS NULL AND quarantine_reason IS NULL)
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_epochs_quarantine_active
ON witness_epochs (is_quarantined, is_active);

-- Update projection view alias for architectural specification parity
DROP VIEW IF EXISTS witness_epoch_state;
CREATE VIEW witness_epoch_state AS 
SELECT 
    epoch_id, 
    epoch_height, 
    created_at_seconds, 
    chain_head_hash, 
    last_sequence_number, 
    state, 
    updated_at_seconds,
    is_quarantined,
    is_active,
    quarantined_at_seconds,
    quarantine_reason,
    quarantine_details
FROM witness_epochs;

-- Preserve view owner and permissions
DO $$
DECLARE
    v_owner TEXT;
BEGIN
    SELECT tableowner INTO v_owner FROM pg_tables WHERE tablename = 'witness_epochs' AND schemaname = 'public';
    IF v_owner IS NOT NULL THEN
        EXECUTE format('ALTER VIEW witness_epoch_state OWNER TO %I', v_owner);
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'web3user_app') THEN
        EXECUTE 'GRANT SELECT ON witness_epoch_state TO web3user_app';
    END IF;
END $$;

-- ============================================================================
-- 2. Define witness_consensus_log Table (Historical Consensus Event Log)
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_consensus_log (
    epoch_id VARCHAR(64) NOT NULL,
    log_index BIGINT NOT NULL,
    term BIGINT NOT NULL,
    etcd_revision BIGINT NOT NULL,
    payload_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    proposal_id VARCHAR(128) NULL,
    committed_at_seconds BIGINT NOT NULL,
    PRIMARY KEY (epoch_id, log_index),
    CONSTRAINT chk_consensus_log_index CHECK (log_index > 0),
    CONSTRAINT chk_consensus_log_term CHECK (term >= 0),
    CONSTRAINT chk_consensus_log_revision CHECK (etcd_revision >= 0)
);

CREATE INDEX IF NOT EXISTS idx_consensus_log_payload_hash 
ON witness_consensus_log (epoch_id, payload_hash);

CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id 
ON witness_consensus_log (proposal_id) 
WHERE proposal_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_consensus_log_epoch_time 
ON witness_consensus_log (epoch_id, committed_at_seconds);

-- Immutability Protection: Append-only enforcement (No UPDATE or DELETE)
CREATE OR REPLACE FUNCTION trg_witness_consensus_log_immutable_func()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'witness_consensus_log is append-only and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_witness_consensus_log_immutable ON witness_consensus_log;
CREATE TRIGGER trg_witness_consensus_log_immutable
BEFORE UPDATE OR DELETE ON witness_consensus_log
FOR EACH ROW EXECUTE FUNCTION trg_witness_consensus_log_immutable_func();

DROP TRIGGER IF EXISTS trg_witness_consensus_log_no_truncate ON witness_consensus_log;
CREATE TRIGGER trg_witness_consensus_log_no_truncate
BEFORE TRUNCATE ON witness_consensus_log
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

-- ============================================================================
-- 3. Define witness_raft_state Table (State Machine Applied Index Tracker)
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_raft_state (
    cluster_id VARCHAR(64) NOT NULL DEFAULT 'default-cluster',
    epoch_id VARCHAR(64) NOT NULL,
    last_applied_index BIGINT NOT NULL DEFAULT 0,
    last_applied_term BIGINT NOT NULL DEFAULT 0,
    last_applied_hash VARCHAR(64) NOT NULL DEFAULT '',
    updated_at_seconds BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT,
    PRIMARY KEY (cluster_id, epoch_id),
    CONSTRAINT chk_raft_state_applied_index CHECK (last_applied_index >= 0),
    CONSTRAINT chk_raft_state_applied_term CHECK (last_applied_term >= 0)
);

CREATE INDEX IF NOT EXISTS idx_raft_state_cluster 
ON witness_raft_state (cluster_id, last_applied_index);

-- Deletion protection on witness_raft_state
CREATE OR REPLACE FUNCTION trg_witness_raft_state_no_delete_func()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'witness_raft_state records cannot be deleted; state progress is permanent';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_witness_raft_state_no_delete ON witness_raft_state;
CREATE TRIGGER trg_witness_raft_state_no_delete
BEFORE DELETE ON witness_raft_state
FOR EACH ROW EXECUTE FUNCTION trg_witness_raft_state_no_delete_func();

DROP TRIGGER IF EXISTS trg_witness_raft_state_no_truncate ON witness_raft_state;
CREATE TRIGGER trg_witness_raft_state_no_truncate
BEFORE TRUNCATE ON witness_raft_state
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

-- Seed initial witness_raft_state entries for any existing registered epochs
INSERT INTO witness_raft_state (cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash, updated_at_seconds)
SELECT 
    'default-cluster',
    epoch_id,
    0,
    0,
    '',
    EXTRACT(EPOCH FROM clock_timestamp())::BIGINT
FROM witness_epochs
ON CONFLICT (cluster_id, epoch_id) DO NOTHING;

COMMIT;
