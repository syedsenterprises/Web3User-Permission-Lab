-- Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2
-- Migration 004 Rollback: Reversible restoration to Migration 003 baseline
-- Guarded by active data protection check (requires stage2b2.allow_destructive_rollback = true)

BEGIN TRANSACTION;

-- ============================================================================
-- 1. Safety Guard: Prevent Accidental Rollback if Active Stage 2-B.2 Data Exists
-- ============================================================================

DO $$
DECLARE
    v_snap_count INT := 0;
    v_persisted_rev BIGINT := 0;
    v_persisted_idx BIGINT := 0;
    v_override TEXT;
BEGIN
    -- Check for committed snapshots
    IF EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'witness_snapshots' AND table_schema = 'public'
    ) THEN
        SELECT COUNT(*) INTO v_snap_count FROM witness_snapshots;
    END IF;

    -- Check for persisted etcd revisions or contiguous index watermarks
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'witness_raft_state' AND column_name = 'last_applied_etcd_revision'
    ) THEN
        SELECT 
            COALESCE(MAX(last_applied_etcd_revision), 0),
            COALESCE(MAX(last_consecutive_persisted_index), 0)
        INTO v_persisted_rev, v_persisted_idx
        FROM witness_raft_state;
    END IF;

    -- If active Stage 2-B.2 data exists, block destructive rollback unless explicitly forced
    IF (v_snap_count > 0 OR v_persisted_rev > 0 OR v_persisted_idx > 0) THEN
        BEGIN
            v_override := current_setting('stage2b2.allow_destructive_rollback', true);
        EXCEPTION WHEN OTHERS THEN
            v_override := NULL;
        END;

        IF v_override IS DISTINCT FROM 'true' THEN
            RAISE EXCEPTION 'Migration 004 rollback aborted: active Stage 2-B.2 data detected (% snapshots, max persisted etcd revision %, max persisted index %). Set stage2b2.allow_destructive_rollback = true to force.', v_snap_count, v_persisted_rev, v_persisted_idx;
        END IF;
    END IF;
END $$;

-- ============================================================================
-- 2. Drop Snapshot Lifecycle Triggers, Functions, and Tables
-- ============================================================================

DROP TRIGGER IF EXISTS trg_witness_snapshots_lifecycle ON witness_snapshots;
DROP TRIGGER IF EXISTS trg_witness_snapshots_no_truncate ON witness_snapshots;
DROP FUNCTION IF EXISTS trg_witness_snapshots_lifecycle_func() CASCADE;

DROP TABLE IF EXISTS witness_snapshot_leases CASCADE;
DROP TABLE IF EXISTS witness_snapshots CASCADE;

-- ============================================================================
-- 3. Remove Cursor Columns and Constraints from witness_raft_state
-- ============================================================================

ALTER TABLE witness_raft_state DROP CONSTRAINT IF EXISTS chk_raft_state_etcd_rev;
ALTER TABLE witness_raft_state DROP CONSTRAINT IF EXISTS chk_raft_state_sub_idx;
ALTER TABLE witness_raft_state DROP CONSTRAINT IF EXISTS chk_raft_state_consec_idx;
ALTER TABLE witness_raft_state DROP CONSTRAINT IF EXISTS chk_raft_state_snap_idx;

ALTER TABLE witness_raft_state
DROP COLUMN IF EXISTS last_applied_etcd_revision,
DROP COLUMN IF EXISTS last_applied_sub_index,
DROP COLUMN IF EXISTS last_consecutive_persisted_index,
DROP COLUMN IF EXISTS last_snapshot_index,
DROP COLUMN IF EXISTS last_snapshot_hash;

-- ============================================================================
-- 4. Revert Proposal Index on witness_consensus_log to Exact Migration 003 Definition
-- ============================================================================

DROP INDEX IF EXISTS uq_consensus_log_proposal_id;

CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id
ON witness_consensus_log (proposal_id)
WHERE proposal_id IS NOT NULL;

-- ============================================================================
-- 5. Drop Canonicalization Version Column and Index from witness_consensus_log
-- ============================================================================

DROP INDEX IF EXISTS idx_consensus_log_canon_ver;
ALTER TABLE witness_consensus_log DROP CONSTRAINT IF EXISTS chk_consensus_log_canon_ver;
ALTER TABLE witness_consensus_log DROP COLUMN IF EXISTS canonicalization_version;

-- ============================================================================
-- 6. Drop Sub-Index Column from witness_consensus_log
-- ============================================================================

ALTER TABLE witness_consensus_log DROP CONSTRAINT IF EXISTS chk_consensus_log_sub_index;
ALTER TABLE witness_consensus_log DROP COLUMN IF EXISTS sub_index;

COMMIT;
