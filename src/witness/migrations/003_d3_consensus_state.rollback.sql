-- Web3User Permission Lab - Milestone 13-D Phase D3: Consensus State Foundation Migration Rollback
-- Reverts all changes introduced by 003_d3_consensus_state.sql cleanly and safely.

BEGIN TRANSACTION;

-- 1. Drop consensus state tables and triggers
DROP TABLE IF EXISTS witness_consensus_log CASCADE;
DROP TABLE IF EXISTS witness_raft_state CASCADE;

DROP FUNCTION IF EXISTS trg_witness_consensus_log_immutable_func() CASCADE;
DROP FUNCTION IF EXISTS trg_witness_raft_state_no_delete_func() CASCADE;

-- 2. Drop and recreate witness_epoch_state view to revert to exact D2 definition
DROP VIEW IF EXISTS witness_epoch_state;
CREATE VIEW witness_epoch_state AS 
SELECT epoch_id, epoch_height, created_at_seconds, chain_head_hash, last_sequence_number, state, updated_at_seconds
FROM witness_epochs;

-- 3. Restore exact original view ownership and runtime role privileges
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
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'web3user_admin') THEN
        EXECUTE 'GRANT ALL ON witness_epoch_state TO web3user_admin';
    END IF;
END $$;

-- 4. Drop constraints, indexes, and columns added to witness_epochs
ALTER TABLE witness_epochs DROP CONSTRAINT IF EXISTS chk_epochs_quarantine_consistency;
ALTER TABLE witness_epochs DROP CONSTRAINT IF EXISTS chk_epochs_state_quarantine_parity;
ALTER TABLE witness_epochs DROP CONSTRAINT IF EXISTS chk_epochs_quarantine_metadata;
DROP INDEX IF EXISTS idx_epochs_quarantine_active;

ALTER TABLE witness_epochs 
DROP COLUMN IF EXISTS is_quarantined,
DROP COLUMN IF EXISTS is_active,
DROP COLUMN IF EXISTS quarantined_at_seconds,
DROP COLUMN IF EXISTS quarantine_reason,
DROP COLUMN IF EXISTS quarantine_details;

COMMIT;
