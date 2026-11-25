-- Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2
-- Migration 004: Consensus Persistence, Unique Proposals, Canon Versioning & Snapshots
-- Idempotent, reversible, fail-closed schema migration.

BEGIN TRANSACTION;

-- ============================================================================
-- 1. Concurrency Controls: Acquire Exclusive Table Locks
-- ============================================================================

-- EXCLUSIVE blocks concurrent write access and row-level locking on witness_raft_state,
-- aligning with application transaction lock hierarchy (witness_raft_state -> witness_consensus_log)
-- to prevent 40P01 deadlocks during concurrent execution.
LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;

-- SHARE ROW EXCLUSIVE blocks concurrent INSERT, UPDATE, DELETE on witness_consensus_log
-- while permitting concurrent read transactions.
LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;

-- ============================================================================
-- 2. Preflight Validation: Assert Zero Duplicate Proposals
-- ============================================================================

DO $$
DECLARE
    v_dup_count INT;
BEGIN
    SELECT COUNT(*) INTO v_dup_count
    FROM (
        SELECT epoch_id, proposal_id
        FROM witness_consensus_log
        WHERE proposal_id IS NOT NULL
        GROUP BY epoch_id, proposal_id
        HAVING COUNT(*) > 1
    ) dups;

    IF v_dup_count > 0 THEN
        RAISE EXCEPTION 'Migration 004 preflight check failed: found % duplicate (epoch_id, proposal_id) pair(s) in witness_consensus_log. Aborting.', v_dup_count;
    END IF;
END $$;

-- ============================================================================
-- 3. Replace Non-Unique Proposal Index with Partial Unique Index
-- ============================================================================

DROP INDEX IF EXISTS idx_consensus_log_proposal_id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_consensus_log_proposal_id
ON witness_consensus_log (epoch_id, proposal_id)
WHERE proposal_id IS NOT NULL;

-- ============================================================================
-- 4. Augment witness_consensus_log with Canonicalization Version & Physical Sub-Index
-- ============================================================================

ALTER TABLE witness_consensus_log
ADD COLUMN IF NOT EXISTS canonicalization_version SMALLINT NOT NULL DEFAULT 1,
ADD COLUMN IF NOT EXISTS sub_index INT NOT NULL DEFAULT 0;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_consensus_log_canon_ver') THEN
        ALTER TABLE witness_consensus_log
        ADD CONSTRAINT chk_consensus_log_canon_ver CHECK (canonicalization_version IN (1, 2));
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_consensus_log_sub_index') THEN
        ALTER TABLE witness_consensus_log
        ADD CONSTRAINT chk_consensus_log_sub_index CHECK (sub_index >= 0);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_consensus_log_canon_ver
ON witness_consensus_log (epoch_id, canonicalization_version);

-- ============================================================================
-- 5. Augment witness_raft_state with Physical Cursor & Snapshot Tracking
-- ============================================================================

ALTER TABLE witness_raft_state
ADD COLUMN IF NOT EXISTS last_applied_etcd_revision BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_applied_sub_index INT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_consecutive_persisted_index BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_snapshot_index BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_snapshot_hash VARCHAR(64) NOT NULL DEFAULT '';

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_raft_state_etcd_rev') THEN
        ALTER TABLE witness_raft_state
        ADD CONSTRAINT chk_raft_state_etcd_rev CHECK (last_applied_etcd_revision >= 0);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_raft_state_sub_idx') THEN
        ALTER TABLE witness_raft_state
        ADD CONSTRAINT chk_raft_state_sub_idx CHECK (last_applied_sub_index >= 0);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_raft_state_consec_idx') THEN
        ALTER TABLE witness_raft_state
        ADD CONSTRAINT chk_raft_state_consec_idx CHECK (last_consecutive_persisted_index >= 0);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_raft_state_snap_idx') THEN
        ALTER TABLE witness_raft_state
        ADD CONSTRAINT chk_raft_state_snap_idx CHECK (last_snapshot_index >= 0);
    END IF;
END $$;

-- ============================================================================
-- 6. Bootstrap Missing witness_raft_state Rows
-- ============================================================================

-- Bootstrap any epochs present in witness_consensus_log that lack a raft state entry
INSERT INTO witness_raft_state (
    cluster_id,
    epoch_id,
    last_applied_index,
    last_applied_term,
    last_applied_hash,
    updated_at_seconds,
    last_applied_etcd_revision,
    last_applied_sub_index,
    last_consecutive_persisted_index,
    last_snapshot_index,
    last_snapshot_hash
)
SELECT 
    'default-cluster',
    l.epoch_id,
    0,
    0,
    '',
    EXTRACT(EPOCH FROM clock_timestamp())::BIGINT,
    0,
    0,
    0,
    0,
    ''
FROM witness_consensus_log l
GROUP BY l.epoch_id
ON CONFLICT (cluster_id, epoch_id) DO NOTHING;

-- Also bootstrap any registered epochs from witness_epochs that lack a raft state entry
INSERT INTO witness_raft_state (
    cluster_id,
    epoch_id,
    last_applied_index,
    last_applied_term,
    last_applied_hash,
    updated_at_seconds,
    last_applied_etcd_revision,
    last_applied_sub_index,
    last_consecutive_persisted_index,
    last_snapshot_index,
    last_snapshot_hash
)
SELECT 
    'default-cluster',
    e.epoch_id,
    0,
    0,
    '',
    EXTRACT(EPOCH FROM clock_timestamp())::BIGINT,
    0,
    0,
    0,
    0,
    ''
FROM witness_epochs e
ON CONFLICT (cluster_id, epoch_id) DO NOTHING;

-- ============================================================================
-- 7. Strict Contiguous Durability Backfill (Scoped by cluster_id, epoch_id)
-- ============================================================================

DO $$
DECLARE
    r RECORD;
    v_min_index BIGINT;
    v_max_index BIGINT;
    v_total_rows BIGINT;
    v_distinct_rows BIGINT;
    v_contiguous_max BIGINT;
    v_last_persisted_rev BIGINT;
    v_last_sub_idx INT;
BEGIN
    FOR r IN SELECT cluster_id, epoch_id, last_consecutive_persisted_index FROM witness_raft_state LOOP
        SELECT MIN(log_index), MAX(log_index), COUNT(*), COUNT(DISTINCT log_index)
        INTO v_min_index, v_max_index, v_total_rows, v_distinct_rows
        FROM witness_consensus_log
        WHERE epoch_id = r.epoch_id;

        -- Scenario A: Empty Log (Clean epoch with zero committed consensus entries)
        IF v_total_rows = 0 THEN
            UPDATE witness_raft_state
            SET last_consecutive_persisted_index = 0
            WHERE cluster_id = r.cluster_id AND epoch_id = r.epoch_id AND last_consecutive_persisted_index = 0;
        ELSE
            -- Scenario B: Non-1 Start (Index does not start at 1)
            IF v_min_index != 1 THEN
                RAISE EXCEPTION 'Migration 004 aborted: epoch % log_index does not start at 1 (starts at %). Durable prefix cannot be proven.', r.epoch_id, v_min_index;
            END IF;

            -- Scenario C: Duplicate Log Indices
            IF v_total_rows != v_distinct_rows THEN
                RAISE EXCEPTION 'Migration 004 aborted: duplicate log_index detected in epoch % (total %, distinct %). Inconsistent log history.', r.epoch_id, v_total_rows, v_distinct_rows;
            END IF;

            -- Scenario D: Detect Gaps via Contiguous Prefix Series [1, v_max_index]
            SELECT COALESCE(MIN(expected_index) - 1, v_max_index)
            INTO v_contiguous_max
            FROM (
                SELECT generate_series(1, v_max_index) AS expected_index
            ) exp
            LEFT JOIN witness_consensus_log act
              ON act.epoch_id = r.epoch_id AND act.log_index = exp.expected_index
            WHERE act.log_index IS NULL;

            -- Fail Closed on Any Gap
            IF v_contiguous_max < v_max_index THEN
                RAISE EXCEPTION 'Migration 004 aborted: non-contiguous log index sequence in epoch % (contiguous reaches %, max index is %). Durable prefix cannot be proven.', r.epoch_id, v_contiguous_max, v_max_index;
            END IF;

            -- Scenario E: Fetch physical cursor at max contiguous index
            SELECT etcd_revision, sub_index
            INTO v_last_persisted_rev, v_last_sub_idx
            FROM witness_consensus_log
            WHERE epoch_id = r.epoch_id AND log_index = v_contiguous_max;

            -- Apply verified contiguous watermark and physical cursor
            UPDATE witness_raft_state
            SET last_consecutive_persisted_index = v_contiguous_max,
                last_applied_etcd_revision = COALESCE(v_last_persisted_rev, last_applied_etcd_revision),
                last_applied_sub_index = COALESCE(v_last_sub_idx, last_applied_sub_index)
            WHERE cluster_id = r.cluster_id AND epoch_id = r.epoch_id AND last_consecutive_persisted_index = 0;
        END IF;
    END LOOP;
END $$;

-- ============================================================================
-- 8. Create witness_snapshots Table with Comprehensive Metadata & Lifecycle Status
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_snapshots (
    snapshot_id VARCHAR(64) NOT NULL,
    cluster_id VARCHAR(64) NOT NULL,
    epoch_id VARCHAR(64) NOT NULL,
    snapshot_index BIGINT NOT NULL,
    snapshot_hash VARCHAR(64) NOT NULL,
    chain_head_hash VARCHAR(64) NOT NULL,
    etcd_revision BIGINT NOT NULL,
    sub_index INT NOT NULL,
    format_version SMALLINT NOT NULL DEFAULT 1,
    canonicalization_version SMALLINT NOT NULL DEFAULT 2,
    storage_backend VARCHAR(32) NOT NULL DEFAULT 'posix_fs',
    storage_uri VARCHAR(512) NOT NULL,
    byte_size BIGINT NOT NULL DEFAULT 0,
    created_at_seconds BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'COMMITTED',
    updated_at_seconds BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT,
    PRIMARY KEY (cluster_id, epoch_id, snapshot_index),
    CONSTRAINT uq_snapshots_id UNIQUE (snapshot_id),
    CONSTRAINT chk_snapshots_index CHECK (snapshot_index >= 0),
    CONSTRAINT chk_snapshots_etcd_rev CHECK (etcd_revision >= 0),
    CONSTRAINT chk_snapshots_sub_idx CHECK (sub_index >= 0),
    CONSTRAINT chk_snapshots_format_ver CHECK (format_version >= 1),
    CONSTRAINT chk_snapshots_canon_ver CHECK (canonicalization_version IN (1, 2)),
    CONSTRAINT chk_snapshots_backend CHECK (storage_backend IN ('posix_fs', 's3', 'gcs')),
    CONSTRAINT chk_snapshots_byte_size CHECK (byte_size >= 0),
    CONSTRAINT chk_snapshots_status CHECK (status IN ('STAGED', 'COMMITTED', 'DELETING'))
);

CREATE INDEX IF NOT EXISTS idx_snapshots_epoch_time 
ON witness_snapshots (cluster_id, epoch_id, created_at_seconds DESC);

CREATE INDEX IF NOT EXISTS idx_snapshots_status
ON witness_snapshots (status);

-- ============================================================================
-- 9. Create witness_snapshot_leases Table for Race-Safe Cleanup
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_snapshot_leases (
    snapshot_id VARCHAR(64) NOT NULL,
    worker_id VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (snapshot_id)
);

CREATE INDEX IF NOT EXISTS idx_snapshot_leases_expiry
ON witness_snapshot_leases (expires_at);

-- ============================================================================
-- 10. Lifecycle State Machine & Deep Immutability Trigger on witness_snapshots
-- ============================================================================

CREATE OR REPLACE FUNCTION trg_witness_snapshots_lifecycle_func()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Assert immutable fields cannot be altered once written
        IF NEW.snapshot_id != OLD.snapshot_id OR
           NEW.cluster_id != OLD.cluster_id OR
           NEW.epoch_id != OLD.epoch_id OR
           NEW.snapshot_index != OLD.snapshot_index OR
           NEW.snapshot_hash != OLD.snapshot_hash OR
           NEW.chain_head_hash != OLD.chain_head_hash OR
           NEW.etcd_revision != OLD.etcd_revision OR
           NEW.sub_index != OLD.sub_index OR
           NEW.format_version != OLD.format_version OR
           NEW.canonicalization_version != OLD.canonicalization_version OR
           NEW.storage_backend != OLD.storage_backend OR
           NEW.storage_uri != OLD.storage_uri OR
           NEW.byte_size != OLD.byte_size OR
           NEW.created_at_seconds != OLD.created_at_seconds THEN
            RAISE EXCEPTION 'witness_snapshots metadata fields are immutable and cannot be updated';
        END IF;

        -- Enforce valid lifecycle transitions: STAGED -> COMMITTED -> DELETING
        IF OLD.status = 'STAGED' AND NEW.status NOT IN ('STAGED', 'COMMITTED', 'DELETING') THEN
            RAISE EXCEPTION 'Invalid snapshot status transition from STAGED to %', NEW.status;
        ELSIF OLD.status = 'COMMITTED' AND NEW.status NOT IN ('COMMITTED', 'DELETING') THEN
            RAISE EXCEPTION 'Invalid snapshot status transition from COMMITTED to %', NEW.status;
        ELSIF OLD.status = 'DELETING' AND NEW.status != 'DELETING' THEN
            RAISE EXCEPTION 'Invalid snapshot status transition: snapshot in DELETING state cannot transition to %', NEW.status;
        END IF;

        NEW.updated_at_seconds := EXTRACT(EPOCH FROM clock_timestamp())::BIGINT;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        -- Only snapshots explicitly transitioned to DELETING can be deleted from the database
        IF OLD.status != 'DELETING' THEN
            RAISE EXCEPTION 'Cannot delete snapshot % with status %: must be in DELETING state before removal', OLD.snapshot_id, OLD.status;
        END IF;
        RETURN OLD;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_witness_snapshots_lifecycle ON witness_snapshots;
CREATE TRIGGER trg_witness_snapshots_lifecycle
BEFORE UPDATE OR DELETE ON witness_snapshots
FOR EACH ROW EXECUTE FUNCTION trg_witness_snapshots_lifecycle_func();

DROP TRIGGER IF EXISTS trg_witness_snapshots_no_truncate ON witness_snapshots;
CREATE TRIGGER trg_witness_snapshots_no_truncate
BEFORE TRUNCATE ON witness_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

COMMIT;
