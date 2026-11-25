-- Web3User Permission Lab - Milestone 13-D: PostgreSQL 16 Witness Storage Foundation
-- Strictly ACID-compliant schema with SERIALIZABLE isolation support, immutability triggers,
-- global authorization uniqueness, per-epoch sequence consistency, and append-only audit log protection.

-- ============================================================================
-- 1. Epoch Tracking & Per-Epoch Sequence Allocation (F1)
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_epochs (
    epoch_id VARCHAR(64) PRIMARY KEY,
    epoch_height BIGINT NOT NULL UNIQUE,
    created_at_seconds BIGINT NOT NULL
);

-- Helper function to guarantee dynamic per-epoch monotonic sequence generators starting at 1
CREATE OR REPLACE FUNCTION get_or_create_epoch_sequence(p_epoch_id VARCHAR(64))
RETURNS VARCHAR(128) AS $$
DECLARE
    v_seq_name VARCHAR(128);
BEGIN
    v_seq_name := 'witness_seq_' || regexp_replace(p_epoch_id, '[^a-zA-Z0-9_]', '_', 'g');
    EXECUTE 'CREATE SEQUENCE IF NOT EXISTS ' || quote_ident(v_seq_name) || ' AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE CACHE 1';
    RETURN v_seq_name;
END;
$$ LANGUAGE plpgsql;

-- Default fallback sequence
CREATE SEQUENCE IF NOT EXISTS witness_sequence_seq AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE;

-- ============================================================================
-- 2. witness_tickets Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_tickets (
    ticket_id VARCHAR(64) PRIMARY KEY,
    authorization_id VARCHAR(128) NOT NULL,
    epoch_id VARCHAR(64) NOT NULL,
    state VARCHAR(32) NOT NULL,
    binding_digest VARCHAR(128) NOT NULL,
    sequence_number BIGINT NULL,
    expires_at_seconds BIGINT NOT NULL,
    created_at_seconds BIGINT NOT NULL,
    updated_at_seconds BIGINT NOT NULL,
    idempotency_key VARCHAR(128) NULL,
    CONSTRAINT uq_witness_auth_id UNIQUE (authorization_id),
    CONSTRAINT uq_tickets_epoch_seq UNIQUE (epoch_id, sequence_number),
    CONSTRAINT chk_ticket_state CHECK (state IN (
        'RESERVED',
        'COMMITTING_SIGNING_PENDING',
        'COMMITTED',
        'RELEASED',
        'QUARANTINED_UNCONFIRMED',
        'QUARANTINED_BLOCKED',
        'RELEASED_AFTER_AUDIT',
        'DISPUTED'
    ))
);

CREATE INDEX IF NOT EXISTS idx_tickets_state_expiry ON witness_tickets (state, expires_at_seconds);
CREATE INDEX IF NOT EXISTS idx_tickets_epoch_seq ON witness_tickets (epoch_id, sequence_number);

-- ============================================================================
-- 3. witness_accumulators Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_accumulators (
    window_id VARCHAR(64) PRIMARY KEY,
    window_type VARCHAR(32) NOT NULL,
    window_start BIGINT NOT NULL,
    current_amount NUMERIC(78, 0) NOT NULL DEFAULT 0,
    held_amount NUMERIC(78, 0) NOT NULL DEFAULT 0,
    max_limit NUMERIC(78, 0) NOT NULL,
    CONSTRAINT chk_positive_amounts CHECK (current_amount >= 0 AND held_amount >= 0),
    CONSTRAINT chk_budget_limit CHECK (current_amount + held_amount <= max_limit)
);

-- ============================================================================
-- 4. witness_signing_outbox Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_signing_outbox (
    intent_id VARCHAR(64) PRIMARY KEY,
    ticket_id VARCHAR(64) NOT NULL REFERENCES witness_tickets(ticket_id) ON DELETE RESTRICT,
    epoch_id VARCHAR(64) NOT NULL,
    sequence_number BIGINT NOT NULL,
    preimage TEXT NOT NULL,
    status VARCHAR(32) NOT NULL,
    retry_count INT NOT NULL DEFAULT 0,
    last_error TEXT NULL,
    created_at_seconds BIGINT NOT NULL,
    updated_at_seconds BIGINT NOT NULL,
    CONSTRAINT uq_outbox_epoch_seq UNIQUE (epoch_id, sequence_number),
    CONSTRAINT chk_outbox_status CHECK (status IN ('PENDING', 'SIGNING', 'COMPLETED', 'FAILED'))
);

CREATE INDEX IF NOT EXISTS idx_outbox_pending ON witness_signing_outbox (status, created_at_seconds) WHERE status IN ('PENDING', 'SIGNING');

-- ============================================================================
-- 5. witness_receipts Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_receipts (
    ticket_id VARCHAR(64) PRIMARY KEY REFERENCES witness_tickets(ticket_id) ON DELETE RESTRICT,
    authorization_id VARCHAR(128) NOT NULL,
    epoch_id VARCHAR(64) NOT NULL,
    sequence_number BIGINT NOT NULL,
    witness_timestamp_seconds BIGINT NOT NULL,
    binding_digest VARCHAR(128) NOT NULL,
    signature BYTEA NOT NULL,
    receipt_json TEXT NOT NULL,
    receipt_chain_hash VARCHAR(64) NOT NULL,
    CONSTRAINT uq_receipts_epoch_seq UNIQUE (epoch_id, sequence_number),
    CONSTRAINT uq_receipts_auth_id UNIQUE (authorization_id)
);

-- Receipt Immutability Function and Triggers (F4)
CREATE OR REPLACE FUNCTION trg_witness_receipts_immutable_func()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Witness receipts are immutable and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_witness_receipts_immutable ON witness_receipts;
CREATE TRIGGER trg_witness_receipts_immutable
BEFORE UPDATE OR DELETE ON witness_receipts
FOR EACH ROW EXECUTE FUNCTION trg_witness_receipts_immutable_func();

-- Statement-Level TRUNCATE Blocker (F4)
CREATE OR REPLACE FUNCTION trg_witness_block_truncate_func()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'TRUNCATE is strictly prohibited on witness immutable tables';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_witness_receipts_no_truncate ON witness_receipts;
CREATE TRIGGER trg_witness_receipts_no_truncate
BEFORE TRUNCATE ON witness_receipts
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

-- ============================================================================
-- 6. witness_audit_log Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_audit_log (
    log_id BIGSERIAL PRIMARY KEY,
    ticket_id VARCHAR(64) NULL REFERENCES witness_tickets(ticket_id) ON DELETE NO ACTION,
    authorization_id VARCHAR(128) NULL,
    action VARCHAR(64) NOT NULL,
    from_state VARCHAR(32) NULL,
    to_state VARCHAR(32) NOT NULL,
    actor_id VARCHAR(128) NOT NULL,
    details JSONB NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit Log Append-Only Function and Triggers (F4)
CREATE OR REPLACE FUNCTION trg_witness_audit_log_append_only_func()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'witness_audit_log is append-only and cannot be updated or deleted';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_witness_audit_log_append_only ON witness_audit_log;
CREATE TRIGGER trg_witness_audit_log_append_only
BEFORE UPDATE OR DELETE ON witness_audit_log
FOR EACH ROW EXECUTE FUNCTION trg_witness_audit_log_append_only_func();

DROP TRIGGER IF EXISTS trg_witness_audit_log_no_truncate ON witness_audit_log;
CREATE TRIGGER trg_witness_audit_log_no_truncate
BEFORE TRUNCATE ON witness_audit_log
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

-- ============================================================================
-- 7. witness_sequence_gaps Table (F2: Sequence Gap Accounting & Reconciliation)
-- ============================================================================

CREATE TABLE IF NOT EXISTS witness_sequence_gaps (
    epoch_id VARCHAR(64) NOT NULL,
    sequence_number BIGINT NOT NULL,
    gap_reason VARCHAR(64) NOT NULL, -- 'TRANSACTION_ROLLBACK', 'PROCESS_CRASH', 'OUTBOX_FAILED', 'RECONCILED_GAP'
    ticket_id VARCHAR(64) NULL,
    detected_at_seconds BIGINT NOT NULL,
    details JSONB NULL,
    PRIMARY KEY (epoch_id, sequence_number)
);

CREATE INDEX IF NOT EXISTS idx_sequence_gaps_epoch ON witness_sequence_gaps (epoch_id, sequence_number);

DROP TRIGGER IF EXISTS trg_witness_gaps_no_truncate ON witness_sequence_gaps;
CREATE TRIGGER trg_witness_gaps_no_truncate
BEFORE TRUNCATE ON witness_sequence_gaps
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

-- ============================================================================
-- 8. Application Role & Table Ownership Reference Model (F4)
-- ============================================================================
-- Table Owner: web3user_admin (Migration / Provisioning Role ONLY)
-- Runtime Role: web3user_app (Stateless Kubernetes Engine / Witness Pods)
--
-- GRANTS:
-- GRANT USAGE ON SCHEMA public TO web3user_app;
-- GRANT SELECT, INSERT, UPDATE ON witness_tickets TO web3user_app;
-- GRANT SELECT, INSERT, UPDATE ON witness_accumulators TO web3user_app;
-- GRANT SELECT, INSERT, UPDATE ON witness_signing_outbox TO web3user_app;
-- GRANT SELECT, INSERT ON witness_receipts TO web3user_app;
-- GRANT SELECT, INSERT ON witness_audit_log TO web3user_app;
-- GRANT SELECT, INSERT ON witness_sequence_gaps TO web3user_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO web3user_app;
--
-- ============================================================================
-- 9. Milestone 13-D Phase D2: Epoch State & Outbox Fencing Augmentations
-- ============================================================================

ALTER TABLE witness_epochs
ADD COLUMN IF NOT EXISTS chain_head_hash VARCHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
ADD COLUMN IF NOT EXISTS last_sequence_number BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN IF NOT EXISTS updated_at_seconds BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT;

ALTER TABLE witness_signing_outbox
ADD COLUMN IF NOT EXISTS fencing_generation BIGINT NOT NULL DEFAULT 1,
ADD COLUMN IF NOT EXISTS owner_worker_id VARCHAR(64) NOT NULL DEFAULT 'worker-bootstrap',
ADD COLUMN IF NOT EXISTS lease_expires_at_seconds BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS request_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS window_id VARCHAR(64) NULL,
ADD COLUMN IF NOT EXISTS requested_amount NUMERIC(78, 0) NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_outbox_unfinalized_lease 
ON witness_signing_outbox (status, lease_expires_at_seconds)
WHERE status IN ('PENDING', 'SIGNING');

ALTER TABLE witness_sequence_gaps
ADD COLUMN IF NOT EXISTS gap_hash VARCHAR(64) NOT NULL DEFAULT '';

ALTER TABLE witness_tickets
ADD COLUMN IF NOT EXISTS owner_identity VARCHAR(128) NOT NULL DEFAULT 'engine-pod-default',
ADD COLUMN IF NOT EXISTS request_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS policy_id VARCHAR(64) NULL,
ADD COLUMN IF NOT EXISTS policy_revision BIGINT NULL,
ADD COLUMN IF NOT EXISTS window_id VARCHAR(64) NULL,
ADD COLUMN IF NOT EXISTS requested_amount NUMERIC(78, 0) NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_audit_log_ticket_action 
ON witness_audit_log (ticket_id, action);

-- ============================================================================
-- 10. Milestone 13-D Phase D3: Consensus State & Quarantine Foundation
-- ============================================================================

ALTER TABLE witness_epochs
ADD COLUMN IF NOT EXISTS is_quarantined BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN IF NOT EXISTS quarantined_at_seconds BIGINT NULL,
ADD COLUMN IF NOT EXISTS quarantine_reason VARCHAR(255) NULL,
ADD COLUMN IF NOT EXISTS quarantine_details JSONB NULL;

UPDATE witness_epochs
SET is_quarantined = true,
    is_active = false,
    quarantined_at_seconds = COALESCE(quarantined_at_seconds, updated_at_seconds, created_at_seconds),
    quarantine_reason = COALESCE(quarantine_reason, 'LEGACY_D2_QUARANTINE')
WHERE state = 'QUARANTINED';

UPDATE witness_epochs
SET is_quarantined = false,
    is_active = true,
    quarantined_at_seconds = NULL,
    quarantine_reason = NULL,
    quarantine_details = NULL
WHERE state = 'ACTIVE';

UPDATE witness_epochs
SET is_quarantined = false,
    is_active = false,
    quarantined_at_seconds = NULL,
    quarantine_reason = NULL,
    quarantine_details = NULL
WHERE state IN ('TERMINATED', 'ARCHIVED', 'CLOSED');

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

-- Runtime Grants Reference for web3user_app:
-- GRANT SELECT, INSERT ON witness_consensus_log TO web3user_app;
-- GRANT SELECT, INSERT, UPDATE ON witness_raft_state TO web3user_app;


