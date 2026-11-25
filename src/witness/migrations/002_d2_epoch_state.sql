-- Web3User Permission Lab - Milestone 13-D Phase D2: Epoch State & Outbox Fencing Schema Migration
-- Non-destructive schema augmentation on existing D1 tables.

-- 1. Augment witness_epochs in-place (F1)
ALTER TABLE witness_epochs
ADD COLUMN IF NOT EXISTS chain_head_hash VARCHAR(64) NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
ADD COLUMN IF NOT EXISTS last_sequence_number BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
ADD COLUMN IF NOT EXISTS updated_at_seconds BIGINT NOT NULL DEFAULT EXTRACT(EPOCH FROM clock_timestamp())::BIGINT;

-- View alias for architectural specification parity
CREATE OR REPLACE VIEW witness_epoch_state AS 
SELECT epoch_id, epoch_height, created_at_seconds, chain_head_hash, last_sequence_number, state, updated_at_seconds
FROM witness_epochs;

-- 2. Augment witness_signing_outbox with fencing, ownership, lease, and payload attribution
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

-- 3. Augment witness_sequence_gaps with recursive gap hash
ALTER TABLE witness_sequence_gaps
ADD COLUMN IF NOT EXISTS gap_hash VARCHAR(64) NOT NULL DEFAULT '';

-- 4. Augment witness_tickets with caller ownership, request fingerprint, and direct budget window columns (PERF-D2-01)
ALTER TABLE witness_tickets
ADD COLUMN IF NOT EXISTS owner_identity VARCHAR(128) NOT NULL DEFAULT 'engine-pod-default',
ADD COLUMN IF NOT EXISTS request_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
ADD COLUMN IF NOT EXISTS policy_id VARCHAR(64) NULL,
ADD COLUMN IF NOT EXISTS policy_revision BIGINT NULL,
ADD COLUMN IF NOT EXISTS window_id VARCHAR(64) NULL,
ADD COLUMN IF NOT EXISTS requested_amount NUMERIC(78, 0) NOT NULL DEFAULT 0;

-- 5. Covering index on witness_audit_log to eliminate sequential table scans (PERF-D2-01)
CREATE INDEX IF NOT EXISTS idx_audit_log_ticket_action 
ON witness_audit_log (ticket_id, action);
