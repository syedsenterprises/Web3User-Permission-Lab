# Web3User — Milestone 13-D / Stage 2-B.2 / Step 4
## Implementation Report: PostgresConsensusStore, Two-Phase State Publication & Replay

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-4-IMPLEMENTATION-REPORT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 4  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Date:** November 25, 2026  
**Status:** COMPLETE — AWAITING INDEPENDENT ACCEPTANCE AUDIT  

---

## 1. Architecture Decisions Followed

The Step 4 implementation adheres strictly to the accepted Stage 2-B.2 architecture baseline and ADR-M13D-010 through ADR-M13D-014:

- **INV-AUTH-01 (PostgreSQL Authority):** Candidate state computed by `ConsensusStateMachine.apply()` remains isolated in local transaction scope and is never published to `authoritativeState` until PostgreSQL `COMMIT` succeeds.
- **INV-RET-01 (Durable Retention):** `last_consecutive_persisted_index` advances strictly on contiguous, committed consensus log entries; retention floor `F_ret` and dual-map eviction are delegated directly to `ConsensusStateMachine.apply()` without duplication.
- **INV-REP-01 (Two-Tier Idempotent Replay):** Historical entries within `[F_ret, A_app]` are verified in memory; pruned entries `< F_ret` are verified in Tier 2 against `witness_consensus_log` (`proposal_id`, `payload_hash`, `canonicalization_version`).
- **ADR-M13D-011 (Single-Writer Serialization):** Every write transaction atomically bootstraps and locks `witness_raft_state` for `(cluster_id, epoch_id)` using `INSERT ... ON CONFLICT DO NOTHING` followed by `SELECT ... FOR UPDATE` before any log write.
- **ADR-M13D-014 (Dual Canonicalization Versioning):** Persists `canonicalization_version` (`1` for Canon-v1, `2` for TTCF-v1) per log row and routes payload verification through `computeCanonicalPayloadHash(payload, version)` with BigInt JSONB hydration.
- **Schema Reconciliation:** Queries and mutations strictly target the actual Migration 003/004 columns (`witness_raft_state`: `last_applied_index`, `last_applied_term`, `last_applied_hash`, `updated_at_seconds`, `last_applied_etcd_revision`, `last_applied_sub_index`, `last_consecutive_persisted_index`, `last_snapshot_index`, `last_snapshot_hash`; `witness_consensus_log`: `epoch_id`, `log_index`, `term`, `etcd_revision`, `payload_type`, `payload`, `payload_hash`, `proposal_id`, `committed_at_seconds`, `canonicalization_version`, `sub_index`; `witness_snapshots`).

---

## 2. Files Created and Modified

| File Path | Action | Purpose |
| :--- | :--- | :--- |
| `src/witness/consensus-store.ts` | **Created** | `PostgresConsensusStore` persistence adapter, two-phase publication, Tier-2 verification, 5-step replay/recovery, and backpressure delegation. |
| `test/witness/consensus-store.test.ts` | **Created** | 18 PostgreSQL 16 integration tests covering F-STEP3-01 Migration 004 gate, persistence, two-phase publication, crash recovery, Tier-2 replay, and backpressure. |
| `docs/M13-D-STAGE-2B2-STEP-4-IMPLEMENTATION-REPORT.md` | **Created** | This Step 4 implementation evidence report. |

Zero pre-existing source files, migrations, or accepted historical reports were modified.

---

## 3. Persistence Design

- **Parameterized SQL Exclusively:** All dynamic values (`cluster_id`, `epoch_id`, `log_index`, `term`, `etcd_revision`, `payload_type`, `payload`, `payload_hash`, `proposal_id`, `committed_at_seconds`, `canonicalization_version`, `sub_index`) are bound via `$1..$N` placeholders.
- **Per-Transaction Statement Timeout:** Configures `SET LOCAL statement_timeout` (default `10000` ms) inside `BEGIN ... COMMIT` to prevent indefinite lock waits.
- **Single-Writer Lock Hierarchy:** `resolveLockEpochId()` locks the active epoch's `witness_raft_state` row (`FOR UPDATE`) before evaluating `ConsensusStateMachine.apply()` and inserting into `witness_consensus_log`. This preserves the `witness_raft_state -> witness_consensus_log` lock order established in Step 3 (`F-STEP3-02`).
- **JSONB BigInt Hydration:** `serializePayloadToJsonb()` serializes `bigint` values cleanly to decimal strings for PostgreSQL `JSONB`; `hydratePayloadFromJsonb()` restores `bigint` domain fields (`sequenceFloor`, `debitedAmount`, `budgetWindows[*].cumulativeSpentAfter`) on read so both `ConsensusStateMachine.apply()` and TTCF-v1 (`version = 2`) hashing operate on exact types.
- **SQLSTATE Error Classification:** `23505` unique violations are classified into `ConsensusConflictError` (`PROPOSAL_ID` for `uq_consensus_log_proposal_id`, `LOG_INDEX` for `witness_consensus_log_pkey`). All errors trigger `ROLLBACK` before release.

---

## 4. Two-Phase State Publication Guarantees

1. **Phase 1 (Isolated Evaluation & Durable Write):**
   - `applyEntry()` validates input arguments and `payloadHash` before opening/mutating state.
   - Inside `BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED`, it locks `witness_raft_state` `FOR UPDATE` and verifies `lockedRaftState.lastConsecutivePersistedIndex <= authoritativeState.lastConsecutivePersistedAppIndex` (throwing `StaleAuthoritativeStateError` if in-memory state is behind PostgreSQL).
   - `ConsensusStateMachine.apply()` evaluates `candidateState` in a local variable without touching `this.authoritativeState`.
   - `witness_consensus_log` `INSERT` and `witness_raft_state` `UPDATE` execute in the same ACID transaction, followed by `COMMIT`.
2. **Phase 2 (Post-Commit Publication):**
   - Only after `await client.query("COMMIT")` succeeds is `this.authoritativeState` updated to the frozen `publishedState` (with `lastConsecutivePersistedAppIndex` synchronized to `candidateState.lastAppliedAppIndex`).
   - If `COMMIT` or any prior step fails, `ROLLBACK` executes, `candidateState` is discarded, and `this.authoritativeState` remains unchanged.
   - If the process crashes after `COMMIT` and before in-memory publication (verified via `onAfterCommitBeforePublish` fault injection), the stale store refuses further writes (`StaleAuthoritativeStateError`) and a restarted store calling `recover()` deterministically reconstructs the exact committed state from PostgreSQL.

---

## 5. Replay and Recovery Behavior

`PostgresConsensusStore.recover(epochId, options)` implements the 5-step deterministic recovery protocol:

1. **Raft State & Log Consistency Inspection:** Reads `witness_raft_state` and `MIN/MAX/COUNT` from `witness_consensus_log`. Empty epochs (`0` rows and `last_consecutive_persisted_index = 0`) cleanly initialize `createInitialState(clusterId)`. Orphaned log rows without `witness_raft_state`, or `max(log_index) > last_consecutive_persisted_index`, fail closed with `UnverifiableDurableHistoryError`.
2. **Snapshot Selection & Genesis Fallback:** Queries `witness_snapshots` (`status = 'COMMITTED'`, `snapshot_index <= L_c_persisted`, `ORDER BY snapshot_index DESC`). When a `ConsensusSnapshotLoader` is supplied, validates `format_version === 1`, cluster/epoch identity, `snapshotIndex`, and `chainHeadHash`; falls back to earlier snapshots or genesis (`createInitialState`, `startIndex = 1n`) if unavailable or corrupt.
3. **Contiguous Log Query:** Queries `witness_consensus_log` for `[startIndex, L_c_persisted]` ordered by `log_index ASC` and fails closed with `UnverifiableHistoricalEntryError` on any missing index.
4. **Cryptographic Payload & Reducer Replay:** Hydrates each entry, verifies `computeCanonicalPayloadHash(payload, canonicalization_version) === payload_hash` (`PayloadHashMismatchError` on mismatch), and applies sequentially through `ConsensusStateMachine.apply()`.
5. **Watermark & Chain-Head Parity + Atomic Publication:** Asserts `baseState.lastAppliedAppIndex === L_c_persisted` and `baseState.chainHeadHash === raftState.lastAppliedHash` (`ReplayVerificationError` on mismatch) before publishing `this.authoritativeState`.

---

## 6. Retention and Backpressure Integration

- `applyEntry()` and `recover()` pass `memoryRetentionWindow` and `lastConsecutivePersistedAppIndex` directly to `ConsensusStateMachine.apply()`, preserving the Step 2 retention floor `F_ret = max(1n, min(A_app - W_mem + 1n, L_c_persisted + 1n))` and atomic dual-map eviction (`appliedIndices` / `appliedProposals`).
- Pruned historical entries (`HISTORICAL_RECORD_PRUNED`) trigger Tier-2 verification in `verifyTier2HistoricalEntry()`, which queries `witness_consensus_log` and fails closed on missing rows (`UnverifiableHistoricalEntryError`) or mismatched `proposal_id` / `payload_hash` (`HistoricalIndexConflictError`).
- `evaluateBackpressure()` delegates directly to `BackpressurePolicy.evaluate()` using `authoritativeState` counters without duplicating threshold or hysteresis logic.

---

## 7. PostgreSQL Integration Evidence Satisfying F-STEP3-01

- **PostgreSQL Engine:** `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit` (local isolated Windows service on `127.0.0.1:5432`, disposable test databases `web3user_test_fstep301_*` and `web3user_test_cs_main_*`; zero staging or production connections).
- **F-STEP3-01 Verification Sequence (executed in `test/witness/consensus-store.test.ts`):**
  1. Applied Migration 003 baseline (`src/witness/schema.sql`) and seeded `witness_epochs` + contiguous `witness_consensus_log` rows (`1, 2`).
  2. Applied actual `src/witness/migrations/004_d3_consensus_persistence.sql` — verified new columns (`canonicalization_version`, `sub_index`, `last_applied_etcd_revision`, `last_applied_sub_index`, `last_consecutive_persisted_index`, `last_snapshot_index`, `last_snapshot_hash`), `uq_consensus_log_proposal_id` unique index, `witness_snapshots` and `witness_snapshot_leases` tables, and contiguous backfill (`last_consecutive_persisted_index = 2`, `last_applied_etcd_revision = 20`).
  3. Verified rollback safety guard aborts `004_d3_consensus_persistence.rollback.sql` when Stage 2-B.2 data exists (`Migration 004 rollback aborted`).
  4. Executed actual `004_d3_consensus_persistence.rollback.sql` with `SET stage2b2.allow_destructive_rollback = 'true'` — verified `witness_snapshots` and `witness_snapshot_leases` dropped and non-unique `idx_consensus_log_proposal_id` on `(proposal_id)` restored.
  5. Re-applied `004_d3_consensus_persistence.sql` cleanly to verify migration repeatability.

---

## 8. Test Commands, Counts, and Actual Results

| Check | Command | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| PostgreSQL 16 Connection & Version | `node -e "import('pg').then(...)"` | `0` | `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit` |
| Step 4 Focused Integration Suite | `npx vitest run test/witness/consensus-store.test.ts` | `0` | **18 passed (18)** (1 F-STEP3-01 gate + 17 `PostgresConsensusStore` integration tests) |
| Witness Regression Suites | `npx vitest run test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/migration-004.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts test/witness/migration-003.test.ts` | `0` | **152 passed (152)** across 7 test files |

---

## 9. Build and Static-Analysis Results

| Check | Command | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| TypeScript Build | `npm run build` (`tsc -p tsconfig.build.json`) | `0` | 0 errors |

---

## 10. Remaining Risks and Limitations

- **Snapshot Blob Loading:** Step 5 (`SnapshotManager`) is not yet implemented; `PostgresConsensusStore.recover()` supports `ConsensusSnapshotLoader` injection and falls back to genesis when no loader or valid snapshot is present. Full POSIX/S3/GCS snapshot rehydration will be integration-tested in Step 5.
- **Unbatched Single-Entry Write Path:** `applyEntry()` persists one `CommittedConsensusEntry` per transaction. High-throughput batching and etcd watch stream pause/resume orchestration belong to Step 6 (`CompactionCoordinator` / watch consumer integration).

---

## 11. SHA-256 Hashes

| File Path | SHA-256 Checksum |
| :--- | :--- |
| `src/witness/consensus-store.ts` | `B853282696E9B90AF70315ACE83A07B7E0F5667F35771845C460AF45B22C3A54` |
| `test/witness/consensus-store.test.ts` | `F8D410706A41D34B4F844C5803B6A423311A528AF5CFEE4F40C8F8A227D0A99A` |

---

## 12. Git Status and Governance Confirmation

- **Implemented & Integration-Verified:** `PostgresConsensusStore` persistence, two-phase publication, Tier-2 verification, 5-step replay/recovery, backpressure integration, and Migration 004 forward/rollback/re-apply against live PostgreSQL 16.15.
- **Unverified / Deferred to Later Steps:** Step 5 `SnapshotManager` backend storage (POSIX/S3/GCS) and Step 6 etcd watch/compaction orchestration.
- **Governance:** Zero git commits, pushes, merges, or deployments performed; zero staging/production database access; all pre-existing untracked docs, Stage 2-B.2 artifacts, and funding files preserved.
- **Status:** Step 4 implementation complete; **not** independently accepted until independent acceptance audit completes. Awaiting independent audit and separate founder authorization before Step 5.
