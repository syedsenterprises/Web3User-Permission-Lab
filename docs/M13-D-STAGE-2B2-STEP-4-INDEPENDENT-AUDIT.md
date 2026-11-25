# Web3User — Milestone 13-D / Stage 2-B.2 / Step 4
## Independent Acceptance Audit — PostgresConsensusStore

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-4-INDEPENDENT-AUDIT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 4  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Audit Date:** November 25, 2026  
**Auditor:** Independent PostgreSQL, Distributed-Systems & Application-Security Auditor  
**Verdict:** **ACCEPTED WITH CONDITIONS**

---

## 1. Executive Verdict

**Verdict: ACCEPTED WITH CONDITIONS**

`PostgresConsensusStore` (`src/witness/consensus-store.ts`) satisfies the core Stage 2-B.2 Step 4 invariants for single-epoch consensus persistence:

1. **Two-Phase State Publication (`INV-AUTH-01`):** Candidate state is evaluated in an isolated local variable and is never published to `authoritativeState` until PostgreSQL `COMMIT` succeeds. Crash-after-commit recovery and `StaleAuthoritativeStateError` fail-closed fencing are verified.
2. **PostgreSQL Transaction & Lock Safety:** All queries use parameterized SQL (`$1..$N`), acquire `witness_raft_state` (`FOR UPDATE`) before `witness_consensus_log` (`INSERT`), roll back on all error paths, and classify `23505` unique violations deterministically.
3. **F-STEP3-01 Integration Gate Satisfied:** Live tests executed against an isolated local **PostgreSQL 16.15** instance (`web3user_test_fstep301_*`, `web3user_test_cs_main_*`) applying Migration 003 baseline, Migration 004 forward, live schema/index/backfill inspection, rollback safety guard, Migration 004 rollback, and Migration 004 re-application.
4. **TTCF-v1 & Canon-v1 Payload Integrity:** `BigInt` JSONB serialization and domain-typed hydration preserve identical SHA-256 digests across both canonicalization versions.

**Condition for Unconditional Closure:**
- **F-STEP4-01 (Medium):** `EPOCH_ADVANCE` transitions `authoritativeState.epochId` to `toEpochId` while keeping `appLogIndex` monotonic, but `witness_raft_state` is keyed by `(cluster_id, epoch_id)` and `PostgresConsensusStore` does not carry `last_consecutive_persisted_index` or cross-epoch log continuity across an `EPOCH_ADVANCE` boundary. Subsequent entries in the new epoch will fail with `PERSISTENCE_WATERMARK_REGRESSION`. Single-epoch operation is unaffected; multi-epoch `EPOCH_ADVANCE` persistence requires a targeted fix before production multi-epoch rollover.

---

## 2. Files and Evidence Inspected

| Artifact | SHA-256 Checksum | Role |
| :--- | :--- | :--- |
| `src/witness/consensus-store.ts` | `B853282696E9B90AF70315ACE83A07B7E0F5667F35771845C460AF45B22C3A54` | Step 4 implementation under audit |
| `test/witness/consensus-store.test.ts` | `F8D410706A41D34B4F844C5803B6A423311A528AF5CFEE4F40C8F8A227D0A99A` | Step 4 PostgreSQL 16 integration suite (18 tests) |
| `docs/M13-D-STAGE-2B2-STEP-4-IMPLEMENTATION-REPORT.md` | `6C0493A306F06EB813AE0E3F27A95A73AAE66185E86034C1D4D26E219C17E1CD` | Step 4 implementation report |
| `src/witness/state-machine.ts` | — | Pure reducer (`ConsensusStateMachine`, `BackpressurePolicy`) |
| `src/witness/state-machine-types.ts` | — | Domain contracts and error classes |
| `src/witness/canonical-serializer.ts` | — | Canon-v1 and TTCF-v1 (`Canon-v2`) hash engine |
| `src/witness/migrations/003_d3_consensus_state.sql` | — | Migration 003 baseline |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | `98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341` | Migration 004 forward SQL |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | `85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74` | Migration 004 rollback SQL |

**Independent Execution Evidence Observed:**
- PostgreSQL server: `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit`.
- `npx vitest run test/witness/consensus-store.test.ts`: **18/18 passed** (exit code `0`).
- Witness regression suites (7 files): **152/152 passed** (exit code `0`).
- `npm run build` (`tsc -p tsconfig.build.json`): **0 errors** (exit code `0`).

---

## 3. Findings

### F-STEP4-01 (Medium): Cross-Epoch `EPOCH_ADVANCE` Watermark & Replay Discontinuity
- **Location:** `src/witness/consensus-store.ts` lines 537–559, 613–680, 861–869.
- **Detail:** In `ConsensusStateMachine.applyEpochAdvance` (`src/witness/state-machine.ts` lines 751–764), `EPOCH_ADVANCE` changes `state.epochId` to `p.toEpochId` while `lastAppliedAppIndex` continues monotonically (`N -> N+1`). In `PostgresConsensusStore.applyEntry()`, `resolveLockEpochId()` locks `authoritativeState.epochId` (`fromEpochId`) and updates `witness_raft_state` for `fromEpochId`. On the next `applyEntry()` for `toEpochId`, `resolveLockEpochId()` returns `toEpochId`, `bootstrapAndLockRaftState()` inserts a new `witness_raft_state` row with `last_consecutive_persisted_index = 0`, and `ConsensusStateMachine.apply()` throws `PERSISTENCE_WATERMARK_REGRESSION` (`received 0, current N`). Similarly, `recover(toEpochId)` assumes `startIndex = 1n` within `toEpochId`.
- **Impact:** Does not affect single-epoch operation (`EPOCH_INITIALIZE`, `POLICY_UPDATE`, `DELEGATION_REVOKE`, `TICKET_COMMIT`, `EPOCH_QUARANTINE`). Blocks multi-epoch `EPOCH_ADVANCE` continuation until addressed.

### F-STEP4-02 (Low): No In-Process Async Mutex Across `[COMMIT -> In-Memory Publish]`
- **Location:** `src/witness/consensus-store.ts` lines 459–576.
- **Detail:** PostgreSQL `FOR UPDATE` serializes database transactions across connections, but there is a microtask window between `await client.query("COMMIT")` (line 562) and `this.authoritativeState = publishedState` (line 575). If two concurrent `applyEntry()` calls share the same `PostgresConsensusStore` instance, a second caller unblocking from `FOR UPDATE` during that microtask sees `lockedRaftState.lastConsecutivePersistedIndex > this.authoritativeState.lastConsecutivePersistedAppIndex` and throws `StaleAuthoritativeStateError`.
- **Impact:** Fail-closed (zero stale or out-of-order publication is possible), but concurrent callers on a single store instance may experience a transient `StaleAuthoritativeStateError` requiring `recover()`.

### F-STEP4-03 (Low): Test Coverage Gaps in `test/witness/consensus-store.test.ts`
- **Location:** `test/witness/consensus-store.test.ts`.
- **Detail:**
  1. `EPOCH_ADVANCE` is not tested end-to-end against `PostgresConsensusStore`.
  2. `recover()` with a *valid* `ConsensusSnapshotLoader` hit (rehydrating `baseState` at `snapshotIndex > 0` and replaying only `[snapshotIndex + 1, L_c_persisted]`) is not tested; only the corrupt/null fallback path is tested.
  3. `statementTimeoutMs` lock-timeout cancellation and `close()` (`STORE_CLOSED`) are not directly tested.

---

## 4. Two-Phase Publication Analysis

- **Candidate Isolation:** `ConsensusStateMachine.apply()` (line 487) produces a frozen `candidateState` held in a local `const` (line 525). `this.authoritativeState` is never mutated prior to `COMMIT`.
- **No Pre-Commit Publication:** `this.authoritativeState` is assigned only at line 575, strictly after `await client.query("COMMIT")` (line 562) returns.
- **Commit Failure Handling:** Verified both by code inspection (lines 588–599) and live test (`rolls back transaction and leaves authoritative state unchanged on database failure`, lines 513–579): `ROLLBACK` executes, `candidateState` is discarded, and PostgreSQL + memory remain at prior index.
- **Crash After Commit / Before Publication:** Verified via `onAfterCommitBeforePublish` hook (lines 697–738): `authoritativeState` remains at `1n`, subsequent writes on the stale instance fail closed with `StaleAuthoritativeStateError` (line 478), and a new store instance calling `recover()` reconstructs index `2n` deterministically.
- **Uncertain COMMIT Result / Retry:** If a network drop occurs after the server commits `COMMIT` but before the client receives `CommandComplete`, `authoritativeState` is not updated. A subsequent write fails closed with `StaleAuthoritativeStateError`, forcing `recover()` before retrying; re-applying the committed entry returns `ALREADY_APPLIED` (`committedToDatabase: false`) without duplication.

---

## 5. PostgreSQL Transaction and Concurrency Analysis

- **Parameterized SQL:** All dynamic values across `getRaftState`, `applyEntry`, `recover`, `bootstrapAndLockRaftState`, `verifyTier2HistoricalEntry`, and `insertConsensusLogRow` use `$1..$N` bind parameters. `SET LOCAL statement_timeout` (line 467) interpolates `this.statementTimeoutMs` only after constructor validation (`Number.isInteger(timeout) && timeout >= 0`, lines 336–341).
- **Lock Order:** `bootstrapAndLockRaftState` (lines 876–894) acquires `ROW SHARE` (`FOR UPDATE`) on `witness_raft_state` before `insertConsensusLogRow` (`ROW EXCLUSIVE` on `witness_consensus_log`), matching Migration 004's `witness_raft_state -> witness_consensus_log` hierarchy.
- **Isolation & Uniqueness:** Transactions run under `READ COMMITTED` with `FOR UPDATE` single-writer row locking on `witness_raft_state`. Duplicate `(epoch_id, proposal_id)` (`uq_consensus_log_proposal_id`) and `(epoch_id, log_index)` (`witness_consensus_log_pkey`) SQLSTATE `23505` errors are mapped to `ConsensusConflictError` (`PROPOSAL_ID` / `LOG_INDEX`).
- **Connection Lifecycle:** Every `pool.connect()` in `applyEntry()` and `recover()` is paired with `client.release()` in `finally`. `close()` ends the pool only when `ownPool === true`.

---

## 6. F-STEP3-01 Integration Gate Assessment

Independent inspection of `test/witness/consensus-store.test.ts` lines 166–303 confirms **F-STEP3-01 is satisfied**:
- Runs against local **PostgreSQL 16.15** on `127.0.0.1:5432` using an isolated disposable database (`web3user_test_fstep301_<ts>_<rand>`), torn down in `finally`/`afterAll`. Zero staging or production connections.
- Establishes Migration 003 baseline (`src/witness/schema.sql`) and seeds contiguous log entries (`1, 2`).
- Executes actual `004_d3_consensus_persistence.sql` and inspects `information_schema.columns`, `pg_indexes` (`uq_consensus_log_proposal_id`), `information_schema.tables` (`witness_snapshots`, `witness_snapshot_leases`), and backfilled `witness_raft_state` values (`last_consecutive_persisted_index = 2`, `last_applied_etcd_revision = 20`).
- Verifies the rollback safety guard aborts when Stage 2-B.2 data exists (`/Migration 004 rollback aborted/`).
- Executes actual `004_d3_consensus_persistence.rollback.sql` with `stage2b2.allow_destructive_rollback = 'true'` and verifies restoration of non-unique `idx_consensus_log_proposal_id` on `(proposal_id)` and removal of snapshot tables.
- Re-applies `004_d3_consensus_persistence.sql` cleanly.

---

## 7. Replay and Recovery Assessment

- **5-Step Protocol:** `recover()` (lines 613–855) handles empty epochs (`INITIAL` state), orphaned logs without `witness_raft_state` (`UnverifiableDurableHistoryError`), `maxLogIndex > L_c_persisted` (`UnverifiableDurableHistoryError`), snapshot selection (`status = 'COMMITTED'`, `snapshot_index <= L_c_persisted`, `ORDER BY snapshot_index DESC`) with genesis fallback, contiguous log verification (`UnverifiableHistoricalEntryError` on gaps), cryptographic `payload_hash` verification (`PayloadHashMismatchError`), and `chainHeadHash` parity (`ReplayVerificationError`).
- **Canonicalization & BigInt Hydration:** `hydratePayloadFromJsonb()` (lines 227–268) restores `sequenceFloor` (`EPOCH_INITIALIZE`) and `debitedAmount` / `budgetWindows[*].cumulativeSpentAfter` (`TICKET_COMMIT`) to `bigint` before `computeCanonicalPayloadHash(hydratedPayload, canonVersion)` and `ConsensusStateMachine.apply()`. Both Canon-v1 and TTCF-v1 (`version = 2`) replay deterministically with exact digest parity.
- **Tier-2 Verification:** Pruned entries (`HISTORICAL_RECORD_PRUNED`) are verified against `witness_consensus_log` in `verifyTier2HistoricalEntry()` (lines 906–959), failing closed on missing rows or `proposal_id` / `payload_hash` mismatches.

---

## 8. Security and Operational Assessment

- **SQL Injection:** None; strictly parameterized queries and validated integer timeout.
- **Retry Safety:** No unsafe automatic retries around non-idempotent writes; callers must `recover()` after `StaleAuthoritativeStateError` or uncertain `COMMIT` failures.
- **Error Leakage:** Errors classify constraint names and indices without logging raw sensitive payloads.
- **Resource Cleanup:** `client.release()` guaranteed in `finally`; `ownPool` lifecycle cleanly managed.

---

## 9. Test Adequacy

All 18 tests in `test/witness/consensus-store.test.ts` execute against live PostgreSQL 16.15 (zero mocked DB behavior except the intentional `COMMIT` fault-injection wrapper in test 6, which still uses a real `PoolClient` for all prior statements and `ROLLBACK`). Assertions verify actual database rows, constraints, indexes, and reconstructed in-memory state. See **F-STEP4-03** for the three minor uncovered scenarios.

---

## 10. Required Remediation

1. **Before multi-epoch `EPOCH_ADVANCE` production use (`F-STEP4-01`):** Define and implement cross-epoch `EPOCH_ADVANCE` persistence/recovery semantics (either carrying `last_consecutive_persisted_index` and prior-epoch replay chaining across `witness_raft_state` rows, or explicitly fencing `EPOCH_ADVANCE` until Step 5/6 epoch rollover design is finalized).
2. **Recommended hardening (`F-STEP4-02`, `F-STEP4-03`):** Add an optional in-process async mutex around `applyEntry()` / `recover()` on a single `PostgresConsensusStore` instance, plus tests for valid `ConsensusSnapshotLoader` rehydration, `statementTimeoutMs`, and `STORE_CLOSED`.

---

## 11. Final Acceptance Decision

- **Decision:** **ACCEPTED WITH CONDITIONS**
- **Authorized Scope:** Step 4 (`PostgresConsensusStore`) is accepted for single-epoch consensus persistence and **F-STEP3-01** is closed. **F-STEP4-01** must be resolved prior to any multi-epoch `EPOCH_ADVANCE` rollover.
- **Governance:** Audit-only; zero source, test, or migration files modified; zero git commits/pushes; Step 5 and Step 6 not started.
