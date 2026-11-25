# Web3User — Milestone 13-D / Stage 2-B.2 / Step 4
## Remediation Report: F-STEP4-01, F-STEP4-02, and F-STEP4-03

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-REPORT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 4 Remediation  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Date:** November 25, 2026  
**Status:** COMPLETE — AWAITING INDEPENDENT ACCEPTANCE AUDIT  

---

## 1. Original Audit Finding IDs

- **F-STEP4-01 (Medium):** Cross-epoch `EPOCH_ADVANCE` persistence watermark & replay discontinuity.
- **F-STEP4-02 (Low):** Lack of in-process async mutex across `[COMMIT -> authoritativeState publish]` on a single `PostgresConsensusStore` instance.
- **F-STEP4-03 (Low):** Missing regression test coverage for `EPOCH_ADVANCE`, valid `ConsensusSnapshotLoader` hit, `statementTimeoutMs`, and `STORE_CLOSED`.

---

## 2. Root Cause Analysis

1. **F-STEP4-01:** `ConsensusStateMachine.applyEpochAdvance()` transitions `state.epochId` from `fromEpochId` to `p.toEpochId` while advancing `lastAppliedAppIndex` monotonically (`N -> N+1`). Previously, `PostgresConsensusStore.applyEntry()` updated `witness_raft_state` only for `fromEpochId`, leaving `(cluster_id, toEpochId)` unseeded (`last_consecutive_persisted_index = 0`), causing `PERSISTENCE_WATERMARK_REGRESSION` on the first entry in `toEpochId`. Furthermore, `recover(toEpochId)` queried only `witness_consensus_log WHERE epoch_id = toEpochId`, which could not replay prior epochs' `EPOCH_ADVANCE` lineage from genesis.
2. **F-STEP4-02:** PostgreSQL `SELECT ... FOR UPDATE` serialized cross-connection writes, but concurrent callers on the same `PostgresConsensusStore` instance could observe a microtask gap between `COMMIT` and `this.authoritativeState = publishedState`, surfacing an avoidable `StaleAuthoritativeStateError`.
3. **F-STEP4-03:** `test/witness/consensus-store.test.ts` lacked explicit integration tests for `EPOCH_ADVANCE`, a valid snapshot loader hit, `statementTimeoutMs` lock-wait cancellation, and `STORE_CLOSED`.

---

## 3. Architecture Decisions Followed

- **INV-AUTH-01 (PostgreSQL Authority):** Candidate state remains isolated until `COMMIT` succeeds; `withMutex()` serializes `[DB tx -> publish]` without altering pre-commit isolation.
- **INV-RET-01 (Durable Retention):** `last_consecutive_persisted_index` is carried atomically across `EPOCH_ADVANCE` inside the same ACID transaction and never regresses within an epoch.
- **ADR-M13D-011 (Single-Writer Serialization):** PostgreSQL `SELECT ... FOR UPDATE` remains the authoritative cross-process lock; the in-process FIFO mutex complements it for single-instance concurrency.
- **ADR-M13D-014 (TTCF-v1 / Canon-v1):** All `EPOCH_ADVANCE` and subsequent entries preserve canonical version verification during lineage replay.

---

## 4. Exact Changes Made

| File Path | Summary of Changes |
| :--- | :--- |
| `src/witness/consensus-store.ts` | 1. Added FIFO in-process async mutex `withMutex()` (`mutexTail`) wrapping `applyEntry()` and `recover()`, with safe `close()` draining.<br>2. On `EPOCH_ADVANCE`, atomically upserted `witness_raft_state` for `(clusterId, candidateState.epochId)` within the same ACID transaction.<br>3. Added `buildReplaySegments()` in `recover()` to trace `EPOCH_ADVANCE` lineage (`payload->>'toEpochId'`) with cycle detection and replay contiguous `[startIndex, L_c_persisted]` segments. |
| `test/witness/consensus-store.test.ts` | Added 7 focused PostgreSQL 16 integration tests (expanding suite from 18 to 25 tests) covering F-STEP4-01, F-STEP4-02, and F-STEP4-03. |
| `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-REPORT.md` | Created this remediation report. |

Zero changes were made to `state-machine.ts`, `state-machine-types.ts`, `canonical-serializer.ts`, Migration 004 SQL, or any previously accepted reports.

---

## 5. Epoch and Watermark Semantics Before and After

| Aspect | Before Remediation | After Remediation |
| :--- | :--- | :--- |
| `EPOCH_ADVANCE` DB write | Updated `witness_raft_state` only for `fromEpochId`. | Atomically updates `fromEpochId` AND upserts `(clusterId, toEpochId)` with `last_consecutive_persisted_index = candidateState.lastAppliedAppIndex` and `last_applied_hash = candidateState.chainHeadHash`. |
| First entry in `toEpochId` | Failed with `PERSISTENCE_WATERMARK_REGRESSION` (`0 < N`). | Reads `lockedRaftState.lastConsecutivePersistedIndex = N` matching `authoritativeState.lastConsecutivePersistedAppIndex = N`; succeeds cleanly. |
| Sealed `fromEpochId` replay | `EpochMismatchError` in-memory. | Preserved: `EpochMismatchError` thrown before any DB mutation. |
| `recover(toEpochId)` | Queried only `witness_consensus_log WHERE epoch_id = toEpochId`. | `buildReplaySegments()` resolves `EPOCH_ADVANCE` lineage with cycle detection and replays contiguous `[startIndex, L_c_persisted]` across epoch boundaries. |

---

## 6. Mutex Design and Concurrency Guarantees

- **FIFO Queue (`mutexTail`):** Each `applyEntry()` / `recover()` chains onto `this.mutexTail` synchronously before any `await`, and releases in `finally` regardless of success or error.
- **Failure Isolation:** A rejected or rolled-back operation always invokes `release()`, unblocking subsequent queued operations without deadlock or unhandled rejections.
- **`close()` Behavior:** Sets `this.closed = true` immediately, awaits `this.mutexTail` so in-flight DB operations release their `PoolClient` before `pool.end()`, and causes queued operations entering the mutex post-close to fail fast with `ConsensusStoreError("STORE_CLOSED")`.
- **Scope & Limitations:** The mutex serializes operations within **one `PostgresConsensusStore` instance** in-process. Cross-process concurrency continues to rely on PostgreSQL `SELECT ... FOR UPDATE` on `witness_raft_state`.

---

## 7. Test Cases and Actual Results

| Test Suite / Run | Command | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| Step 4 Integration Suite (Run 1) | `npx vitest run test/witness/consensus-store.test.ts` | `0` | **25 passed (25)** |
| Step 4 Integration Suite (Run 2) | `npx vitest run test/witness/consensus-store.test.ts` | `0` | **25 passed (25)** |
| Step 4 Integration Suite (Run 3) | `npx vitest run test/witness/consensus-store.test.ts` | `0` | **25 passed (25)** |
| Witness Regression Suites (7 files) | `npx vitest run test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/migration-004.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts test/witness/migration-003.test.ts` | `0` | **152 passed (152)** |
| TypeScript Build | `npm run build` (`tsc -p tsconfig.build.json`) | `0` | **0 errors** |

All 25 tests in `test/witness/consensus-store.test.ts` are **implemented and integration-tested** against live PostgreSQL 16.15. Independent acceptance audit of this remediation has not yet been performed.

---

## 8. PostgreSQL Integration Evidence

- **Engine:** `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit` (local isolated disposable databases `web3user_test_fstep301_*` and `web3user_test_cs_main_*`).
- Verified live: `EPOCH_ADVANCE` (`ep-1 -> ep-2 -> ep-3`), crash-after-commit recovery of `EPOCH_ADVANCE`, simultaneous sequential appends + concurrent `EPOCH_ADVANCE`, failed queued op mutex release, `close()` draining + `STORE_CLOSED`, valid `ConsensusSnapshotLoader` suffix replay, and real PostgreSQL `statementTimeoutMs` (`150ms`) cancellation under `FOR UPDATE` lock contention.

---

## 9. Remaining Risks and Limitations

- **Single-Instance Mutex Scope:** `withMutex()` protects one `PostgresConsensusStore` instance; multi-process writers rely on PostgreSQL `FOR UPDATE` and `recover()` on `StaleAuthoritativeStateError`.
- **Snapshot Backend Storage:** Full POSIX/S3/GCS snapshot serialization remains scoped to Step 5 (`SnapshotManager`).

---

## 10. SHA-256 Hashes

| File Path | SHA-256 Checksum |
| :--- | :--- |
| `src/witness/consensus-store.ts` | `6262EB7C090C06ED000DF2E93AB2910828950A6AC6EFDCDFED32D116EE08F88F` |
| `test/witness/consensus-store.test.ts` | `3D879DD1B848E219F82622C9783F91AD2F3A702522903C0A6BA00FC6C61C2D6B` |

---

## 11. Final Git Status and Governance Confirmation

- **Modified/Created Files:** `src/witness/consensus-store.ts`, `test/witness/consensus-store.test.ts`, `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-REPORT.md`.
- **Governance:** Zero git commits, pushes, merges, or deployments; zero staging/production database access; all pre-existing untracked files and accepted historical reports preserved untouched.
- **Stop Condition:** Stopping here for fresh independent acceptance audit prior to any Step 5 authorization.
