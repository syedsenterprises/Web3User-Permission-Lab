# Web3User — Milestone 13-D / Stage 2-B.2 / Step 4
## Independent Remediation Acceptance Audit — F-STEP4-01, F-STEP4-02, F-STEP4-03

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-INDEPENDENT-AUDIT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 4 Remediation Audit  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Audit Date:** November 25, 2026  
**Auditor:** Independent Distributed-Systems & PostgreSQL Auditor  
**Verdict:** **ACCEPTED**

---

## 1. Executive Verdict

**Verdict: ACCEPTED**

The Step 4 remediation (`src/witness/consensus-store.ts`, `test/witness/consensus-store.test.ts`) resolves all three findings from the Step 4 Independent Acceptance Audit (`F-STEP4-01`, `F-STEP4-02`, `F-STEP4-03`):

1. **F-STEP4-01 (Multi-Epoch `EPOCH_ADVANCE` Continuity):** Resolved. `applyEntryInternal()` atomically seeds/updates `witness_raft_state` for the destination `epochId` within the same ACID transaction, and `buildReplaySegments()` deterministically reconstructs cross-epoch `EPOCH_ADVANCE` lineage with cycle detection, contiguous verification, and full cryptographic hash-chain validation.
2. **F-STEP4-02 (FIFO In-Process Async Mutex):** Resolved. `withMutex()` serializes `applyEntry()` and `recover()` in strict FIFO order on a single `PostgresConsensusStore` instance, releases on all failure paths, and drains cleanly in `close()` without deadlocks or unhandled rejections. Cross-process concurrency remains enforced by PostgreSQL `SELECT ... FOR UPDATE`.
3. **F-STEP4-03 (Regression Coverage):** Resolved. Expanded `test/witness/consensus-store.test.ts` from 18 to 25 live PostgreSQL 16.15 integration tests covering multi-epoch `EPOCH_ADVANCE`, crash recovery, mutex serialization/failure release/`close()`, valid `ConsensusSnapshotLoader` suffix replay, `statementTimeoutMs` lock-wait cancellation, and `STORE_CLOSED`.

---

## 2. Finding-by-Finding Remediation Assessment

| Finding | Severity | Status | Evidence & Verification |
| :--- | :---: | :---: | :--- |
| **F-STEP4-01** | Medium | **RESOLVED** | `src/witness/consensus-store.ts` lines 599–629, 820–906, 945–995; verified by 2 live multi-epoch & crash-recovery tests (`test/witness/consensus-store.test.ts` lines 1074–1227). |
| **F-STEP4-02** | Low | **RESOLVED** | `src/witness/consensus-store.ts` lines 316, 369–399, 484–487, 692–695; verified by 3 concurrency/shutdown tests (`test/witness/consensus-store.test.ts` lines 1232–1378). |
| **F-STEP4-03** | Low | **RESOLVED** | `test/witness/consensus-store.test.ts` lines 1074–1494; verified valid snapshot hit, `statementTimeoutMs` (150ms) cancellation against PostgreSQL `FOR UPDATE`, and `STORE_CLOSED`. |

---

## 3. Exact Source Line References

- **FIFO Mutex & Shutdown (`src/witness/consensus-store.ts`):**
  - `mutexTail` declaration: line 316.
  - `close()`: lines 369–375 (sets `this.closed = true`, awaits `this.mutexTail`, ends `ownPool`).
  - `withMutex()`: lines 387–399 (synchronous tail chaining, `try ... finally { release(); }`).
  - `applyEntry()` mutex entry + post-acquire `assertOpen()`: lines 484–487.
  - `recover()` mutex entry + post-acquire `assertOpen()`: lines 692–695.
- **Multi-Epoch `EPOCH_ADVANCE` Persistence & Lineage Replay (`src/witness/consensus-store.ts`):**
  - Atomic `witness_raft_state` upsert for `candidateState.epochId`: lines 602–629.
  - `buildReplaySegments()` invocation in `recoverInternal()`: lines 821–822.
  - Multi-segment contiguous query & cryptographic verification loop: lines 825–906.
  - `buildReplaySegments()` implementation with `visitedEpochs` cycle detection: lines 945–995.

---

## 4. Multi-Epoch Correctness Analysis

- **Composite Identity `(cluster_id, epoch_id, log_index)`:** `witness_raft_state` rows are keyed by `(cluster_id, epoch_id)` and `witness_consensus_log` rows by `(epoch_id, log_index)`. On `EPOCH_ADVANCE` (`ep-1 -> ep-2` at index `N`), `(cluster_id, ep-1)` and `(cluster_id, ep-2)` are updated/inserted atomically in the same PostgreSQL transaction with `last_consecutive_persisted_index = N` and `last_applied_hash = candidateState.chainHeadHash`.
- **First Entry in New Epoch:** `resolveLockEpochId()` (lines 997–1005) locks `(cluster_id, ep-2)`, reads `last_consecutive_persisted_index = N` matching `authoritativeState.lastConsecutivePersistedAppIndex = N`, and passes `ConsensusStateMachine.apply()` without `PERSISTENCE_WATERMARK_REGRESSION`.
- **Lineage Reconstruction (`buildReplaySegments()`):**
  - Walks backwards from `targetEpochId` via `payload_type = 'EPOCH_ADVANCE' AND payload->>'toEpochId' = $1 AND log_index <= $2`.
  - **Cycles:** `visitedEpochs` set (lines 952–963) throws `UnverifiableDurableHistoryError` on any cycle.
  - **Missing Parents / Discontinuities:** If an `EPOCH_ADVANCE` parent is missing, `buildReplaySegments()` falls back to `startIndex = 1n` on `targetEpochId`, where the segment count/index check (lines 836–854) fails closed with `UnverifiableHistoricalEntryError`.
  - **Hash & State Parity:** Every segment entry is verified for `payload_hash` (Canon-v1 / TTCF-v1), `proposal_id`, `ConsensusStateMachine.apply()` (`fromEpochId === state.epochId` on `EPOCH_ADVANCE`, `entry.epochId === state.epochId` otherwise), and final `chainHeadHash === raftState.lastAppliedHash`.
  - **Advisory Note (Informational):** `buildReplaySegments()` selects predecessor `EPOCH_ADVANCE` rows by `toEpochId` without an extra `AND payload->>'fromEpochId' = epoch_id` SQL filter; `ConsensusStateMachine.apply()` still enforces `advPayload.fromEpochId === state.epochId` during replay, so tampered transitions fail closed.

---

## 5. Mutex and Shutdown Analysis

- **Strict FIFO & No Poisoning:** `withMutex()` chains synchronously onto `this.mutexTail` before `await prev` and releases in `finally`. `mutexTail` only ever resolves (`resolve = release`), so thrown errors/rollbacks propagate cleanly to the caller without poisoning subsequent queued operations.
- **No Stale Publication Race:** Because `applyEntry()` and `recover()` both execute under `withMutex()`, the entire `[PostgreSQL tx -> COMMIT -> this.authoritativeState = publishedState]` sequence is atomic with respect to in-process callers.
- **Safe `close()`:** Setting `this.closed = true` before `await this.mutexTail` ensures active work finishes and releases its `PoolClient` before `pool.end()`, while queued operations entering `withMutex()` fail fast at `this.assertOpen()` with `STORE_CLOSED`.
- **Scope Boundary:** Correctly documented (lines 311–315) as protecting a single `PostgresConsensusStore` instance; multi-process writers rely on PostgreSQL `SELECT ... FOR UPDATE`.

---

## 6. PostgreSQL Integration Evidence & Task History Investigation

- **Database Engine & Isolation:** Verified in `test/witness/consensus-store.test.ts` against local **PostgreSQL 16.15** (`127.0.0.1:5432`) using disposable databases (`web3user_test_fstep301_*`, `web3user_test_cs_main_*`) dropped in `afterAll`/`finally`. Zero staging or production access.
- **Earlier Task Failure Investigation (`task-32285`):**
  - During remediation, `task-32285` failed 1/25 tests (`close() drains active work...`) because the initial test called `store.close()` synchronously on the same tick as `store.applyEntry(e1)`, setting `this.closed = true` before `p1` cleared the `await prev` microtask in `withMutex()`.
  - The test was corrected (`await new Promise((r) => setTimeout(r, 5))` at line 1354) so `p1` genuinely enters the mutex before `close()` is invoked.
  - Subsequent verification (`task-32293`) ran `npx vitest run test/witness/consensus-store.test.ts` **3 consecutive times**, passing **25/25** on every run (exit code `0`), alongside **152/152** across 7 witness regression suites and **0 errors** on `npm run build`.

---

## 7. Test Adequacy

All 25 tests in `test/witness/consensus-store.test.ts` run against live PostgreSQL 16.15 and exercise real SQL transactions, constraints, triggers, Migration 004 forward/rollback/re-apply, multi-epoch `EPOCH_ADVANCE`, mutex serialization/failure release/`close()`, valid `ConsensusSnapshotLoader` suffix replay, `statementTimeoutMs` lock-wait cancellation, and `STORE_CLOSED`. (Minor stylistic note: line 1403 uses an inline ternary `e2 === e2 ? (await store.applyEntry(e1), e2) : e2` which executes `e1` then `e2` cleanly.)

---

## 8. Remaining Risks

- **Single-Instance Mutex:** Multi-process deployments must handle `StaleAuthoritativeStateError` by invoking `recover()`, as intended by `INV-AUTH-01`.
- **Step 5 / Step 6 Scope:** Full snapshot serialization (`SnapshotManager`) and etcd compaction/watch orchestration remain deferred to Steps 5 and 6.

---

## 9. Final Verdict

- **Verdict:** **ACCEPTED**
- **SHA-256 Checksums Verified:**
  - `src/witness/consensus-store.ts`: `6262EB7C090C06ED000DF2E93AB2910828950A6AC6EFDCDFED32D116EE08F88F`
  - `test/witness/consensus-store.test.ts`: `3D879DD1B848E219F82622C9783F91AD2F3A702522903C0A6BA00FC6C61C2D6B`
  - `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-REPORT.md`: `AA196806B613D0484DEC9F0D8A09E35291893C19EC03DEA88116F0E4F0F85E84`
- **Governance:** Audit-only; zero source, test, or migration files modified; zero git commits/pushes; Step 5 and Step 6 not started.
