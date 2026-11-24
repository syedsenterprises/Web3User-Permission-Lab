# Milestone 13-D Phase D3: Stage 2-B.2 Implementation Plan
## Persistent State-Machine Integration

**Document ID:** `M13-D-STAGE-2B2-IMPLEMENTATION-PLAN`  
**Date:** 2026-11-24  
**Status:** READY FOR AUTHORIZATION / AMENDED POST-FINAL CORRECTNESS REVIEW (FCR-07)  
**Target Milestone:** Milestone 13-D (Distributed Consensus Engine) — Stage 2-B.2  
**Auditor / Architect:** Antigravity Autonomous Security & Architecture Reviewer  
**Direct Predecessors & Accepted Architecture Baseline:**
1. `docs/M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md`
2. `docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md`
3. `docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md`
4. `docs/M13-D-STAGE-2B1-IMPLEMENTATION-REPORT.md`
5. `docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md`
6. `docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md`
7. `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md`
8. `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md`
9. `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md`
10. `docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md`
11. `docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md`
12. `src/witness/migrations/003_d3_consensus_state.sql`

---

## 1. Executive Summary

Milestone 13-D Phase D3 Stage 2-B.1 implemented and verified the pure in-memory application state-machine contracts, domain models, and deterministic reducer (`ConsensusStateMachine`). The subsequent architectural closure series (ADR-010 through ADR-014) established the exact mathematical boundaries, transactional invariants, crash-durability protocols, and canonical type-tagging rules governing persistent execution.

**Stage 2-B.2: Persistent State-Machine Integration** bridges the pure reducer to durable relational persistence and snapshot storage. It transforms the in-memory reducer into an enterprise-grade, crash-resilient consensus engine capable of bounded-memory execution, cold-start bootstrap, two-tier replay verification, and etcd compaction coordination.

This final amended implementation plan incorporates all technical review corrections (C1–C6, FCR-01–FCR-06) and the final correctness closure amendments (**FCR-07.1 through FCR-07.5**). It provides an adversarial, mathematically sound foundation for persistent state execution, covering contiguous durability verification during database migration, empirical physical revision telemetry, race-safe snapshot cleaner coordination, cryptographically verified hash-chain genesis recovery, and comprehensive etcd watch boundary test suites.

### 1.1 Core Objectives of Stage 2-B.2
1. **Bounded In-Memory Retention & Watch Backpressure (WP1 / C1, FCR-01):** Bound in-memory state to an operational sliding window ($W_{mem}$) governed by the retention floor $F_{ret} = \max(1\text{n}, \min(A_{app} - W_{mem} + 1\text{n}, L_{c\_persisted} + 1\text{n}))$. Enforce explicit persistence lag ($\Delta_{lag\_max}$) and in-memory backlog ($B_{max}$) limits. Never assume a paused watch stream remains alive: implement explicit pause, drop, exponential jitter reconnect, and snapshot catch-up protocols. Prove events cannot be skipped or double-applied.
2. **Relational Persistence, Concurrency & Migration 004 (WP2 / C2, C3, C6, FCR-04, FCR-06, FCR-07.1):** Author and verify Migration 004 to introduce `uq_consensus_log_proposal_id`, add physical cursor columns to `witness_raft_state`, add `canonicalization_version` to `witness_consensus_log`, backfill cursors using a strict contiguous-prefix calculation algorithm (failing closed on gaps or corrupt sequences), and create `witness_snapshots`. Enforce table-level exclusive locks during preflight/index creation. Enforce single-writer serialization (`FOR UPDATE`) and publish candidate state in memory only after PostgreSQL `COMMIT` succeeds.
3. **Multi-Backend Snapshot Engine & Concurrency Safety (WP3 / C4, FCR-02, FCR-07.3):** Implement `ApplicationStateSnapshot` supporting distinct storage semantics: POSIX (6-step rename with parent-dir `fsync`), AWS S3 (conditional `If-None-Match: *` with `ChecksumSHA256`), and Google Cloud Storage (preconditioned `x-goog-if-generation-match: 0` with CRC32C verification). Implement active lease coordination, a mandatory 1-hour grace period, and a final database reference check immediately prior to deletion to prevent the orphan cleaner from deleting in-flight artifacts. Add crash-injection tests across all publication boundaries.
4. **Type-Tagged Canonicalization (WP4 / C2, FCR-05):** Implement the Type-Tagged Canonical Format (TTCF-v1 / Canon-v2), eliminating BigInt/String/Number ambiguity while preserving backward compatibility with legacy v1 digests through durable database version discriminators in both log entries and snapshot manifests.
5. **Dimensionally Correct Compaction Readiness (WP5 / C5, FCR-03, FCR-07.2):** Establish physical revision tracking ($R_{pg\_persisted}$) accounting for multi-event revisions. Prove compaction safety ($R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$). Ground revision conversion in exact physical etcd Prometheus telemetry, require operational calibration prior to enabling automatic compaction, and preserve Stage 2-B0.2 sub-index filtering on watch recovery.
6. **Cryptographic Replay Chain & Genesis Correctness (WP2 / FCR-06, FCR-07.4):** Formally define the 5-step hash-chain verification algorithm for genesis recovery, snapshot selection, fallback to earlier snapshots, contiguous log replay, and atomic state publication.
7. **etcd Watch Boundary Verification (WP1, WP5 / FCR-07.5):** Implement explicit test scenarios for inclusive start revisions, multi-event revisions, mid-batch disconnects, cursor resumption, compaction recovery, and zero-loss / zero-duplicate invariants.

---

## 2. Fundamental System Invariants

Stage 2-B.2 establishes five inviolable architectural invariants that must be satisfied by all subsystems under nominal, partitioned, and crash conditions:

* **INV-RET-01 (Durable Retention Invariant):**  
  An application log entry at index $L_{app}$ can be evicted from memory if and only if its identical proposal ID and payload hash are contiguously committed to PostgreSQL:
  $$L_{app} < F_{ret} \implies L_{app} \le L_{c\_persisted}$$
  No entry is ever pruned from memory before it is durably verifiable in PostgreSQL.

* **INV-REP-01 (Idempotent Two-Tier Replay Invariant):**  
  For any committed consensus entry with log index $L \le A_{app}$, re-applying the entry must yield an idempotent `ALREADY_APPLIED` result without mutating application state if its proposal ID and payload hash match, or fail closed with a fatal deterministic error if they conflict:
  $$\forall L \le A_{app}: \text{apply}(S, E_L) = \begin{cases}
  \text{ALREADY_APPLIED}(S) & \text{if } \text{verify}(E_L) = \text{VALID} \\
  \text{CONFLICT_ERROR} & \text{if } \text{verify}(E_L) = \text{MISMATCH}
  \end{cases}$$
  Verification checks in-memory maps if $L \ge F_{ret}$ (Tier 1) or queries `witness_consensus_log` if $L < F_{ret}$ (Tier 2).

* **INV-SNAP-01 (Authoritative Snapshot Durability Invariant):**  
  A snapshot file on storage (disk, S3, GCS) is authoritative if and only if its exact metadata record is durably committed in PostgreSQL `witness_snapshots`. Any storage artifact lacking a matching committed row in `witness_snapshots` is considered uncommitted and must be safely purged after its grace period expires.

* **INV-COMP-01 (Compaction Durability Invariant):**  
  etcd compaction at revision $R_{comp}$ must never prune any physical revision containing unpersisted or partially persisted events:
  $$R_{comp} \le \min\big(R_{snap}, \; R_{pg\_persisted}\big) - \Delta_{buffer} < R(E_{unpersisted})$$

* **INV-AUTH-01 (PostgreSQL Authority Invariant):**  
  PostgreSQL committed state is the sole authoritative state of the witness node. Candidate state evaluated in memory remains uncommitted and must never become authoritative until the corresponding PostgreSQL transaction commits. On process crash or restart, in-memory state is reconstructed strictly from PostgreSQL logs and snapshots.

---

## 3. Current-State Repository Assessment

### 3.1 Existing Codebase Assets
* **State Machine Contracts (`src/witness/state-machine-types.ts`):**  
  Defines `ApplicationState`, `CommittedConsensusEntry`, `ConsensusPayloadMap`, error classes, and immutable collection interfaces. `ApplicationState` currently tracks `appliedIndices: ReadonlyMap<bigint, AppliedIndexRecord>` and `appliedProposals: ReadonlyMap<string, bigint>`.
* **Pure State Machine Reducer (`src/witness/state-machine.ts`):**  
  Implements `ConsensusStateMachine.apply()`. Fully frozen state objects; zero external I/O; 20 unit tests in `test/witness/state-machine.test.ts` (100% pass rate).
* **Migration 003 (`src/witness/migrations/003_d3_consensus_state.sql`):**  
  Creates `witness_consensus_log` (`PRIMARY KEY (epoch_id, log_index)`) with non-unique `idx_consensus_log_proposal_id`, and `witness_raft_state` (`PRIMARY KEY (cluster_id, epoch_id)`).

### 3.2 Delta & Gaps to Close in Stage 2-B.2
Table 3.1 establishes the specific technical delta between current repository assets and the Stage 2-B.2 targets:

### Table 3.1: Architectural Gaps & Implementation Targets

| Subsystem | Current State in Repository | Required Target in Stage 2-B.2 | Target WP |
| :--- | :--- | :--- | :--- |
| **In-Memory Retention & Backpressure** | Unbounded $O(N)$ growth of `appliedIndices` and `appliedProposals`. Missing index $\le A_{app}$ throws `UnverifiableHistoricalEntryError`. No backpressure when persistence lags. | Implement $F_{ret}$ formula; emit `HISTORICAL_RECORD_PRUNED`; coordinate dual eviction of `appliedIndices` & `appliedProposals`; enforce $\Delta_{lag\_max}$ and watch pause/resume. | **WP1 (C1, FCR-01)** |
| **Two-Tier Replay & Authority** | Memory-only check. No fallback mechanism to PostgreSQL. | Two-tier verification: In-memory hot path ($L \ge F_{ret}$) with automatic fallback to PostgreSQL `witness_consensus_log` ($L < F_{ret}$); candidate state published only post-commit. | **WP1 & WP2 (C6, FCR-06)** |
| **Database Schema & Backfill** | `idx_consensus_log_proposal_id` is non-unique; `witness_raft_state` lacks physical cursor columns; `witness_snapshots` table does not exist; no canonical version tracking. | Migration 004 adds `uq_consensus_log_proposal_id`, physical cursors to `witness_raft_state`, `canonicalization_version` to log, backfills contiguous cursor, and creates `witness_snapshots`. | **WP2 (C2, C3, FCR-04, FCR-07.1)** |
| **Persistence Adapter** | `PostgresWitnessStore` handles D1/D2 ticket lifecycle. No consensus log ingestion or `witness_raft_state` integration. | Create `PostgresConsensusStore` implementing single-writer locking, atomic log batch commit, Tier 2 replay verification, and safe crash recovery. | **WP2 (C3, C6, FCR-06, FCR-07.4)** |
| **Snapshot Management & Concurrency** | No snapshot interfaces, serializers, validators, or staged file publication logic. | Create `SnapshotManager` implementing multi-backend publication (POSIX, S3, GCS), active lease protection against orphan cleaners, and crash-injection resilience. | **WP3 (C4, FCR-02, FCR-07.3)** |
| **Canonical Serialization** | Canon-v1 serializes BigInt as JSON string (`"100"`), colliding with string `"100"`. No version tagging in DB. | Implement TTCF-v1 (Canon-v2) with prefixes (`bi:`, `n:`, `"`), negative zero (`n:0`), Unicode NFC, `"TTCF-v1\n"` prefix, and DB version column routing. | **WP4 (C2, FCR-05)** |
| **etcd Cursor Tracking & Compaction** | `ApplicationState` tracks `lastPhysicalCursor`, but PostgreSQL does not persist it. Multi-event revisions unhandled. | Persist contiguous $R_{etcd}$ and $S_{idx}$ to `witness_raft_state`, handle multi-event revisions, enforce dimensionally calibrated $\Delta_{buffer}$ compaction equation with telemetry prerequisites. | **WP5 (C5, FCR-03, FCR-07.2)** |

---

## 4. Architecture & Data-Flow Description

```
========================================================================================
STAGE 2-B.2 PERSISTENT CONSENSUS ARCHITECTURE & TRANSACTION PUBLICATION
========================================================================================

                 +-------------------------------------------------------+
                 |            etcd Raft Cluster (Consensus Bus)          |
                 |  - Linearizes proposals into global revisions (R_etcd)|
                 |  - Dispatches watch events with sub-indexes (S_idx)   |
                 +---------------------------+---------------------------+
                                             |
                                             | (Physical Watch Stream)
                                             v
                 +-------------------------------------------------------+
                 |           EtcdClientAdapter (Stream Consumer)         |
                 |  - Resumes watch from R_persisted (or R_snap)         |
                 |  - Filters: R == R_persisted && S_idx <= S_persisted  |
                 |  - BACKPRESSURE: Pauses when Lag >= Delta_lag_max     |
                 |  - RECONNECT: Jittered backoff if stream drops        |
                 |  - CATCH-UP: Triggers snapshot restore on compacted   |
                 +---------------------------+---------------------------+
                                             |
                                             | CommittedConsensusEntry
                                             v
                 +-------------------------------------------------------+
                 |        PostgresConsensusStore (Engine Coordinator)    |
                 |  1. Locks witness_raft_state FOR UPDATE (Single Writer)
                 |  2. Pure transition: candidateState = apply(currState) |
                 +-------------+---------------------------+-------------+
                               |                           |
                 (L_app < F_ret)|                           | (Pure Transition)
                               v                           v
                 +---------------------------+   +-----------------------+
                 | Tier 2 Replay Lookup      |   | ConsensusStateMachine |
                 | (witness_consensus_log)   |   | - Sliding window W_mem|
                 | - Confirms proposal_id    |   | - Enforces contiguity |
                 |   and payload_hash (v1/v2)|   | - Computes chain hash |
                 +---------------------------+   +-----------+-----------+
                                                             |
                                                             | Candidate State Held
                                                             v
                 +-------------------------------------------------------+
                 |          Single-Transaction ACID Database Commit      |
                 |  1. INSERT INTO witness_consensus_log (canon_version) |
                 |  2. UPDATE Domain Projections (tickets, policies)     |
                 |  3. UPDATE witness_raft_state (A_app, R_persisted)    |
                 |  4. Advances L_c_persisted watermark                  |
                 +---------------------------+---------------------------+
                                             |
                                             | COMMIT SUCCESSFUL
                                             v
                 +-------------------------------------------------------+
                 |          Authoritative In-Memory State Publication    |
                 |  1. this.authoritativeState = candidateState;         |
                 |  2. Acknowledge entry completion to etcd watch        |
                 |  3. Check backpressure: Unpause if Lag <= resume_lag  |
                 +---------------------------+---------------------------+
                                             |
                 (Periodic Snapshot Trigger) |
                                             v
                 +-------------------------------------------------------+
                 |            SnapshotManager (Multi-Backend Engine)     |
                 |  POSIX: 1. Temp -> 2. fsync -> 3. Rename -> 4. Dir fsync
                 |  S3:    Atomic PUT with ChecksumSHA256 & If-None-Match
                 |  GCS:   Precondition PUT with x-goog-if-generation-match
                 |  Lease: Active lease + DB re-check fences cleaner     |
                 |  PostgreSQL: Commit Metadata to witness_snapshots     |
                 +-------------------------------------------------------+
```

---

## 5. Work-Package Breakdown

```
========================================================================================
WP1: In-Memory Retention, Watch Backpressure Lifecycle & Two-Tier Replay
========================================================================================
```

### Objectives
1. Eliminate unbounded memory growth in `ConsensusStateMachine`.
2. Implement the mathematically proven retention floor $F_{ret}$.
3. Coordinate simultaneous pruning of `appliedIndices` and `appliedProposals`.
4. Implement `HISTORICAL_RECORD_PRUNED` status for Tier 2 fallback.
5. Guarantee invariant **INV-RET-01** ($L < F_{ret} \implies L \le L_{c\_persisted}$).
6. **(FCR-01, FCR-07.5) Complete etcd Watch Lifecycle:** Implement pause, drop, jittered reconnect, catch-up restoration, boundary testing, and prove no-skip / no-duplicate semantics.

### Detailed Technical Specifications

#### 1. Why $W_{mem}$ Alone Fails Under Persistence Lag
The retention floor is defined as:
$$F_{ret} = \max\Big(1\text{n}, \; \min\big(A_{app} - W_{mem} + 1\text{n}, \; L_{c\_persisted} + 1\text{n}\big)\Big)$$
When PostgreSQL persistence stalls ($L_{c\_persisted} < A_{app} - W_{mem}$), $F_{ret} = L_{c\_persisted} + 1\text{n}$. Because **INV-RET-01** prevents pruning unpersisted entries, entries cannot be evicted. Unbounded watch ingestion under lag yields $O(N)$ memory growth.

#### 2. Explicit Watch Backpressure, Disconnect & Reconnect Protocol (FCR-01)
* **Backpressure & Memory Thresholds:**
  - $\Delta_{lag\_max} = 1,000\text{ entries}$ (persistence lag $L_{lag} = A_{app} - L_{c\_persisted}$).
  - $W_{mem} = 10,000\text{ entries}$ (nominal in-memory retention window).
  - $B_{max} = W_{mem} + \Delta_{lag\_max} = 11,000\text{ entries}$ (hard in-memory backlog limit).
  - **Memory Footprint Bound ($M_{max}$):** At an average entry size of 5 KB (maximum allowable payload 64 KB), $B_{max}$ enforces a hard upper bound of $\le 55\text{ MB}$ (worst-case $\le 704\text{ MB}$ under maximum payload saturation). Memory cannot grow without bound.
  - $\Delta_{lag\_resume} = 500\text{ entries}$ (hysteresis low-watermark resume).
* **Alerting & Escalation Thresholds:**
  - **WARNING:** Emitted when $L_{lag} \ge 500$ entries (`CONSENSUS_PERSISTENCE_LAG_WARNING`).
  - **CRITICAL ALERT:** If $L_{lag} \ge \Delta_{lag\_max} (1,000)$ persists for $> 30\text{ seconds}$, emit `CONSENSUS_PERSISTENCE_LAG_CRITICAL`. PagerDuty/webhook escalation triggered.
  - **HARD CEILING ERROR:** If in-memory unpersisted entries reach $B_{max}$, the consumer throws `BacklogLimitExceededError` and forcibly terminates the watch stream (`watchStream.destroy()`) to protect process heap integrity.
* **Database Retry & Failure Handling:**
  - When persisting a batch of consensus log entries, `PostgresConsensusStore` executes up to 5 retries with exponential backoff and decorrelated jitter ($t_{retry} = \min(5000\text{ms}, 100\text{ms} \times 2^{attempt}) \pm \text{random}$).
  - If all 5 retries fail, the transaction rolls back, candidate state is discarded, and the engine halts ingestion.
  - The watch stream remains paused/disconnected; zero new events are admitted into memory while persistence is impaired.
* **The "Paused Stream Dead" Problem:**  
  A consumer cannot assume that a paused gRPC watch stream stays open indefinitely. Firewalls, proxies, OS TCP keepalives, or etcd server settings (`--max-request-bytes`, idle stream timeouts) will terminate paused streams.
* **Stream State Machine:**  
  States: `STREAMING`, `BACKPRESSURE_PAUSED`, `DISCONNECTED`, `RECONNECTING`, `CATCH_UP_RECOVERY`.
  1. **Pause:** When $L_{lag} \ge \Delta_{lag\_max}$, transition to `BACKPRESSURE_PAUSED`. Call `watchStream.pause()`. If the server closes the stream with `RST_STREAM` or timeout while paused, transition to `DISCONNECTED`.
  2. **Disconnect Handling:** On stream error, EOF, or network timeout:
     - Record failure.
     - Transition to `RECONNECTING`.
  3. **Jittered Exponential Reconnect:**
     - Compute backoff: $t = \min(t_{max}, t_{base} \times 2^{attempt}) \times (0.5 + \text{random}())$.
     - Read the latest durably committed cursor from PostgreSQL: $(R_{last}, S_{last}) = (\text{last\_applied\_etcd\_revision}, \text{last\_applied\_sub\_index})$.
     - If in `BACKPRESSURE_PAUSED` when reconnecting, hold reconnection until $L_{lag} \le \Delta_{lag\_resume}$.
     - Once unpaused, initiate `watchClient.watch(key, { startRevision: R_{last} })`.
  4. **Sub-Index Event Deduplication:**
     - For every received event $(R, S_{idx})$:
       $$\text{if } R < R_{last} \lor (R == R_{last} \land S_{idx} \le S_{last}) \implies \text{DROP (already applied)}$$
  5. **Compacted Recovery Catch-Up:**
     - If etcd returns error code `11 (OUT_OF_RANGE)` / `EtcdCompactedError`:
       - The requested revision $R_{last}$ has been pruned by etcd compaction!
       - Transition to `CATCH_UP_RECOVERY`.
       - Query `witness_snapshots` for highest snapshot index $\le L_{c\_persisted}$.
       - Rehydrate state from snapshot blob, verify SHA-256 and chain head hash.
       - Replay remaining entries from `witness_consensus_log` up to $L_{c\_persisted}$.
       - Obtain new physical cursor $(R_{snap}, S_{snap})$.
       - Reopen etcd watch at $R_{snap}$.

#### 3. Mathematical Proof of Zero Event Skips and Zero Duplication (FCR-01)
* **Proof of Zero Skips:**  
  etcd assigns monotonically increasing physical revisions to Raft log entries. Resuming at $R_{last}$ ensures etcd sends all events starting at $R_{last}$. All events with $R > R_{last}$ are processed. Since $R_{last}$ was durably recorded in PostgreSQL upon committing the last event, no committed event is omitted.
* **Proof of Zero Duplication:**  
  Events at $R == R_{last}$ with $S_{idx} \le S_{last}$ are discarded by the consumer filter. Furthermore, if an event passes the consumer filter, `ConsensusStateMachine.apply()` checks $L \le A_{app}$ and proposal uniqueness, returning `ALREADY_APPLIED` idempotently without state mutation. Thus, no event is applied twice.  
  $\blacksquare$

---

```
========================================================================================
WP2: PostgreSQL Persistence, Concurrency & Migration 004 Safety Closure
========================================================================================
```

### Objectives
1. Design and author `Migration 004` and its rollback script.
2. Implement strict table-locking concurrency controls before preflight verification.
3. Augment `witness_raft_state` with physical cursor and snapshot tracking columns.
4. **(FCR-07.1 Correction) Contiguous Durability Backfill:** Formalize strict contiguous prefix calculation, gap detection, duplicate rejection, and fail-safe migration aborts.
5. **(FCR-05 Correction) Canonicalization Version Column:** Add `canonicalization_version` to `witness_consensus_log` to support dual v1/v2 payload verification.
6. **(FCR-06, FCR-07.4 Correction) Two-Phase State Publication & Hash-Chain Genesis Replay:** Publish candidate state in memory only after PostgreSQL `COMMIT` succeeds; define exact 5-step hash-chain verification and snapshot fallback.

### Detailed Technical Specifications

#### 1. Contiguous Durability Backfill Algorithm & Gap Detection (FCR-07.1)
Using `MAX(log_index)` alone is invalid because an interrupted migration, failed batch write, or manual database intervention could leave gaps (e.g. log indices 1, 2, 4 present, but 3 missing). Setting $L_{c\_persisted} = 4$ would violate **INV-RET-01** by falsely claiming index 3 was persisted.

##### Strict Backfill Protocol for Existing Migration 003 Databases
For each row in `witness_raft_state`:
1. **Empty Log Case:** If `COUNT(*) == 0` in `witness_consensus_log` for that `epoch_id`, set `last_consecutive_persisted_index = 0`.
2. **Non-Empty Log Case:**
   - **Verification 1 (Genesis Index):** Assert `MIN(log_index) == 1`. If `MIN(log_index) != 1`, abort migration immediately:
     `RAISE EXCEPTION 'Migration 004 aborted: epoch % log_index does not start at 1 (starts at %)', r.epoch_id, v_min_index;`
   - **Verification 2 (Duplicate Indices):** Assert `COUNT(*) == COUNT(DISTINCT log_index)`. If duplicates exist, abort immediately:
     `RAISE EXCEPTION 'Migration 004 aborted: duplicate log_index detected in epoch %', r.epoch_id;`
   - **Verification 3 (Contiguity & Gap Detection):** Find the earliest missing index in the sequence $[1, \text{MAX}(log\_index)]$:
     ```sql
     SELECT COALESCE(MIN(expected_index) - 1, (SELECT MAX(log_index) FROM witness_consensus_log WHERE epoch_id = r.epoch_id))
     INTO v_contiguous_max
     FROM (
         SELECT generate_series(1, (SELECT MAX(log_index) FROM witness_consensus_log WHERE epoch_id = r.epoch_id)) AS expected_index
     ) exp
     LEFT JOIN witness_consensus_log act
       ON act.epoch_id = r.epoch_id AND act.log_index = exp.expected_index
     WHERE act.log_index IS NULL;
     ```
   - **Verification 4 (Contiguity Assertion):** Assert `v_contiguous_max == MAX(log_index)`. If `v_contiguous_max < MAX(log_index)`, a gap exists. **Fail Closed:**
     `RAISE EXCEPTION 'Migration 004 aborted: non-contiguous log index sequence in epoch % (contiguous prefix reaches %, max index is %). Durable prefix cannot be proven.', r.epoch_id, v_contiguous_max, v_max_index;`
   - **Commit Backfill:** Update `last_consecutive_persisted_index = v_contiguous_max`.
3. **Fresh Database Case:** On a clean database with 0 rows, all columns initialize with their declared defaults (`DEFAULT 0`).

#### 2. Migration 004 Execution Matrix
Table 5.1 specifies migration behavior across all database configurations:

### Table 5.1: Migration 004 Execution Matrix

| Scenario / Condition | Operational Behavior & State Resolution | Guard / Invariant Enforced |
| :--- | :--- | :--- |
| **Fresh Database** | Runs migrations 001 $\to$ 002 $\to$ 003 $\to$ 004. Tables created empty; constraints applied cleanly. | Clean installation path. |
| **Existing Migration 003 DB** | Adds columns to `witness_raft_state` with default 0. Adds `canonicalization_version` to `witness_consensus_log` with default 1. | Non-destructive schema evolution. |
| **Existing Row Cursor Backfill** | Validates `MIN(log_index) == 1`, no duplicates, and contiguous sequence. Sets `last_consecutive_persisted_index = v_contiguous_max`. | **INV-RET-01:** Never advance durability watermark across gaps. |
| **Non-Contiguous History** | Gap detected in `witness_consensus_log`. Migration aborts with `RAISE EXCEPTION`. Transaction rolled back. | Fails closed; prevents corruption of consensus state. |
| **Preflight Duplicate Detection** | Scans `witness_consensus_log` for duplicate `(epoch_id, proposal_id)`. If count $> 0$, executes `RAISE EXCEPTION` and aborts transaction. | Guarantees partial unique index creation cannot fail midway. |
| **Index Verification & Swap** | Verifies non-unique `idx_consensus_log_proposal_id` exists, drops it, and creates `uq_consensus_log_proposal_id WHERE proposal_id IS NOT NULL`. | Prevents duplicate index bloat. |
| **Concurrent Writer Blocking** | Executes `LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;` and `LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;`. | Eliminates concurrent write race conditions during preflight and DDL. |
| **Interruption & Retry** | Entire migration wrapped in `BEGIN ... COMMIT;`. Uses `IF NOT EXISTS` on columns and checks constraint existence before adding. | Perfectly idempotent; safe to re-run after partial network failure. |
| **Rollback Data Safety Guard** | Rollback checks `SELECT COUNT(*) FROM witness_snapshots;` and `last_applied_etcd_revision`. If active data exists, aborts unless override is set. | Prevents catastrophic accidental data loss in production. |

#### 3. Cryptographic Hash-Chain Verification & Genesis Replay Protocol (FCR-07.4)
On node startup or post-commit crash recovery, `PostgresConsensusStore` reconstructs authoritative in-memory state through the following deterministic 5-step procedure:

1. **Snapshot Selection & Validation:**
   - Query `witness_snapshots` for candidates where `cluster_id = $cluster AND epoch_id = $epoch AND snapshot_index <= last_consecutive_persisted_index` ORDER BY `snapshot_index DESC`.
   - Iterate candidates in descending order:
     - Check file existence on storage backend (POSIX, S3, GCS).
     - Read blob, calculate SHA-256 digest, assert equality with `snapshot_hash`.
     - Deserialize manifest; verify `format_version == 1` and `canonicalization_version IN (1, 2)`.
     - Verify `cluster_id` and `epoch_id` match current running parameters.
     - If candidate is valid: set `baseState = rehydrate(blob)`, `expectedChainHead = baseState.chainHeadHash`, `L_start = baseState.lastAppliedAppIndex + 1n`. Break loop.
     - If candidate fails integrity check: log warning (`SnapshotIntegrityError`), mark corrupt, and fall back to the next earlier valid snapshot.
   - **Genesis Fallback (No Valid Snapshot Exists):**
     If no valid snapshot is found, initialize genesis:
     `baseState = INITIAL_APPLICATION_STATE`, `expectedChainHead = GENESIS_CHAIN_HEAD_HASH` (`"0000000000000000000000000000000000000000000000000000000000000000"`), `L_start = 1n`.
2. **Contiguous Log Query:**
   - Query `witness_consensus_log` WHERE `epoch_id = $epoch AND log_index >= $L_start AND log_index <= last_consecutive_persisted_index` ORDER BY `log_index ASC`.
   - Assert contiguous sequence: row $0$ must have `log_index == L_start`, and row $i$ must have `log_index == row[i-1].log_index + 1n`. Any missing index throws `UnverifiableHistoricalEntryError` and aborts recovery.
3. **Cryptographic Chaining Assertion Loop:**
   - For each replayed entry $E$:
     - Assert `E.cluster_id === clusterId` and `E.epoch_id === epochId`.
     - Assert `E.previousEntryHash === expectedChainHead`.
     - Compute payload hash: `computedHash = computeCanonicalPayloadHash(E.payload, E.canonicalization_version)`.
     - Assert `computedHash === E.payload_hash`.
     - Compute new entry hash: `H_entry = sha256(E.previousEntryHash + ":" + E.log_index + ":" + E.proposal_id + ":" + computedHash)`.
     - Assert `E.entry_hash === H_entry`.
     - Advance expected chain head: `expectedChainHead = H_entry`.
     - Apply entry to state slice: `baseState = ConsensusStateMachine.apply(baseState, E).state`.
4. **Watermark Parity Check:**
   - Assert `baseState.lastAppliedAppIndex === last_consecutive_persisted_index`.
5. **Atomic Publication:**
   - Only after all entries up to $L_{c\_persisted}$ have been verified with 100% cryptographic parity, publish state:
     `this.authoritativeState = baseState;`.
   - If replay is interrupted or fails at any step, the candidate replayed state is discarded. Invariant **INV-AUTH-01** is strictly preserved.

#### 4. Missing witness_raft_state Bootstrap & Single-Transaction Invariants
* **Missing Row Bootstrap:** If `witness_raft_state` contains no row for the running `(cluster_id, epoch_id)`, `PostgresConsensusStore` executes an atomic idempotent bootstrap:
  ```sql
  INSERT INTO witness_raft_state (
      cluster_id, epoch_id, term, leader_id, last_applied_app_index,
      last_applied_etcd_revision, last_applied_sub_index,
      last_consecutive_persisted_index, last_snapshot_index, last_snapshot_hash
  ) VALUES ($1, $2, 0, '', 0, 0, 0, 0, 0, '')
  ON CONFLICT (cluster_id, epoch_id) DO NOTHING;
  ```
  Immediately followed by acquiring the single-writer lock:
  ```sql
  SELECT * FROM witness_raft_state WHERE cluster_id = $1 AND epoch_id = $2 FOR UPDATE;
  ```
  This eliminates bootstrap race conditions between concurrent worker threads or failover coordinators.
* **Atomic Single-Transaction Invariant:**
  Every state transition write is bound to a single ACID PostgreSQL transaction (`BEGIN ... COMMIT`):
  1. `INSERT INTO witness_consensus_log (...) VALUES (...)` with explicit `canonicalization_version`.
  2. Domain projection mutations (tickets, authorizations, nonces).
  3. `UPDATE witness_raft_state SET last_applied_app_index = $1, last_consecutive_persisted_index = $2, last_applied_etcd_revision = $3, last_applied_sub_index = $4 WHERE cluster_id = $5 AND epoch_id = $6;`
  If any write fails, a deadlock occurs, or connectivity is severed, the entire transaction is rolled back via `ROLLBACK`. Candidate state is discarded immediately. Neither log indices nor durability watermarks are ever partially advanced.

---

```
========================================================================================
WP3: Multi-Backend Snapshot Storage & Race-Safe Cleaner Coordination
========================================================================================
```

### Objectives
1. Implement `ApplicationStateSnapshot` contract with comprehensive metadata.
2. Separate storage protocols for POSIX, Amazon S3, and Google Cloud Storage.
3. **(FCR-07.3 Correction) Race-Safe Snapshot Cleanup:** Implement active lease registration, renewal, expiration fencing, a 1-hour grace period, and a final database reference check immediately before deletion.
4. Define precise GCS upload and CRC32C checksum verification contract.
5. Add crash-injection test suite (CI-1 through CI-8) across all publication boundaries.

### Detailed Technical Specifications

#### 1. Snapshot Storage Protocols by Backend (FCR-02, FCR-07.3)

##### Protocol A: Local POSIX Filesystem (6 Steps)
1. Write temporary file: `{storageDir}/{snapshotId}.tmp`.
2. Flush file descriptor: `fs.fsyncSync(fileDescriptor)`. Close fd.
3. Atomic rename within same filesystem:  
   `fs.renameSync("{storageDir}/{snapshotId}.tmp", "{storageDir}/{snapshotId}.snap")`.
4. Flush parent directory descriptor: Open `{storageDir}`, call `fs.fsyncSync(parentDirDescriptor)`. Close dir fd.
5. Checksum verification readback: Read file, compute SHA-256, assert match with `snapshotHash`.
6. PostgreSQL metadata commit: Insert row into `witness_snapshots` within an ACID transaction.

##### Protocol B: Amazon S3 (Conditional Write & Transport Checksums)
1. Compute SHA-256 and MD5 digests in memory.
2. Execute `PutObjectCommand`:
   - Key: `snapshots/{clusterId}/{epochId}/{snapshotId}.snap`.
   - Headers: `If-None-Match: *` (conditional write ensuring key does not exist).
   - Checksum: `ChecksumSHA256: <base64-sha256>`, `ContentMD5: <base64-md5>`.
3. Validate S3 response: Assert HTTP 200/201 and matching `ETag` / `ChecksumSHA256`.
4. If S3 returns HTTP 412 (Precondition Failed), throw `SnapshotCollisionError` (unique ID conflict).
5. PostgreSQL metadata commit: Insert row into `witness_snapshots` with `storage_backend = 's3'`.

##### Protocol C: Google Cloud Storage (Generation-Match & CRC32C Verification Contract)
1. Compute SHA-256 digest and CRC32C (Castagnoli 0x1EDC6F41) checksum in memory.
2. Execute upload with generation-match precondition:
   - Destination URI: `gs://{bucket}/{clusterId}/{epochId}/{snapshotId}.snap`.
   - Precondition Header: `x-goog-if-generation-match: 0` (object creation succeeds only if object does NOT exist).
   - Validation: Parse response header `x-goog-hash: crc32c=<base64-crc32c>`.
   - Assert that returned `crc32c` exactly matches the local computed Base64 CRC32C value.
   - Assert returned object byte size matches `byteSize`.
3. If GCS returns HTTP 412, throw `SnapshotCollisionError`.
4. PostgreSQL metadata commit: Insert row into `witness_snapshots` with `storage_backend = 'gcs'`.

#### 2. Race-Safe Orphan Cleaner Coordination & Fencing Protocol (FCR-07.3)
To eliminate race conditions between in-flight snapshot publication, delayed writers, and background cleanup sweeps:

* **Publication Lease Registration:**
  Before beginning file write or upload, `SnapshotManager` registers an active lease:
  `INSERT INTO witness_snapshot_leases (snapshot_id, worker_id, expires_at) VALUES ($1, $2, NOW() + INTERVAL '10 minutes');`
  While uploading large states, the worker periodically heartbeats to extend `expires_at`.
* **Mandatory Age Grace Period:**  
  The orphan cleaner **NEVER** inspects or purges any file whose creation or modification timestamp is less than $T_{grace} = 1\text{ hour}$ old ($T_{grace} \ge 30\text{ minutes}$).
* **Four-Fold Deletion Verification & Final Database Check:**  
  When the cleaner identifies an unreferenced candidate file on storage:
  1. *Age Verification:* Confirms file age $> 1\text{ hour}$.
  2. *Lease Check:* Queries `witness_snapshot_leases` - confirms NO active (unexpired) lease exists for `snapshot_id`.
  3. *Snapshot Reference Check:* Queries `witness_snapshots` - confirms NO committed row exists for `snapshot_id`.
  4. *Raft State Check:* Queries `witness_raft_state` - confirms `last_snapshot_hash` does not match.
  5. *Final Re-Check (Delayed Writer Guard):* Immediately prior to executing `unlink()` or `DeleteObject()`, within an active PostgreSQL transaction, the cleaner executes:
     `SELECT 1 FROM witness_snapshots WHERE snapshot_id = $1 FOR UPDATE;`
     If a delayed writer committed in the last millisecond, a row now exists; the cleaner aborts deletion immediately.
* **Cleaner Crash Resilience:**  
  The cleaner is fully stateless and idempotent. A crash at any point during scanning or deletion leaves storage consistent; the next scheduled run resumes cleanly.

---

```
========================================================================================
WP4: Type-Tagged Canonicalization (TTCF-v1 / Canon-v2)
========================================================================================
```

### Objectives
1. Implement Type-Tagged Canonical Format (TTCF-v1) in `src/witness/canonical-serializer.ts`.
2. Guarantee mathematical distinction across all 7 types (Null, Boolean, Number, BigInt, String, Array, Object).
3. Normalize negative zero (`-0` $\to$ `n:0`), enforce Unicode NFC normalization, and reject IEEE 754 unsafe integers.
4. Reject duplicate normalized object keys.
5. Embed domain separation prefix `"TTCF-v1\n"`.
6. **(FCR-05 Correction) Complete Versioning Contract:** Implement dual version serialization and durable version tracking across all storage formats.

### Detailed Technical Specifications
* **Serializer Grammar (`src/witness/canonical-serializer.ts`):**
  - Null: `null`
  - Boolean: `true` / `false`
  - Number: Rejects `NaN`, `Infinity`, unsafe integers ($|n| > 2^{53}-1$). Normalizes `-0` $\to$ `n:0`. Formats finite floats per RFC 8785 $\to$ `n:<num>`.
  - BigInt: `bi:<digits>`.
  - String: Unicode NFC normalized, JSON-escaped, double-quoted.
  - Array: `[item0,item1]`.
  - Object: Keys NFC normalized; duplicate normalized keys throw `TypeError`; sorted by UTF-16 code units; `{k:v}`.
* **Hash Computation:**
  - Version 1: Invokes legacy Canon-v1.
  - Version 2: Emits `sha256("TTCF-v1\n" + canonicalizeValueV2(payload))`.

---

```
========================================================================================
WP5: etcd Persistence Mapping, Telemetry Calibration & Compaction
========================================================================================
```

### Objectives
1. Map physical etcd revisions ($R_{etcd}$) and sub-indexes ($S_{idx}$) to logical log indices ($L_{app}$).
2. Track physical revision progression in `witness_raft_state` ($R_{pg\_persisted}$).
3. **(FCR-07.2 Correction) Ground Compaction in Physical Telemetry:** Formally establish the relationship between application proposals and physical etcd revisions, define exact Prometheus metrics, and mandate production calibration.
4. Enforce invariant **INV-COMP-01** (no unpersisted revision compacted).
5. Implement watch catch-up handler for `EtcdCompactedError` preserving Stage 2-B0.2 sub-index filtering.

### Detailed Technical Specifications

#### 1. Proposal-to-Revision Mapping & Physical Telemetry (FCR-07.2)
In distributed systems using etcd as a consensus log:
* **Application Proposals:** Domain operations submitted by witness coordinators.
* **Raft Proposals:** Internal consensus log entries proposed to the Raft state machine.
* **Committed Transactions:** Linearized atomic writes that commit to etcd storage.
* **Physical MVCC Revisions:** The 64-bit monotonically advancing revision counter incremented by etcd whenever an MVCC write (`Put`, `DeleteRange`, `Txn`) commits.

##### Revision Conversion & Conservative Upper Bound
1. In nominal operation, $N$ application proposals submitted via unbatched transactions generate $N$ physical revisions ($r_{rev/prop} = 1$).
2. When proposals are batched into a single multi-key transaction, $N$ proposals yield 1 revision ($r_{rev/prop} \le 1$).
3. **The System Revision Rate Hazard ($R_{system}$):** Background etcd operations (lease keepalives with keys, leader election heartbeats, cluster membership updates, external tenant writes) advance the physical MVCC revision *independently* of application proposals.
4. Total physical revision rate is:
   $$R_{rate} = \frac{dR}{dt} = \big(P_{rate} \times r_{rev/prop}\big) + R_{system}$$
   Assuming $r_{rev/prop} = 1$ without measuring $R_{system}$ can underestimate revision velocity, causing the compaction window to trail too close to the watch cursor.

##### Exact Prometheus Metrics for Revision Velocity
To establish an empirical, mathematically verified upper bound:
* **Direct Physical Revision Velocity:**
  $$R_{rate} = \text{rate}(\text{etcd\_debugging\_mvcc\_put\_total}[1\text{m}]) + \text{rate}(\text{etcd\_debugging\_mvcc\_delete\_total}[1\text{m}])$$
  (Alternative direct gauge derivative: $\text{deriv}(\text{etcd\_server\_revision}[1\text{m}])$).
* **Application Proposal Arrival Rate:**
  $$P_{rate} = \text{rate}(\text{etcd\_server\_proposals\_committed\_total}[1\text{m}])$$
* **Watch Reconnection Latency:**
  $$T_{reconnect\_p99} = \text{histogram\_quantile}(0.99, \text{rate}(\text{witness\_etcd\_watch\_reconnect\_duration\_seconds\_bucket}[5\text{m}]))$$

##### Compaction Formula & Production Deployment Prerequisites
The compaction safety inequality is:
$$R_{comp} \le \min\big(R_{snap}, \; R_{pg\_persisted}\big) - \Delta_{buffer}$$

#### 2. Formal Compaction Safety Proof & Multi-Event Revision Handling (FCR-03)
* **Definition of $R_{pg\_persisted}$ under Multi-Event Revisions:**  
  In etcd, a single multi-key transaction at physical revision $R$ can emit $K \ge 1$ distinct watch events with sub-indices $S_{idx} \in [0, K-1]$.
  If an interruption or crash occurs after persisting sub-indices $0 \dots j$ ($j < K-1$), revision $R$ is only partially persisted.
  To prevent compacting revision $R$ while sub-indices $j+1 \dots K-1$ remain unpersisted:
  $$R_{pg\_persisted} = \begin{cases}
  R & \text{if all } K \text{ events for revision } R \text{ are committed to PostgreSQL} \\
  R - 1 & \text{if revision } R \text{ is only partially committed}
  \end{cases}$$
  In practice, $R_{pg\_persisted}$ is only advanced to $R$ upon committing the final sub-index of revision $R$ (or a subsequent revision $R' > R$).

* **Theorem (Compaction Safety):**  
  If etcd is compacted to physical revision $R_{comp}$, no committed, candidate, or in-flight consensus event required for witness recovery can ever be lost.
  
  *Proof:*  
  1. By definition of $R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$, we have $R_{comp} < R_{pg\_persisted}$ and $R_{comp} < R_{snap}$.
  2. For every physical event $E$ with revision $R(E) \le R_{comp}$, we have $R(E) < R_{pg\_persisted}$.
  3. By the definition of $R_{pg\_persisted}$, every event with $R(E) < R_{pg\_persisted}$ has been contiguously and durably committed to PostgreSQL `witness_consensus_log` and recorded in `witness_raft_state`.
  4. By **INV-AUTH-01**, PostgreSQL is the sole durable authority for historical state. Once committed to PostgreSQL, a node never requires etcd to replay events at or below $R_{comp}$.
  5. If an active watch stream disconnects, it resumes at $R_{last} \ge R_{pg\_persisted} > R_{comp}$. Because $R_{last} > R_{comp}$, the watch resumption revision has not been compacted.
  6. If a catastrophic disaster requires full cold-start restore, the engine rehydrates from the snapshot at $R_{snap} > R_{comp}$ and replays from PostgreSQL logs.
  7. Therefore, compacting etcd up to $R_{comp}$ removes only physical history that is fully redundant and permanently archived in PostgreSQL. No event can be lost.  
  $\blacksquare$

* **Replacement of the Arbitrary 50,000-Revision Buffer:**  
  A static 50,000-revision buffer is mathematically ungrounded:
  - In high-throughput clusters ($R_{rate} = 2,000\text{ rev/s}$), 50,000 revisions represents only 25 seconds of retention—failing to cover transient network partitions.
  - In low-throughput clusters ($R_{rate} = 0.5\text{ rev/s}$), 50,000 revisions represents $> 27\text{ hours}$ of dead MVCC history, causing severe bbolt B+tree fragmentation and read amplification.
  - The static 50,000 buffer is therefore **strictly replaced** by the evidence-based dimensional formula:
    $$\Delta_{buffer} = \max\Big(\Delta_{buffer\_min}, \; S_f \times R_{rate\_p99} \times T_{reconnect\_p99}\Big)$$
    where $\Delta_{buffer\_min} = 1,000\text{ revisions}$, $S_f = 2.0$, and parameters are dynamically calibrated from live Prometheus metrics.

* **Mandatory Production Safety Guard:**  
  Automatic etcd compaction is **STRICTLY DISABLED BY DEFAULT** (`consensus.compaction.enabled = false`).
  Enabling automatic compaction in production is gated on empirical telemetry verification of $R_{rate\_p99}$ and $T_{reconnect\_p99}$ over a minimum 24-hour observation window. Without verified telemetry, compaction must remain disabled.

---

## 6. Exact Source Files & Proposed Changes

Table 6.1 outlines the exact file changes and new modules to be created:

### Table 6.1: File Modification and Creation Matrix

| File Path | Action | Description & Scope of Changes |
| :--- | :--- | :--- |
| `src/witness/state-machine-types.ts` | **Modify** | Add `retentionFloorIndex`, `lastConsecutivePersistedAppIndex` to `ApplicationState`; add `HISTORICAL_RECORD_PRUNED` status and result types; add `SnapshotMetadata` and versioning types. |
| `src/witness/state-machine.ts` | **Modify** | Update `ConsensusStateMachine.apply()` with $F_{ret}$ evaluation, `HISTORICAL_RECORD_PRUNED` emission, coordinated proposal/index pruning, and v1/v2 hash routing. |
| `src/witness/canonical-serializer.ts` | **Create** | Implements TTCF-v1 canonical grammar, Unicode NFC normalization, negative zero normalization, and `"TTCF-v1\n"` domain separation. |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | **Create** | Migration 004: table-level locks, preflight duplicate checks, `uq_consensus_log_proposal_id`, `canonicalization_version` column, cursor columns, strict contiguous-prefix backfill, and `witness_snapshots` table. |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | **Create** | Rollback script for Migration 004 with active data safety checks. |
| `src/witness/consensus-store.ts` | **Create** | Implements `PostgresConsensusStore`: single-writer locking, two-phase state publication, Tier 2 historical verification fallback, and backpressure monitoring. |
| `src/witness/snapshot-manager.ts` | **Create** | Implements `SnapshotManager`: multi-backend publication (POSIX, S3, GCS), active lease protection, race-safe orphan cleaner coordination, crash-injection safety, checksum verification, and restoration logic. |
| `src/witness/compaction-coordinator.ts` | **Create** | Compaction safety calculation ($R_{comp} \le \min(R_{snap}, R_{pg}) - \Delta$), multi-event revision handling, telemetry-grounded buffer, and post-compaction watch catch-up handler. |
| `test/witness/state-machine.test.ts` | **Modify** | Preserve existing 20 tests; add unit tests for $F_{ret}$ sliding window pruning, `HISTORICAL_RECORD_PRUNED` status, and dual eviction. |
| `test/witness/canonical-ttcf.test.ts` | **Create** | Dedicated test suite for TTCF-v1: BigInt, Number, String, negative zero, unsafe integers, Unicode NFC, duplicate key rejection, and domain separation. |
| `test/witness/migration-004.test.ts` | **Create** | Dedicated test suite for Migration 004: table lock verification, preflight duplicate detection, schema upgrade, contiguous backfill, gap detection abort, rollback parity, and constraint enforcement. |
| `test/witness/consensus-store.test.ts` | **Create** | Integration suite for `PostgresConsensusStore`: single-writer locks, two-phase publication, atomic batch persistence, Tier 2 verification, backpressure triggers, crash recovery, and hash-chain genesis replay. |
| `test/witness/snapshot-manager.test.ts` | **Create** | Integration suite for `SnapshotManager`: staged POSIX publication, S3 PUT simulation, GCS precondition & CRC32C simulation, concurrent cleaner sweep fencing, CI-1 through CI-8 crash-injection cases, and restore parity. |
| `test/witness/compaction-readiness.test.ts` | **Create** | Integration suite for compaction coordinator: multi-event durability tracking, dimensional buffer sizing, compaction gating, stream boundary cases (WB-1 to WB-7), and catch-up recovery. |

---

## 7. Migration 004 Design & Safety Specification

### 7.1 Forward Migration (`004_d3_consensus_persistence.sql`)
```sql
-- Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2
-- Migration 004: Consensus Persistence, Unique Proposals, Canon Versioning & Snapshots
BEGIN TRANSACTION;

-- 1. Concurrency Controls: Acquire Exclusive Table Locks
-- SHARE ROW EXCLUSIVE blocks concurrent INSERT/UPDATE/DELETE on consensus log
LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;
-- EXCLUSIVE blocks all concurrent access to witness_raft_state
LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;

-- 2. Preflight Validation: Assert zero existing duplicate (epoch_id, proposal_id)
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
        RAISE EXCEPTION 'Migration 004 aborted: found % duplicate (epoch_id, proposal_id) pair(s) in witness_consensus_log', v_dup_count;
    END IF;
END $$;

-- 3. Replace Non-Unique Proposal Index with Partial Unique Index
DROP INDEX IF EXISTS idx_consensus_log_proposal_id;

CREATE UNIQUE INDEX IF NOT EXISTS uq_consensus_log_proposal_id
ON witness_consensus_log (epoch_id, proposal_id)
WHERE proposal_id IS NOT NULL;

-- 4. Add Canonicalization Version Column to witness_consensus_log (C2, FCR-05)
ALTER TABLE witness_consensus_log
ADD COLUMN IF NOT EXISTS canonicalization_version SMALLINT NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_consensus_log_canon_ver') THEN
        ALTER TABLE witness_consensus_log
        ADD CONSTRAINT chk_consensus_log_canon_ver CHECK (canonicalization_version IN (1, 2));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_consensus_log_canon_ver
ON witness_consensus_log (epoch_id, canonicalization_version);

-- 5. Augment witness_raft_state with Physical Cursor & Snapshot Tracking
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

-- 6. Strict Contiguous Durability Backfill for Migration 003 Databases (FCR-07.1)
DO $$
DECLARE
    r RECORD;
    v_min_index BIGINT;
    v_max_index BIGINT;
    v_total_rows BIGINT;
    v_distinct_rows BIGINT;
    v_contiguous_max BIGINT;
BEGIN
    FOR r IN SELECT cluster_id, epoch_id, last_consecutive_persisted_index FROM witness_raft_state LOOP
        SELECT MIN(log_index), MAX(log_index), COUNT(*), COUNT(DISTINCT log_index)
        INTO v_min_index, v_max_index, v_total_rows, v_distinct_rows
        FROM witness_consensus_log
        WHERE epoch_id = r.epoch_id;

        IF v_total_rows > 0 THEN
            -- Verification 1: Must start at index 1
            IF v_min_index != 1 THEN
                RAISE EXCEPTION 'Migration 004 aborted: epoch % log_index does not start at 1 (starts at %)', r.epoch_id, v_min_index;
            END IF;

            -- Verification 2: Must contain zero duplicate log indices
            IF v_total_rows != v_distinct_rows THEN
                RAISE EXCEPTION 'Migration 004 aborted: duplicate log_index detected in epoch % (total %, distinct %)', r.epoch_id, v_total_rows, v_distinct_rows;
            END IF;

            -- Verification 3: Detect any gap in the sequence [1, v_max_index]
            SELECT COALESCE(MIN(expected_index) - 1, v_max_index)
            INTO v_contiguous_max
            FROM (
                SELECT generate_series(1, v_max_index) AS expected_index
            ) exp
            LEFT JOIN witness_consensus_log act
              ON act.epoch_id = r.epoch_id AND act.log_index = exp.expected_index
            WHERE act.log_index IS NULL;

            -- Verification 4: Assert contiguous prefix equals max index
            IF v_contiguous_max < v_max_index THEN
                RAISE EXCEPTION 'Migration 004 aborted: non-contiguous log index sequence in epoch % (contiguous prefix reaches %, max index is %). Durable prefix cannot be proven.', r.epoch_id, v_contiguous_max, v_max_index;
            END IF;

            -- Apply verified contiguous watermark
            UPDATE witness_raft_state
            SET last_consecutive_persisted_index = v_contiguous_max
            WHERE cluster_id = r.cluster_id AND epoch_id = r.epoch_id AND last_consecutive_persisted_index = 0;
        END IF;
    END LOOP;
END $$;

-- 7. Create witness_snapshots Table with Comprehensive Metadata (C4, FCR-02)
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
    PRIMARY KEY (cluster_id, epoch_id, snapshot_index),
    CONSTRAINT uq_snapshots_id UNIQUE (snapshot_id),
    CONSTRAINT chk_snapshots_index CHECK (snapshot_index >= 0),
    CONSTRAINT chk_snapshots_etcd_rev CHECK (etcd_revision >= 0),
    CONSTRAINT chk_snapshots_sub_idx CHECK (sub_index >= 0),
    CONSTRAINT chk_snapshots_format_ver CHECK (format_version >= 1),
    CONSTRAINT chk_snapshots_canon_ver CHECK (canonicalization_version IN (1, 2)),
    CONSTRAINT chk_snapshots_backend CHECK (storage_backend IN ('posix_fs', 's3', 'gcs')),
    CONSTRAINT chk_snapshots_byte_size CHECK (byte_size >= 0)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_epoch_time 
ON witness_snapshots (cluster_id, epoch_id, created_at_seconds DESC);

-- 8. Create witness_snapshot_leases Table for Race-Safe Cleanup (FCR-07.3)
CREATE TABLE IF NOT EXISTS witness_snapshot_leases (
    snapshot_id VARCHAR(64) NOT NULL,
    worker_id VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (snapshot_id)
);

CREATE INDEX IF NOT EXISTS idx_snapshot_leases_expiry
ON witness_snapshot_leases (expires_at);

-- 9. Immutability & No-Truncate Triggers on witness_snapshots
DROP TRIGGER IF EXISTS trg_witness_snapshots_immutable ON witness_snapshots;
CREATE TRIGGER trg_witness_snapshots_immutable
BEFORE UPDATE OR DELETE ON witness_snapshots
FOR EACH ROW EXECUTE FUNCTION trg_witness_consensus_log_immutable_func();

DROP TRIGGER IF EXISTS trg_witness_snapshots_no_truncate ON witness_snapshots;
CREATE TRIGGER trg_witness_snapshots_no_truncate
BEFORE TRUNCATE ON witness_snapshots
FOR EACH STATEMENT EXECUTE FUNCTION trg_witness_block_truncate_func();

COMMIT;
```

### 7.2 Rollback Migration (`004_d3_consensus_persistence.rollback.sql`)
```sql
-- Web3User Permission Lab - Milestone 13-D Phase D3: Stage 2-B.2
-- Migration 004 Rollback: Safety checks, drops snapshots table, cursors, and restores index
BEGIN TRANSACTION;

-- 1. Safety Guard: Prevent accidental rollback if active Stage 2-B.2 data exists (FCR-04)
DO $$
DECLARE
    v_snap_count INT;
    v_persisted_rev BIGINT;
BEGIN
    SELECT COUNT(*) INTO v_snap_count FROM witness_snapshots;
    SELECT COALESCE(MAX(last_applied_etcd_revision), 0) INTO v_persisted_rev FROM witness_raft_state;

    -- If override parameter is not set, block destructive rollback
    IF (v_snap_count > 0 OR v_persisted_rev > 0) AND current_setting('stage2b2.allow_destructive_rollback', true) IS DISTINCT FROM 'true' THEN
        RAISE EXCEPTION 'Migration 004 rollback aborted: active Stage 2-B.2 data detected (% snapshots, persisted_rev %). Set stage2b2.allow_destructive_rollback = true to force.', v_snap_count, v_persisted_rev;
    END IF;
END $$;

-- 2. Drop Snapshots & Leases Tables
DROP TABLE IF EXISTS witness_snapshot_leases CASCADE;
DROP TABLE IF EXISTS witness_snapshots CASCADE;

-- 3. Remove Cursor Columns from witness_raft_state
ALTER TABLE witness_raft_state
DROP COLUMN IF EXISTS last_applied_etcd_revision,
DROP COLUMN IF EXISTS last_applied_sub_index,
DROP COLUMN IF EXISTS last_consecutive_persisted_index,
DROP COLUMN IF EXISTS last_snapshot_index,
DROP COLUMN IF EXISTS last_snapshot_hash;

-- 4. Revert Proposal Index to Non-Unique (Migration 003 State)
DROP INDEX IF EXISTS uq_consensus_log_proposal_id;
CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id
ON witness_consensus_log (epoch_id, proposal_id);

-- 5. Drop Canonicalization Version Column
ALTER TABLE witness_consensus_log
DROP COLUMN IF EXISTS canonicalization_version;

COMMIT;
```

---

## 8. Dependency Graph & Implementation Order

The 7-step implementation structure is strictly preserved:

```
[ Step 1: WP4 - TTCF-v1 Canonical Serializer ]
  - Create src/witness/canonical-serializer.ts
  - Create test/witness/canonical-ttcf.test.ts
  - Verify all 7 scalar/structural types, Unicode NFC, negative zero, and domain separation
        |
        v
[ Step 2: WP1 - Retention Boundary, Watch Backpressure & Sliding Window in Pure Reducer ]
  - Update src/witness/state-machine-types.ts (retentionFloorIndex, L_c_persisted, backpressure types)
  - Update src/witness/state-machine.ts with F_ret, HISTORICAL_RECORD_PRUNED, and backpressure hooks
  - Update test/witness/state-machine.test.ts (verify 6 retention lifecycle cases and dual eviction)
        |
        v
[ Step 3: WP2 - Migration 004 Authoring & Database Schema Tests ]
  - Create src/witness/migrations/004_d3_consensus_persistence.sql (with table locks, canon version & backfill)
  - Create src/witness/migrations/004_d3_consensus_persistence.rollback.sql (with data guards)
  - Create test/witness/migration-004.test.ts (verify preflight locking, up, down, idempotency, contiguous backfill, gap abort)
        |
        v
[ Step 4: WP2 - PostgresConsensusStore Implementation, Two-Phase Publication & Tier 2 Replay ]
  - Create src/witness/consensus-store.ts (single-writer lock, two-phase publication, backpressure pause, hash-chain genesis replay)
  - Create test/witness/consensus-store.test.ts (verify two-phase publication, Tier 2 fallback & genesis recovery)
        |
        v
[ Step 5: WP3 - SnapshotManager, Multi-Backend Storage & Race-Safe Cleanup ]
  - Create src/witness/snapshot-manager.ts (POSIX 6-step, S3 PUT, GCS precondition & CRC32C, lease coordination, final check)
  - Create test/witness/snapshot-manager.test.ts (verify CI-1 to CI-8 crash cases, cleaner fencing, & corrupt blob detection)
        |
        v
[ Step 6: WP5 - Compaction Coordinator & etcd Multi-Event Revision Durability ]
  - Create src/witness/compaction-coordinator.ts (multi-event durability, calibrated buffer, watch resumption)
  - Create test/witness/compaction-readiness.test.ts (verify WB-1 to WB-7 watch boundary tests & catch-up recovery)
        |
        v
[ Step 7: Full Subsystem & Regression Verification ]
  - Run npx vitest run test/witness/
  - Run npx vitest run (full test suite)
  - Run npm run build
  - Document implementation report in docs/M13-D-STAGE-2B2-IMPLEMENTATION-REPORT.md
```

---

## 9. Comprehensive Test Matrix

Table 9.1 defines the comprehensive test suite required to validate Stage 2-B.2, including all FCR-07 boundary cases:

### Table 9.1: Comprehensive Test Matrix for Stage 2-B.2

| Test Suite File | Test Category | Target Invariant / Scenario |
| :--- | :--- | :--- |
| `canonical-ttcf.test.ts` | Unit / Spec | Verify collision freedom: `bi:100` vs `n:100` vs `"100"`. Negative zero `n:0`. Reject unsafe IEEE 754 integers ($> 2^{53}-1$). Unicode NFC normalization. Duplicate key rejection. Domain separation prefix `"TTCF-v1\n"`. |
| `state-machine.test.ts` | Unit / Invariant | Verify 6 retention lifecycle cases for $F_{ret}$. Verify emission of `HISTORICAL_RECORD_PRUNED`. Verify dual pruning of `appliedIndices` and `appliedProposals`. Verify contiguous durability gating ($L_{c\_persisted}$). |
| `migration-004.test.ts` | Database / Migration | Table locking isolation during preflight. Preflight detection of duplicate proposals (fails closed). Fresh install. **Contiguous historical backfill test.** **Non-contiguous gap detection abort test (fails closed).** **Duplicate log index abort test.** Rollback data guards. |
| `consensus-store.test.ts` | Integration / Concurrency | Single-writer row lock (`witness_raft_state FOR UPDATE`). **Two-phase publication verification (candidate state not visible before commit).** Tier 2 historical verification with v1 and v2 payload hashes. **Backpressure pause trigger at $\Delta_{lag\_max}$ and resume at low watermark.** Missing row bootstrap. Mid-publication crash recovery. **Hash-chain genesis replay test.** **Corrupt snapshot fallback to earlier valid snapshot test.** |
| `snapshot-manager.test.ts` | Storage / Durability | 6-step POSIX publication protocol with parent-directory `fsync`. S3 PUT protocol simulation with conditional `If-None-Match`. GCS generation-match simulation with CRC32C response verification. **Crash-injection suite (CI-1 through CI-8).** **Concurrent publication vs orphan cleaner sweep test.** **Delayed writer final-check fencing test.** Restore rehydration parity. |
| `compaction-readiness.test.ts` | Integration / Raft | Multi-event same-revision durability tracking ($R_{pg\_persisted}$). Dimensional buffer sizing calibration ($\Delta_{buffer}$). Compaction barrier calculation. **Stream Boundary Tests:**<br>- **WB-1:** Inclusive `start_revision` deduplication.<br>- **WB-2:** Multiple events within same revision ($K$ sub-indices).<br>- **WB-3:** Disconnect after partial sub-index processing.<br>- **WB-4:** Resume from last committed physical cursor.<br>- **WB-5:** Compaction during reconnect (`EtcdCompactedError`).<br>- **WB-6:** Snapshot-based recovery catch-up.<br>- **WB-7:** Zero event loss and zero duplicate mutations under network churn. |

---

## 10. Acceptance Criteria for Every Work Package

### Work Package 1 (Retention, Backpressure & Replay)
- [ ] $F_{ret}$ formula matches $\max(1\text{n}, \min(A_{app} - W_{mem} + 1\text{n}, L_{c\_persisted} + 1\text{n}))$.
- [ ] Entries with $L_{app} < F_{ret}$ emit `status: "HISTORICAL_RECORD_PRUNED"`.
- [ ] Pruning evicts corresponding `proposalId` from `appliedProposals` atomically.
- [ ] Pruning is strictly blocked from advancing past $L_{c\_persisted} + 1\text{n}$ (**INV-RET-01**).
- [ ] Watch consumer pauses when persistence lag $A_{app} - L_{c\_persisted} \ge \Delta_{lag\_max}$ or memory entries $\ge B_{max}$.
- [ ] Watch consumer handles disconnects during pause, reconnects with jittered backoff, and unpauses when lag drains below $\Delta_{lag\_resume}$ without missing or skipping events (**FCR-01**).
- [ ] Boundary tests WB-1 through WB-7 all pass with 100% assertion parity (**FCR-07.5**).

### Work Package 2 (PostgreSQL Persistence & Migration 004)
- [ ] Migration 004 acquires `SHARE ROW EXCLUSIVE` lock on `witness_consensus_log` before preflight check (**C3**).
- [ ] Migration 004 preflight detects duplicates and aborts cleanly.
- [ ] `uq_consensus_log_proposal_id` enforces uniqueness per epoch.
- [ ] `witness_consensus_log` tracks `canonicalization_version SMALLINT` (1 or 2) (**C2, FCR-05**).
- [ ] `witness_raft_state` tracks $A_{app}, R_{etcd}, S_{idx}, L_{c\_persisted}, S_{snap}$.
- [ ] Migration 004 computes strict contiguous prefix for existing Migration 003 rows; fails closed with exception if any gap, duplicate, or non-1 start is detected (**FCR-07.1**).
- [ ] `PostgresConsensusStore` bootstraps missing `witness_raft_state` rows before locking.
- [ ] Authoritative in-memory state is published only after database `COMMIT` succeeds (**C6, INV-AUTH-01**).
- [ ] Node recovers deterministically from committed PostgreSQL logs after a mid-publication crash (**FCR-06**).
- [ ] Node executes 5-step hash-chain verification during replay, supporting genesis recovery and fallback to earlier valid snapshots (**FCR-07.4**).
- [ ] Tier 2 query verifies `(proposal_id, payload_hash)` against matching canonical version (**INV-REP-01**).
- [ ] Rollback script blocks execution if active Stage 2-B.2 snapshots or persisted revisions exist, unless explicitly overridden (**FCR-04**).

### Work Package 3 (Snapshots)
- [ ] Snapshot metadata tracks identity, format version, canonical version, backend, digests, cursors, and sizes (**C4**).
- [ ] POSIX publication executes Temp write $\to$ File `fsync` $\to$ Atomic rename $\to$ Parent directory `fsync` $\to$ Checksum verification $\to$ DB metadata commit (**INV-SNAP-01**).
- [ ] S3 publication executes atomic single-part PUT with `If-None-Match: *` and checksum headers (**FCR-02**).
- [ ] GCS publication executes upload with `x-goog-if-generation-match: 0` precondition and validates returned CRC32C checksum header (**FCR-02, FCR-07.3**).
- [ ] Orphan cleaner acquires active leases, respects 1-hour grace period, and executes final database reference check immediately prior to deletion, never deleting in-flight artifacts (**FCR-02, FCR-07.3**).
- [ ] All crash-injection cases (CI-1 through CI-8) recover cleanly without data loss or corruption.
- [ ] Corrupt checksum throws `SnapshotCorruptionError` and falls back to prior snapshot.
- [ ] Rehydrated `ApplicationState` exactly matches pre-snapshot state.

### Work Package 4 (TTCF-v1 Canonicalization)
- [ ] BigInt, Number, and String produce mutually disjoint prefixes.
- [ ] `-0` normalizes to `n:0`.
- [ ] Unsafe integer Numbers ($> 2^{53}-1$) throw `TypeError`.
- [ ] Duplicate normalized object keys throw `TypeError`.
- [ ] Domain prefix `"TTCF-v1\n"` is embedded in digest calculation.
- [ ] Legacy v1 hashing remains functional for Stage 2-B.1 unit tests and historical log verification (**FCR-05**).

### Work Package 5 (etcd Compaction Readiness)
- [ ] $R_{pg\_persisted}$ explicitly handles multi-event revisions, excluding partially persisted revisions (**C5**).
- [ ] Compaction formula strictly uses 64-bit physical revision units: $R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$ (**INV-COMP-01**).
- [ ] $\Delta_{buffer}$ is dimensionally derived and calibrated as an evidence-based configurable parameter grounded in physical Prometheus metrics (**FCR-03, FCR-07.2**).
- [ ] Automatic compaction is disabled by default until operational telemetry calibration succeeds (**FCR-07.2**).
- [ ] Post-compaction watch resumption filters sub-indexes $S_{idx} \le S_{snap}$ and logical indices $L_{app} \le S_{app}$.

---

## 11. Security, Consistency & Failure-Mode Analysis

Table 11.1 establishes the deterministic system response to major failure modes:

### Table 11.1: Failure Mode and Security Mitigation Matrix

| Failure Mode | Subsystem Affected | Failure Detection Mechanism | System Mitigation & Recovery Action |
| :--- | :--- | :--- | :--- |
| **PostgreSQL Network Partition** | `PostgresConsensusStore` | Connection timeout / pool exhaustion. | Watch consumer halts via backpressure ($\Delta_{lag\_max}$); engine throws `ConsensusStoreUnavailableError`; retries with backoff. Zero state divergence. |
| **etcd Stream Disconnect During Pause** | `EtcdClientAdapter` | Socket close / EOF / keepalive ping timeout. | Adapter transitions to `RECONNECTING`; applies jittered backoff; queries PostgreSQL for latest cursor $(R_{last}, S_{last})$; resumes watch once unpaused. |
| **Missing Log Row during Tier 2 Replay** | Historical Replay | `witness_consensus_log` returns zero rows for $L \le A_{app}$. | Throws `UnverifiableHistoricalEntryError(L)`. Engine trips epoch quarantine; alerts operator to database corruption. Never assumes unverified entries succeeded. |
| **Crash After DB Commit Before In-Memory Publish** | State Coordinator | Node reboot / process restart. | On startup, node loads latest snapshot, replays committed entries from `witness_consensus_log` up to $L_{c\_persisted}$, and recovers exact state. Re-delivered watch events return `ALREADY_APPLIED`. |
| **Non-Contiguous Log History in Migration** | Database Migration | Migration 004 verification script. | Detects gap (`v_contiguous_max < v_max_index`), aborts transaction with `RAISE EXCEPTION`. Zero watermarks corrupted. |
| **Power Failure during Snapshot Publication** | File Storage / DB | Checkpoint boundary (Section 5.3). | Reboot inspects PostgreSQL metadata. If metadata was uncommitted, unreferenced temp/snap file is purged by orphan cleaner after grace period. If committed, blob is guaranteed durable by parent-dir `fsync`. |
| **Concurrent Migration Contention** | PostgreSQL Migration | Lock acquisition wait / timeout. | Migration acquires `SHARE ROW EXCLUSIVE` lock on `witness_consensus_log`, blocking concurrent writers and eliminating preflight race conditions. |
| **etcd Compacts Past Watch Cursor** | Stream Watch | `EtcdCompactedError` (gRPC OutOfRange). | Engine enters `CATCH_UP_RECOVERY`; fetches latest snapshot from PostgreSQL; rehydrates state; resumes watch at $R_{snap}$. |

---

## 12. Rollback & Recovery Strategy

1. **Database Rollback:**  
   If Migration 004 must be rolled back, execute `004_d3_consensus_persistence.rollback.sql`. The rollback script includes active data safeguards, preventing accidental loss of snapshot records or cursor data unless explicitly forced via configuration.
2. **Code Rollback:**  
   Because all Stage 2-B.2 additions are modularized in `consensus-store.ts`, `snapshot-manager.ts`, and `canonical-serializer.ts`, rolling back to Stage 2-B.1 involves reverting imports and retaining the pure reducer.
3. **Dual-Hashing Compatibility:**  
   `computeCanonicalPayloadHash` retains `version: 1 | 2` routing. Database column `canonicalization_version` records the version for each entry, allowing seamless coexistence of v1 and v2 entries without data corruption.

---

## 13. Technical Review Corrections Matrix & Deployment Prerequisites

### 13.1 Technical Review Corrections Traceability Matrix
Table 13.1 establishes the direct traceability from each review finding to its architectural resolution and validating test suite:

### Table 13.1: Technical Review Corrections Traceability Matrix

| Finding ID | Finding Description | Architectural Resolution | Validating Test Suite |
| :--- | :--- | :--- | :--- |
| **C1 / FCR-01** | Retention backpressure & watch disconnect lifecycle | Formally proved $W_{mem}$ bounded memory failure under lag. Defined $\Delta_{lag\_max}$, $B_{max}$, pause/resume state machine. Implemented jittered reconnect and snapshot catch-up on stream closure. Proved zero-skip / zero-duplicate semantics. | `state-machine.test.ts`<br>`consensus-store.test.ts`<br>`compaction-readiness.test.ts` |
| **C2 / FCR-05** | Canonicalization version persistence & integrity | Added `canonicalization_version SMALLINT` to `witness_consensus_log` in Migration 004. Defined dual-version verification routing. Durable version stored in log rows and snapshot manifests. | `canonical-ttcf.test.ts`<br>`migration-004.test.ts`<br>`consensus-store.test.ts` |
| **C3 / FCR-04** | Migration 004 concurrency & safety closure | Added `SHARE ROW EXCLUSIVE` and `EXCLUSIVE` table locks. Added preflight duplicate detection. Handled non-unique index replacement, cursor backfilling, missing-row bootstrap, and rollback data guards. | `migration-004.test.ts` |
| **C4 / FCR-02** | Multi-backend snapshot semantics & orphan safety | Separated POSIX 6-step rename, S3 conditional `If-None-Match`, and GCS `x-goog-if-generation-match` protocols. Added active lease tracking and 1-hour grace period for orphan cleaner. Defined CI-1 through CI-8 crash matrix. | `snapshot-manager.test.ts` |
| **C5 / FCR-03** | etcd revision durability & dimensional buffer sizing | Defined $R_{pg\_persisted}$ for multi-event revisions. Proved compaction safety theorem. Performed dimensional analysis calibrating $\Delta_{buffer} = S_f \times R_{rate} \times T_{reconnect}$ in physical revisions. Marked calibration as deployment prerequisite. | `compaction-readiness.test.ts` |
| **C6 / FCR-06** | Two-phase state publication & recovery authority | Specified that candidate state is held uncommitted in memory until PostgreSQL `COMMIT` succeeds. Reconstructed authoritative in-memory state on restart strictly from PostgreSQL snapshots and logs. | `consensus-store.test.ts` |
| **FCR-07.1** | Contiguous durability backfill & gap abort | Replaced `MAX(log_index)` with strict contiguous-prefix calculation. Detects gaps, duplicate indices, and non-1 starts, aborting migration with `RAISE EXCEPTION`. | `migration-004.test.ts` |
| **FCR-07.2** | Physical revision telemetry & conversion proof | Grounded revision rate in physical Prometheus metrics (`rate(etcd_debugging_mvcc_put_total) + rate(delete)`). Accounts for background system revisions. Disabled auto-compaction by default pending calibration. | `compaction-readiness.test.ts` |
| **FCR-07.3** | Race-safe snapshot cleaner & GCS CRC32C contract | Added active publication leases (`witness_snapshot_leases`), 1-hour grace period, and a final database check immediately prior to deletion. Formalized GCS Base64 CRC32C response assertion. | `snapshot-manager.test.ts` |
| **FCR-07.4** | Cryptographic replay chain & genesis correctness | Formalized 5-step hash-chain verification: genesis initialization, candidate snapshot validation with fallback to earlier snapshots, contiguous log query, chaining validation, and atomic state publication. | `consensus-store.test.ts` |
| **FCR-07.5** | etcd watch boundary test suite | Specified boundary tests WB-1 to WB-7 covering inclusive start revisions, multi-event revisions, mid-batch disconnects, cursor resumption, compaction recovery, and zero-loss / zero-duplicate invariants. | `compaction-readiness.test.ts` |

### 13.2 Remaining Deployment Prerequisites
1. **Compaction Buffer Sizing Calibration:** Production deployment must configure `consensus.compaction.bufferRevisions` based on measured peak physical revision telemetry (`rate(etcd_debugging_mvcc_put_total[1m]) + rate(etcd_debugging_mvcc_delete_total[1m])`) against the dimensional formula. Automatic compaction must remain disabled until this calibration is verified.
2. **Snapshot Storage IAM Credentials & Bucket Configuration:** When deploying to AWS S3 or GCS, buckets must be provisioned with versioning/Object Lock enabled, and witness service accounts must be granted `s3:PutObject` / `storage.objects.create` permissions.
3. **PostgreSQL Statement Timeout Tuning:** Production database connection pools must set appropriate statement timeouts (`statement_timeout = '10s'`) to prevent indefinite row-lock stalls during transient network partitions.

---

## 14. File Metadata & SHA-256 Manifest

| File Path | Description | SHA-256 Digest |
| :--- | :--- | :--- |
| `docs/M13-D-STAGE-2B2-IMPLEMENTATION-PLAN.md` | Authoritative Stage 2-B.2 Implementation Plan (FCR-07 Closed) | `44B93C6979E5B64E7950E9C6856C352C2F6E5EC0AF3E3D0AA4BACFEE3CAD8603` |
| `docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md` | Accepted Architectural Closure Document | `31694A4A4FE054A2ABCA399FE071E3D412E55B0044FA4A0E4E6E51C28D5F6715` |
| `src/witness/migrations/003_d3_consensus_state.sql` | Base Migration 003 Schema | `84F953051ECBCF42B104F5EBDD793C29EB0DE501F0EC09CE968C090CDCF26C03` |
| `src/witness/state-machine-types.ts` | State Machine Types Contract | `B51B425A3EE05BDB935D9B6DA86C6EF6C3ACA97D1F5ED099EDB0F8181C102363` |
| `src/witness/state-machine.ts` | State Machine Reducer | `D1B8D9DACB2E08CAF2E1CA7E5969C78FDE8DDD93830DA9DD156E013C272C4B0A` |
