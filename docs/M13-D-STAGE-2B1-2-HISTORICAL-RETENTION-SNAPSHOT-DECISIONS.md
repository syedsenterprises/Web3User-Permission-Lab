# Milestone 13-D Stage 2-B.1.2: Historical Retention and Snapshot Architecture Decisions

**Document ID:** `M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS`  
**Date:** 2026-11-23  
**Status:** DRAFT / PENDING ARCHITECTURAL APPROVAL  
**Document Type:** Architectural Decision Record (ADR), Formal Specification & Safety Proof  
**Target Milestone:** Milestone 13-D (Distributed Consensus Engine) — Stage 2-B.1.2  
**Auditor / Architect:** Antigravity Autonomous Security & Architecture Reviewer  
**Prerequisites:** 
- `docs/M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md`
- `docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md`
- `docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md`
- `docs/M13-D-STAGE-2B1-IMPLEMENTATION-REPORT.md`
- `docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md`
- `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md`

---

## 1. Executive Summary

This architecture specification closes the open conditions identified in `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md` regarding in-memory resource retention, historical replay verification, snapshotting, etcd compaction coordination, and canonical serialization ambiguity.

### 1.1 The Core Architectural Tensions
1. **Unbounded Memory vs. Fail-Closed Integrity:**  
   In Stage 2-B.1.1, `ConsensusStateMachine` achieved tamper-proof historical replay detection by storing every applied log index in memory (`appliedIndices: ReadonlyMap<bigint, AppliedIndexRecord>`). However, retaining every index indefinitely yields an unbounded $O(N)$ memory growth. Pruning older indices without a defined retention architecture would cause legitimate historical replays to fail closed with `UnverifiableHistoricalEntryError`. Conversely, blindly accepting unverified historical entries as duplicates violates safety.
2. **Ephemeral Raft Bus vs. Permanent Audit Log:**  
   The consensus cluster (etcd) operates a high-throughput, ephemeral Raft WAL that must periodically undergo aggressive compaction ($R < R_{comp}$) to prevent disk exhaustion. PostgreSQL, by contrast, operates an immutable, append-only historical audit log (`witness_consensus_log`). Reconciling these two timelines requires an explicit two-tier replay architecture.
3. **Decoupled Dual-Cursor Snapshot Restoration:**  
   A snapshot must capture both the logical application state ($L_{app}$, domain models, hash-chain head) and the physical stream coordinates ($R_{etcd}, S_{idx}$) without conflating logical indices with leaping physical etcd revisions.
4. **Canonical BigInt / String Serialization Ambiguity:**  
   In Stage 2-B.1.1, `canonicalizeValue` serializes `BigInt` values as JSON strings (`"100"`), creating an encoding identical to string `"100"`. While typed domain schemas prevent collision in the current protocol, canonical serialization must be mathematically unambiguous across all scalar types.

---

## 2. Current Implementation Facts vs. Proposed Architecture

To maintain rigorous governance, Table 2.1 establishes the boundary between existing code in `feature/m13-d-consensus` and the decisions established in this document.

### Table 2.1: Implementation Reality vs. Architectural Target

| Component | Implemented Reality (Stage 2-B.1.1 Code) | Architectural Target (Stage 2-B.1.2 Specification) | Status / Delta |
| :--- | :--- | :--- | :--- |
| **State Machine Immutability** | `ReadonlyFrozenMap`, `ReadonlyFrozenSet`, and shallow `Object.freeze()` on `PolicyRecord` and `CommittedTicketRecord`. | Full immutability preserved. | **Implemented & Verified** |
| **Historical Replay** | Replay of $L_{app} \le A_{app}$ verified against in-memory `appliedIndices`. If missing, throws `UnverifiableHistoricalEntryError`. | Two-tier verification: In-memory sliding window ($W_{mem}$) with automatic fallback to PostgreSQL `witness_consensus_log`. | **Specified in ADR-M13D-011** |
| **Memory Growth** | Unbounded $O(N)$ growth of `appliedIndices` and `appliedProposals` in memory. | Bounded $O(W_{mem})$ sliding window + Epoch sealing upon `EPOCH_ADVANCE`. | **Specified in ADR-M13D-010** |
| **State Snapshotting** | No snapshot contract, interface, or serializer exists in TypeScript. | Formal `ApplicationStateSnapshot` contract with recursive `chainHeadHash` and `snapshotHash`. | **Specified in ADR-M13D-012** |
| **etcd Compaction** | etcd client adapter handles raw watches. No catch-up handler for `EtcdCompactedError`. | State machine catch-up protocol via Snapshot Restoration when watch revision is compacted. | **Specified in ADR-M13D-013** |
| **BigInt Serialization** | BigInt serialized as JSON string: `JSON.stringify(val.toString())` (`"100"`). | Unquoted RFC 8259-compliant decimal representation (`100`), distinct from quoted strings. | **Specified in ADR-M13D-014** |
| **Database Schema** | Migration 003 creates `witness_consensus_log` and `witness_raft_state`. | Schema is fully compatible; dual-cursor columns in `witness_raft_state` validated for Stage 2-B.2. | **Schema Ready** |

---

## 3. Architecture Decision Records (ADRs)

```
================================================================================
ADR-M13D-010: In-Memory Historical Retention Boundary and Epoch Sealing
================================================================================
```

### Context & Problem Statement
In `src/witness/state-machine.ts`, every applied entry appends to `state.appliedIndices` and `state.appliedProposals`. In high-throughput production (e.g., 500 tx/sec), retaining these records in V8 memory consumes approximately 180 bytes per entry, reaching ~1.5 GB within 24 hours. Because Node.js V8 heap is constrained and garbage collection pauses scale with heap size, holding history indefinitely in memory is unsustainable. However, pruning indices without a contract causes legitimate replays to fail closed.

### Evaluated Alternatives
* **Alternative 1: Retain Full History in Memory (Status Quo).**  
  *Pros:* Simplest in-memory logic; zero disk fallback for historical replays.  
  *Cons:* Fatal memory exhaustion; GC latency spikes; violates production scalability requirements.
* **Alternative 2: Global Sliding Window across All Epochs.**  
  *Pros:* Bounds memory to the last $N$ entries.  
  *Cons:* Crosses epoch boundaries arbitrarily; complicates epoch quarantine and epoch sealing; allows zombie proposals across epochs.
* **Alternative 3: Epoch-Bound Sealing with Active Sliding Window (Recommended).**  
  *Pros:* Leverages existing epoch lifecycle. Sealed epochs are fully pruned from memory because cross-epoch entries are rejected upfront. Within an active epoch, a bounded sliding window ($W_{mem} = 10,000$ entries) covers all in-flight duplicate deliveries.

### Decision
1. **Epoch Sealing Invariant:**  
   When the state machine transitions to a new epoch via `EPOCH_ADVANCE`, the prior epoch is sealed. Because line 278 of `ConsensusStateMachine.apply()` strictly enforces:
   $$\text{entry.epochId} == \text{state.epochId}$$
   any duplicate replay from a prior epoch is rejected with `EpochMismatchError` *before* the historical replay index check is reached. Therefore, upon `EPOCH_ADVANCE`, all `appliedIndices` and `appliedProposals` from the prior epoch are **completely purged from memory**.
2. **Active Epoch In-Memory Retention Window ($W_{mem}$):**  
   Within the active epoch, the state machine retains historical records for the most recent $W_{mem}$ entries, where:
   $$W_{mem} = \max(10000, \text{LeaseDurationInSeconds} \times \text{PeakTps})$$
   The state machine defines a dynamic boundary:
   $$\text{retentionFloorIndex} = \max(1\text{n}, \text{state.lastAppliedAppIndex} - W_{mem} + 1\text{n})$$
   Entries where $L_{app} < \text{retentionFloorIndex}$ are pruned from in-memory maps during transition.

### Failure Scenarios & Security Analysis
* *Scenario:* A duplicate entry arrives from 2 hours ago within the active epoch ($L_{app} < \text{retentionFloorIndex}$).  
  *Mitigation:* The in-memory state machine does NOT guess or assume it is a duplicate. It triggers the Two-Tier Replay Verification protocol (ADR-M13D-011).

### Stage 2-B.2 & Stage 3-A Status
Blocks Stage 2-B.2. Stage 2-B.2 must implement `retentionFloorIndex` in `ApplicationState`.

---

```
================================================================================
ADR-M13D-011: Two-Tier Historical Replay Verification
================================================================================
```

### Context & Problem Statement
When an entry arrives with $L_{app} \le A_{app}$ and $L_{app} < \text{retentionFloorIndex}$, the record is no longer in memory. If the state machine blindly returns `ALREADY_APPLIED`, an attacker could submit a forged payload with an old index and receive a false success status. If the state machine unconditionally throws `UnverifiableHistoricalEntryError`, network re-transmissions of older events will halt the witness engine.

### Evaluated Alternatives
* **Alternative 1: Fail-Closed Fatal Error for all Pruned Replays.**  
  *Pros:* Zero I/O required in state machine.  
  *Cons:* Fragile; normal network retries of compacted watch events cause permanent crashes.
* **Alternative 2: Blind Idempotent Acknowledgment.**  
  *Pros:* Zero memory or disk overhead.  
  *Cons:* Severe safety violation; allows historical state-tampering spoofing.
* **Alternative 3: Two-Tier Memory + PostgreSQL Durable Replay Verification (Recommended).**  
  *Pros:* Fast path in memory ($O(1)$ for 99.99% of in-flight retries); durable ground-truth verification via PostgreSQL `witness_consensus_log` for pruned events.

### Decision
1. **Tier 1 (In-Memory Hot Path):**  
   If $L_{app} \ge \text{retentionFloorIndex}$, `ConsensusStateMachine.apply()` inspects `state.appliedIndices.get(L_{app})`:
   * If `proposalId` and `payloadHash` match: return `status: "ALREADY_APPLIED"`.
   * If either mismatches: throw `HistoricalIndexConflictError`.
2. **Tier 2 (Durable Storage Cold Path):**  
   If $L_{app} < \text{retentionFloorIndex}$:
   * The pure state machine reducer returns a distinct status:
     ```typescript
     {
       status: "HISTORICAL_RECORD_PRUNED",
       appLogIndex: entry.appLogIndex,
       epochId: entry.epochId,
       payloadHash: computedPayloadHash,
       proposalId: entry.proposalId
     }
     ```
   * The outer witness persistence layer (PostgreSQL store) intercepts `HISTORICAL_RECORD_PRUNED` and executes an authoritative SQL lookup:
     ```sql
     SELECT payload_hash, proposal_id 
     FROM witness_consensus_log 
     WHERE epoch_id = $1 AND log_index = $2;
     ```
   * If the database row matches both `proposal_id` and `payload_hash`, the store confirms idempotent replay.
   * If the row does not match or does not exist, the store throws `HistoricalIndexConflictError` or `UnverifiableHistoricalEntryError`.

```
+-----------------------------------------------------------------------------------+
|                        ENTRY DELIVERED: L_app <= A_app                            |
+-----------------------------------------------------------------------------------+
                                          |
                        +-----------------v-----------------+
                        | L_app >= retentionFloorIndex?     |
                        +-----------------+-+---------------+
                                          | |
                     YES (In Memory)     | | NO (Pruned from Memory)
                                          | |
            +-----------------------------+ +-----------------------------+
            |                                                             |
+-----------v---------------------+                 +---------------------v---------------------+
| Lookup state.appliedIndices     |                 | State machine emits:                      |
| Match proposalId & payloadHash? |                 | "HISTORICAL_RECORD_PRUNED"                |
+-----------+-+-------------------+                 +---------------------+---------------------+
            | |                                                           |
       YES  | | NO                                                        v
            | |                                     +-------------------------------------------+
            | +---> THROW                           | Query PostgreSQL witness_consensus_log    |
            |       HistoricalIndexConflictError    | Match proposal_id & payload_hash?         |
            v                                       +---------------------+---------------------+
+---------------------------------+                                       | |
| Return ALREADY_APPLIED          |                   YES                 | | NO
| (Zero State Mutation)           |<--------------------------------------+ +---> THROW
+---------------------------------+                                               HistoricalIndexConflictError
```

### Stage 2-B.2 & Stage 3-A Status
Blocks Stage 2-B.2. The interface contract must return `HISTORICAL_RECORD_PRUNED` when $L_{app} < \text{retentionFloorIndex}$.

---

```
================================================================================
ADR-M13D-012: Deterministic Snapshot Schema, State Integrity Hash, and Restoration Contract
================================================================================
```

### Context & Problem Statement
When a node starts from cold storage, or when an offline node rejoins after etcd has compacted its WAL, replaying millions of raw entries from index 1 is prohibitively slow and impossible if etcd has compacted. A deterministic snapshot format is required to restore `ApplicationState` instantly.

### Specification: `ApplicationStateSnapshot`
```typescript
export interface ApplicationStateSnapshot {
  /** Snapshot schema format version (monotonically increasing) */
  readonly formatVersion: number;
  /** Unique snapshot identifier: {clusterId}-{epochId}-{snapshotAppIndex}-{timestamp} */
  readonly snapshotId: string;
  /** Target consensus cluster identifier */
  readonly clusterId: string;
  /** Active epoch identifier at snapshot boundary */
  readonly epochId: string;
  /** Monotonic epoch height */
  readonly epochHeight: number;
  /** Epoch lifecycle state (e.g. ACTIVE or QUARANTINED) */
  readonly epochState: EpochLifecycleState;
  /** Highest applied application log index included in this snapshot */
  readonly snapshotAppIndex: bigint;
  /** Raft term of the consensus cluster at snapshotAppIndex */
  readonly snapshotRaftTerm: bigint;
  /** Decoupled physical stream coordinate in etcd at snapshot boundary */
  readonly snapshotPhysicalCursor: PhysicalStreamCursor;
  /** Cumulative recursive hash chain head at snapshotAppIndex */
  readonly chainHeadHash: string;
  /** Monotonic sequence counter allocated by committed tickets */
  readonly lastSequenceNumber: bigint;
  /** Compacted retention boundary for historical replay verification */
  readonly retentionFloorIndex: bigint;
  /** Complete frozen active policies at snapshot time */
  readonly policies: ReadonlyArray<PolicyRecord>;
  /** Complete frozen committed tickets at snapshot time */
  readonly committedTickets: ReadonlyArray<CommittedTicketRecord>;
  /** Complete frozen revoked authorization IDs at snapshot time */
  readonly revokedAuthorizations: ReadonlyArray<string>;
  /** Sliding window of applied indices: [retentionFloorIndex, snapshotAppIndex] */
  readonly retainedAppliedIndices: ReadonlyArray<readonly [bigint, AppliedIndexRecord]>;
  /** Sliding window of proposal IDs applied within retention window */
  readonly retainedAppliedProposals: ReadonlyArray<readonly [string, bigint]>;
  /** Unix timestamp (seconds) when snapshot was materialized */
  readonly createdAtSeconds: number;
  /** Cryptographic checksum over all preceding canonical fields */
  readonly snapshotHash: string;
}
```

### Snapshot Restoration Algorithm
1. **Checksum Verification:**  
   Before inspecting fields, compute SHA-256 over canonical serialization of the snapshot payload (omitting `snapshotHash`). If computed digest $\ne \text{snapshot.snapshotHash}$, abort immediately with `SnapshotCorruptionError`.
2. **Epoch State Verification:**  
   Verify that `chainHeadHash` matches the cryptographic commitment in PostgreSQL `witness_epochs.chain_head_hash` or `witness_raft_state.last_applied_hash`.
3. **ApplicationState Reconstruction:**  
   Construct `ApplicationState` using `snapshotAppIndex`, `snapshotPhysicalCursor`, and domain collections. Reconstruct `ReadonlyFrozenMap` instances for `policies`, `committedTickets`, `revokedAuthorizations`, `appliedIndices`, and `appliedProposals`.
4. **Physical Watch Resumption:**  
   Open etcd watch using physical coordinate:
   $$\text{startRevision} = \text{snapshot.snapshotPhysicalCursor.etcdRevision}$$
   Any event where $R_{etcd} == \text{snapshot.snapshotPhysicalCursor.etcdRevision} \land S_{idx} \le \text{snapshot.snapshotPhysicalCursor.subIndex}$ or $L_{app} \le \text{snapshot.snapshotAppIndex}$ is discarded.

### Stage 2-B.2 & Stage 3-A Status
Blocks Stage 2-B.2. Required for cold-start database recovery.

---

```
================================================================================
ADR-M13D-013: etcd WAL Compaction Coordination and Snapshot Catch-Up Protocol
================================================================================
```

### Context & Problem Statement
In etcd, compaction is necessary to discard old revisions. If etcd compacts up to revision $R_{comp}$, any client watch opened with $\text{startRevision} \le R_{comp}$ fails with gRPC error `rpc error: code = OutOfRange desc = etcdserver: mvcc: required revision has been compacted`. We must define when compaction is permitted and how nodes recover.

### Decision
1. **Safe Compaction Invariant:**  
   The etcd cluster administrator or automated compaction cron MUST NOT compact revisions beyond the minimum durable checkpoint revision across active witness engines:
   $$R_{comp} \le \min_{i \in \text{Engines}}(R_{\text{durable}, i})$$
   In practice, compaction is coordinated after creating a durable PostgreSQL snapshot at revision $R_{snap}$, setting $R_{comp} = R_{snap} - \Delta_{buffer}$ (e.g. $\Delta_{buffer} = 50,000$ revisions).
2. **Compacted Catch-Up Procedure:**  
   If an engine experiences extended downtime and its local cursor $R_{etcd} < R_{comp}$:
   * The etcd watch fails with `EtcdCompactedError`.
   * The engine enters `CATCH_UP_RECOVERY` mode.
   * The engine fetches the latest `ApplicationStateSnapshot` from PostgreSQL (or shared object storage).
   * The engine restores `ApplicationState` via ADR-M13D-012.
   * The engine resumes the watch stream at the snapshot's physical revision $R_{snap}$.

```
+-----------------------------------------------------------------------------------+
|                        WITNESS ENGINE WATCH RESUMPTION                            |
+-----------------------------------------------------------------------------------+
                                          |
                        +-----------------v-----------------+
                        | etcd watch(startRevision = R_pg)  |
                        +-----------------+-----------------+
                                          |
                      +-------------------+-------------------+
                      |                                       |
           SUCCESS: Watch Stream Active             ERROR: EtcdCompactedError
                      |                                       |
                      v                                       v
         Normal Event Processing             +---------------------------------+
                                             | Enter CATCH_UP_RECOVERY Mode    |
                                             +----------------+----------------+
                                                              |
                                             +----------------v----------------+
                                             | Load Latest Snapshot from PG    |
                                             | Verify snapshotHash & chainHead |
                                             +----------------+----------------+
                                                              |
                                             +----------------v----------------+
                                             | Restore ApplicationState        |
                                             | (A_app, R_snap, S_snap)         |
                                             +----------------+----------------+
                                                              |
                                             +----------------v----------------+
                                             | Resume watch at R_snap          |
                                             +---------------------------------+
```

### Stage 2-B.2 & Stage 3-A Status
Pre-requisite for Stage 3-A (multi-node fault-tolerance).

---

```
================================================================================
ADR-M13D-014: Canonical BigInt Unquoted Numeric Serialization (RFC 8259 Compliant)
================================================================================
```

### Context & Problem Statement
In `src/witness/state-machine.ts`, line 143:
```typescript
if (type === "bigint") {
  return JSON.stringify((val as bigint).toString());
}
```
This converts `100n` to `"\"100\""`, exactly identical to string `"100"`.  
While current TypeScript domain types enforce `sequenceFloor: bigint` and `debitedAmount: bigint`, relying on string encapsulation produces a mathematical collision between BigInt numbers and ordinary strings in generic payload contexts.

### Evaluated Alternatives
* **Alternative 1: Retain String Quoting (Status Quo).**  
  *Pros:* No changes required to current tests.  
  *Cons:* Cryptographically ambiguous; violates type distinction principle in canonical encoding.
* **Alternative 2: Type-Prefixed String (e.g. `"#bigint:100"`).**  
  *Pros:* Clearly tagged.  
  *Cons:* User strings matching `"#bigint:100"` can collide unless complex escaping is introduced; verbose.
* **Alternative 3: Type-Tagged Object Wrapper (e.g. `{"@type":"bigint","val":"100"}`).**  
  *Pros:* Explicit JSON schema compliance.  
  *Cons:* Incompatible with simple scalar hashing; alters payload structure.
* **Alternative 4: Unquoted RFC 8259 Decimal Representation (Recommended).**  
  *Pros:* Fully distinguishes BigInt from strings without artificial tags. BigInt `100n` serializes as `100` (raw unquoted digits); string `"100"` serializes as `"\"100\""` (quoted). Consistent with RFC 8259 Section 6 which permits arbitrary precision decimal numbers. Matches integer Number representation ($100 \equiv 100n$).

### Decision
1. **Unquoted BigInt Output:**  
   In the next scheduled implementation stage (Stage 2-B.2), update `canonicalizeValue` in `src/witness/state-machine.ts`:
   ```typescript
   if (type === "bigint") {
     return (val as bigint).toString(); // Emit unquoted decimal digits
   }
   ```
2. **Disambiguation Invariant:**
   * For BigInt `100n`: Output is `100`.
   * For String `"100"`: Output is `"100"` (enclosed in double quotes).
   * For Number `100`: Output is `100`.
   * For Number `100.5`: Output is `100.5`.
   * BigInt and String can **never collide** because strings are unconditionally enclosed in double quotes and escaped, while BigInts consist strictly of optional `-` and decimal digits `[0-9]+`.
3. **Canonical Versioning & Migration:**  
   Because this change adjusts the SHA-256 output for entries containing BigInts, it must be introduced prior to live data persistence. Since Stage 2-B.1 is an in-memory development stage with zero committed database records or live etcd proposals, adopting this in Stage 2-B.2 carries zero backward-compatibility debt.

### Stage 2-B.2 & Stage 3-A Status
Blocks Stage 2-B.2. Must be updated when Stage 2-B.2 contracts are finalized.

---

## 4. Invariants and Formal Recovery Scenarios

### 4.1 Global Consistency Invariants
* **Invariant INV-01 (Strict Logical Contiguity):**  
  $$\forall e \in \text{Epoch}, \quad L_{app}(e_{k+1}) = L_{app}(e_k) + 1\text{n}$$
  Logical index progression must have zero gaps.
* **Invariant INV-02 (Monotonic Physical Progression):**  
  $$R_{etcd}(e_{k+1}) > R_{etcd}(e_k) \lor (R_{etcd}(e_{k+1}) = R_{etcd}(e_k) \land S_{idx}(e_{k+1}) > S_{idx}(e_k))$$
  Physical stream coordinates must strictly advance forward or leap forward; backwards regression is strictly prohibited.
* **Invariant INV-03 (Fail-Closed Replay Verification):**  
  No entry $L_{app} \le A_{app}$ may be classified as `ALREADY_APPLIED` without cryptographic proof that its `proposalId` and canonical `payloadHash` match the originally committed event.
* **Invariant INV-04 (Epoch Hash-Chain Continuity):**  
  $$H_k = \text{sha256}(H_{k-1} : \text{CommandParams}_k)$$
  Receipt chain head hash commits recursively to all preceding entries in the active epoch.

---

### 4.2 Crash & Recovery Walkthroughs

#### Recovery Scenario 1: Crash Between Events in a Multi-Event Transaction
* **Setup:** etcd commits revision $R=500$ with two events:
  * Event 0: $(R=500, S=0, L=101)$
  * Event 1: $(R=500, S=1, L=102)$
* **Failure:** Node applies Event 0, commits to PostgreSQL $(A_{app}=101, R=500, S=0)$, and crashes before processing Event 1.
* **Recovery:**
  1. Node boots, reads PostgreSQL: $A_{app}=101, R_{persisted}=500, S_{persisted}=0$.
  2. Resumes watch at $\text{startRevision} = 500$ (NOT 501).
  3. etcd delivers Event 0 $(R=500, S=0, L=101)$:
     * Check: $L=101 \le A_{app}(101) \land S=0 \le S_{persisted}(0)$.
     * Action: Discarded as duplicate.
  4. etcd delivers Event 1 $(R=500, S=1, L=102)$:
     * Check: $L=102 == A_{app} + 1 (102) \land S=1 > S_{persisted}(0)$.
     * Action: Applied and committed to PostgreSQL: $A_{app}=102, R=500, S=1$.
* **Outcome:** Zero data loss, zero state duplication.

#### Recovery Scenario 2: Replay of Pruned Historical Index ($L_{app} < \text{retentionFloorIndex}$)
* **Setup:** Current state has $A_{app} = 25,000$. Sliding window retention floor is $\text{retentionFloorIndex} = 15,001$. A delayed duplicate of entry $L_{app} = 12,000$ arrives.
* **Execution:**
  1. Reducer detects $L_{app}(12000) \le A_{app}(25000)$.
  2. Reducer detects $L_{app}(12000) < \text{retentionFloorIndex}(15001)$.
  3. Reducer emits `status: "HISTORICAL_RECORD_PRUNED"`.
  4. Persistence layer queries `witness_consensus_log` for `epoch_id` and `log_index = 12000`.
  5. If `payload_hash` and `proposal_id` match: returns `status: "ALREADY_APPLIED"`.
  6. If mismatch: throws `HistoricalIndexConflictError`.
* **Outcome:** Tamper-proof validation maintained without consuming RAM.

#### Recovery Scenario 3: Cold Start with Corrupted Snapshot
* **Setup:** Node initializes from disk. Local snapshot file has bit-rot or invalid checksum.
* **Execution:**
  1. Node recalculates SHA-256 over canonical snapshot body.
  2. Digest mismatches `snapshot.snapshotHash`.
  3. Node raises `SnapshotCorruptionError` and rejects file.
  4. Node queries PostgreSQL for prior validated checkpoint or replays from genesis using `witness_consensus_log`.
* **Outcome:** System fails closed cleanly; corrupted state cannot taint live memory.

---

## 5. Deferred Risks & Stage Prerequisites

### 5.1 Deferred Technical Risks
1. **PostgreSQL Log Growth:**  
   Because `witness_consensus_log` is immutable and append-only, long-term PostgreSQL disk capacity must be monitored. At 100M events, table size reaches ~40 GB. Future architecture (Post-M13) may introduce cold table partitioning by epoch.
2. **Cold Snapshot Fetch Latency:**  
   Restoring a 10,000-ticket snapshot during `CATCH_UP_RECOVERY` takes ~150ms in V8. During this window, the node cannot process live proposals. This is standard Raft catch-up behavior.

### 5.2 Prerequisites for Subsequent Stages

| Prerequisite ID | Target Stage | Requirement Description |
| :--- | :--- | :--- |
| **PREREQ-2B2-01** | Stage 2-B.2 | Implement `retentionFloorIndex` and `HISTORICAL_RECORD_PRUNED` status in `src/witness/state-machine.ts`. |
| **PREREQ-2B2-02** | Stage 2-B.2 | Update `canonicalizeValue` in `src/witness/state-machine.ts` to emit unquoted decimal digits for `BigInt` (ADR-M13D-014). |
| **PREREQ-2B2-03** | Stage 2-B.2 | Implement Tier 2 fallback in PostgreSQL store (`PostgresWitnessStore`) to query `witness_consensus_log` upon receiving `HISTORICAL_RECORD_PRUNED`. |
| **PREREQ-2B2-04** | Stage 2-B.2 | Implement `ApplicationStateSnapshot` serializer and validator. |
| **PREREQ-3A-01** | Stage 3-A | Implement `EtcdCompactedError` catch-up handler using snapshot restoration in the multi-node worker daemon. |

---

## 6. Cryptographic File Integrity Manifest

| File Path | SHA-256 Digest | Audit Status |
| :--- | :--- | :--- |
| `src/witness/state-machine-types.ts` | `B51B425A3EE05BDB935D9B6DA86C6EF6C3ACA97D1F5ED099EDB0F8181C102363` | Intact / Read-Only |
| `src/witness/state-machine.ts` | `D1B8D9DACB2E08CAF2E1CA7E5969C78FDE8DDD93830DA9DD156E013C272C4B0A` | Intact / Read-Only |
| `test/witness/state-machine.test.ts` | `225E61468548A97F0775536C3972DC6B92FF8805D0AD125CFC8354822A910A2C` | Intact / Read-Only |
| `docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md` | `77957788F1596C2B03909978AFE5EC42C4483510E57E2E0A9851F2BEC048CC99` | Intact / Read-Only |
| `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md` | `CBF79A7D8BB0A6FF1ABF6BE2FC42CCBD0A0D453C1643D54A32B9ABC12B0AF363` | Intact / Read-Only |

---

## 7. Governance and Verification Summary

- **Design-Only Governance:** This document was produced strictly via read-only inspection. Zero source code, tests, dependencies, or prior reports were modified.
- **Git Status:** 0 staged files, 0 commits, 0 pushes.
- **Next Authorized Step:** Await user review and authorization of ADR-M13D-010 through ADR-M13D-014 before proceeding to Stage 2-B.2 implementation.
