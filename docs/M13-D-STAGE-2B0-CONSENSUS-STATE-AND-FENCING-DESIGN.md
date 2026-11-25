# Milestone 13-D Stage 2-B0: Consensus Application State & Fencing Design

**Document ID:** `M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN`  
**Date:** 2026-11-23  
**Status:** DRAFT / PENDING ARCHITECTURAL APPROVAL  
**Document Type:** Architectural Design Specification & Decision Record (DDR)  
**Target Milestone:** Milestone 13-D (Distributed Consensus Engine) — Stage 2-B (State Machine & Fencing)  
**Assessor / Architect:** Antigravity Autonomous Security & Architecture Reviewer  

---

## 1. Executive Summary

This specification establishes the authoritative architectural design for the **Application State-Machine Layer**, **Persistence Recovery**, and **Hardware/Cloud KMS Fencing** for Milestone 13-D Stage 2-B in the Web3User Permission Lab repository.

This design incorporates the empirical findings of the Phase D3 Readiness Assessment (`M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT.md`) and resolves the safety and architectural critiques sustained in the Independent Architecture Challenge (`M13-D-PHASE-D3-ARCHITECTURE-CHALLENGE.md`).

### 1.1 Core Principles & Invariants
1. **Strict Consensus Demarcation:** The core distributed consensus engine is strictly delegated to an **external canonical etcd v3.5 cluster**. Web3User's TypeScript application tier is strictly an **Application State-Machine Apply Layer** (`apply(state, command) -> state'`). It **does not** implement another Raft consensus engine, election loop, or peer-to-peer voting protocol.
2. **Dual-Cursor Ordering Model:** Because etcd `mod_revision` is a non-contiguous global keyspace counter that can produce identical revisions across multi-key transactions, the application decouples **physical stream resumption** `(etcd_revision, event_index)` from **logical application log ordering** (`app_log_index`).
3. **Downstream Idempotent Projection:** PostgreSQL 16 is a downstream projection and audit replica, not a consensus participant. Consistency between etcd and PostgreSQL is maintained via an idempotent, at-least-once event-driven consumer model, eliminating the operational fragility of distributed Two-Phase Commit (2PC).
4. **Defense-in-Depth KMS Fencing:** Stale-leader signing cannot be prevented by cloud KMS IAM policies alone because cloud KMS APIs are stateless. Fencing is achieved through a dual mechanism: an **active pre-sign linearizable lease barrier** to prevent the call, and **cryptographic term/index binding in Receipt Preimage v2** so that any rogue signature produced by a stale leader is rejected by all online verifiers.

---

## 2. Existing Architecture & Codebase Baseline

### 2.1 Implemented & Accepted Foundations
* **PostgreSQL Migration 003 (`src/witness/migrations/003_d3_consensus_state.sql`):** Creates relational tables:
  * `witness_consensus_log`: Append-only historical event log with immutable triggers blocking `UPDATE`, `DELETE`, and `TRUNCATE`.
  * `witness_raft_state`: Records `(cluster_id, epoch_id, last_applied_index, last_applied_term, last_applied_hash)`.
  * Fully verified across 12 regression tests in `test/witness/migration-003.test.ts`.
* **Single-Node etcd Client Adapter (`src/witness/etcd-client-adapter.ts`):** 872 lines of hardened TypeScript providing:
  * Native `bigint` parsing for 64-bit integer revisions (`toPositiveBigInt`).
  * Enforced linearizable reads (`serializable: false`).
  * Compare-And-Swap (CAS) transaction builder (`txn()`).
  * Watch streams with automatic reconnection and revision resumption (`watch()`).
  * Fail-closed ambiguous transaction recovery (`recoverAmbiguousTxn()`).
  * Verified across 26 real-etcd integration tests against `etcd-v3.5.18-windows-amd64` (`docs/m13-d-stage2a2-acceptance-record.md`).
* **Cloud KMS Signer (`src/witness/cloud-kms-signer.ts`):** Implements AWS KMS and GCP Cloud KMS signing with Castagnoli CRC32C integrity checking and ASN.1 DER decoding.

### 2.2 Existing Architectural Gaps & Vulnerabilities
1. **Hardcoded Fencing Generation:** In `src/witness/grpc-service.ts` line 494, `const fencingGen = 1;` is hardcoded. `signReceipt()` is called with this static constant, providing zero runtime fencing against term changes or lease expirations.
2. **Missing State-Machine Layer:** There is currently no TypeScript module in `src/witness/` that bridges etcd watch events to state mutations. Neither `postgres-store.ts` nor `grpc-service.ts` references `witness_consensus_log` or `witness_raft_state`.
3. **Dual-Store Divergence Hazard:** `grpc-service.ts` operates entirely against PostgreSQL, without synchronizing state changes through etcd transactions.
4. **Stateless KMS Signing:** In `cloud-kms-signer.ts`, `signReceipt()` directly invokes `doSignReceipt()`, sending preimages to cloud APIs without verifying etcd leader lease freshness.

---

## 3. Authoritative Ordering Model

### 3.1 Analysis of etcd Revision Semantics
An investigation of etcd v3 revision behavior reveals three fundamental characteristics that prevent using raw `mod_revision` directly as an application log index:

1. **Global Monotonicity, Local Gaps:** `mod_revision` increments globally across the entire etcd keyspace on every write. If a client watches the prefix `/web3user/consensus/log/`, and an unrelated key (e.g., `/web3user/leases/` or a cluster maintenance key) is written, `mod_revision` advances. The sequence of revisions observed under the watched prefix will contain gaps (e.g., $1001, 1004, 1005, 1012$). An application state machine that expects strict contiguous progression ($i, i+1, i+2$) will falsely detect missing log entries.
2. **Multi-Event Collisions:** When an etcd atomic transaction (`Txn`) executes multiple `Put` operations, **every key-value pair written within that transaction shares the exact same `mod_revision`**. If an application attempts to key its state machine strictly by `mod_revision`, duplicate key collisions occur within a single transaction.
3. **Cluster-Scope vs. Epoch-Scope:** Revisions continue to advance across epoch transitions and cluster resets, whereas application business logic requires per-epoch sequential sequence numbers.

### 3.2 Dual-Cursor Ordering Specification
To achieve deterministic, gap-free, reproducible ordering across restarts and retranslations, Web3User adopts a **Dual-Cursor Ordering Model**:

```
+---------------------------------------------------------------------------------------+
| 1. PHYSICAL STREAM CURSOR (Wire-Level Resumption)                                     |
|    Tuple: (etcd_revision: bigint, event_sub_index: number)                            |
|    - Used exclusively by EtcdClientAdapter to resume watches from etcd.               |
|    - Resumption: client.watch({ startRevision: lastSeenEtcdRevision + 1n })          |
+---------------------------------------------------------------------------------------+
                                           |
                               Mapped 1-to-1 in Event
                                           v
+---------------------------------------------------------------------------------------+
| 2. LOGICAL APPLICATION LOG INDEX (State-Machine Ordering)                             |
|    Field: app_log_index: bigint (strictly contiguous: 1, 2, 3, ...)                   |
|    - Embedded inside the canonical command payload proposed to etcd via CAS.          |
|    - Governed by atomic CAS advance on /web3user/consensus/{epoch_id}/last_index.     |
|    - Used by StateMachine.apply() to guarantee strict sequential execution.           |
+---------------------------------------------------------------------------------------+
```

### 3.3 Atomic Logical Index Allocation Protocol
When an application leader proposes a command to the consensus log, it executes an atomic etcd CAS transaction:

```
PROPOSAL TRANSACTION:
  key_current_index = "/web3user/consensus/" + epoch_id + "/last_index"
  key_log_entry     = "/web3user/consensus/" + epoch_id + "/log/" + (expected_index + 1)

  IF (
    value(key_current_index) == expected_index
  ) THEN (
    put(key_current_index, expected_index + 1)
    put(key_log_entry, canonical_json_payload)
  ) ELSE (
    // Transaction rejected: concurrent proposal committed. Retry with updated index.
  )
```

*Guarantee:* Because etcd executes the transaction atomically through Raft, exactly one node can allocate index $N+1$. Any competing node receives `EtcdTransactionConflictError`, reads the newly committed index, and retries.

---

## 4. State-Machine Contract & Specification

The proposed `src/witness/state-machine.ts` module must be implemented as a pure, deterministic state machine apply layer.

### 4.1 Domain Models & Interfaces

```typescript
export type ConsensusCommandType =
  | "EPOCH_INITIALIZE"
  | "EPOCH_ADVANCE"
  | "EPOCH_QUARANTINE"
  | "DELEGATION_REVOKE"
  | "TICKET_COMMIT"
  | "POLICY_UPDATE";

export interface CommittedConsensusEntry<T = unknown> {
  readonly epochId: string;
  readonly appLogIndex: bigint;       // Strictly contiguous: 1, 2, 3...
  readonly raftTerm: bigint;          // Raft term when proposed
  readonly etcdRevision: bigint;      // Physical etcd mod_revision
  readonly eventSubIndex: number;     // Index within multi-event txn (0-indexed)
  readonly commandType: ConsensusCommandType;
  readonly payload: T;
  readonly payloadHash: string;       // SHA-256 of canonical payload string
  readonly proposalId: string;        // UUIDv4 client idempotency token
  readonly committedAtSeconds: number;// Deterministic timestamp from proposal
}

export interface StateMachineApplyResult {
  readonly status: "APPLIED" | "ALREADY_APPLIED" | "QUARANTINED";
  readonly appliedIndex: bigint;
  readonly appliedTerm: bigint;
  readonly stateHash: string;
  readonly sideEffectAuthorized: boolean; // True ONLY if node is verified current leader
}
```

### 4.2 State Transition Contract (Pure Reducer)
The state machine transition function is defined mathematically as:
$$\text{apply}(\text{State}_{i-1}, \text{CommittedEntry}_i) \longrightarrow (\text{State}_i, \text{Receipt}_i)$$

#### Mandatory Reducer Invariants
1. **Zero External I/O:** The state reducer must not perform database calls, file I/O, network requests, or read system clocks. Time must be derived strictly from `committedAtSeconds` in the entry.
2. **Strict Monotonic Index Guard:**
   * If $\text{appLogIndex} == \text{lastAppliedIndex} + 1$: **Apply state transition.**
   * If $\text{appLogIndex} \le \text{lastAppliedIndex}$: **Duplicate entry.** Return `status: "ALREADY_APPLIED"` without state mutation.
   * If $\text{appLogIndex} > \text{lastAppliedIndex} + 1$: **Gap detected.** Reject transition, halt application, and trigger stream rewind or snapshot recovery.
3. **Invalid Command Handling:** If a command violates domain invariants (e.g. attempting to spend a budget that exceeds ceilings, or an unknown policy ID), the state machine records a `REJECTED_INTENT` entry, increments `lastAppliedIndex`, and advances `chainHeadHash` without applying the unauthorized state mutation. This prevents malicious or malformed proposals from stalling the consensus pipeline.

---

## 5. PostgreSQL Projection and Recovery Model

### 5.1 Downstream Projection Architecture
Rather than coupling etcd and PostgreSQL via distributed 2PC (which introduces coordinator failure modes and network latency), PostgreSQL operates as a **downstream, at-least-once, idempotent projection store**.

```
                           +------------------------+
                           |  etcd Consensus WAL    | (Authoritative Commit Point)
                           +------------------------+
                                        |
                               etcd Watch Stream
                                        v
                           +------------------------+
                           |  StateMachine Consumer | (In-Memory Apply)
                           +------------------------+
                                        |
                            Single Local ACID Txn
                                        v
                           +------------------------+
                           |  PostgreSQL 16 Tables  | (Downstream Projection Replica)
                           |  - witness_consensus_log
                           |  - witness_raft_state  |
                           |  - witness_epochs      |
                           |  - witness_receipts    |
                           +------------------------+
```

### 5.2 Atomic Projection Transaction Boundary
Every committed event received from etcd is written to PostgreSQL inside a single local ACID transaction:

```sql
BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- 1. Acquire row lock on epoch raft state to prevent concurrent workers
SELECT last_applied_index 
FROM witness_raft_state 
WHERE cluster_id = $cluster_id AND epoch_id = $epoch_id 
FOR UPDATE;

-- 2. Idempotency Check
IF $app_log_index <= last_applied_index THEN
    ROLLBACK; -- Already applied; no-op
    RETURN;
END IF;

-- 3. Assert Gap-Free Contiguity
IF $app_log_index != last_applied_index + 1 THEN
    RAISE EXCEPTION 'Consensus log gap detected: expected %, received %', 
        last_applied_index + 1, $app_log_index;
END IF;

-- 4. Record append-only consensus log entry
INSERT INTO witness_consensus_log (
    epoch_id, log_index, term, etcd_revision, payload_type, 
    payload, payload_hash, proposal_id, committed_at_seconds
) VALUES (
    $epoch_id, $app_log_index, $term, $etcd_revision, $payload_type, 
    $payload, $payload_hash, $proposal_id, $committed_at_seconds
);

-- 5. Apply Domain Projections
-- (e.g. advance epoch, update sequence number, debit budget, record receipt)

-- 6. Advance durable state machine cursor
UPDATE witness_raft_state
SET last_applied_index = $app_log_index,
    last_applied_term  = $term,
    last_applied_hash  = $new_state_hash,
    updated_at_seconds = EXTRACT(EPOCH FROM clock_timestamp())::BIGINT
WHERE cluster_id = $cluster_id AND epoch_id = $epoch_id;

COMMIT;
```

### 5.3 Crash Behavior Analysis across 6 Points

| Crash Point | Failure State | System Impact | Automated Recovery Mechanism |
| :--- | :--- | :--- | :--- |
| **1. Before PG Transaction** | etcd committed; PG has not processed event. | Temporary projection lag. | On reconnect/restart, watch stream re-delivers the event from `last_applied_index + 1`. Processed normally. |
| **2. During PG Transaction** | Crash / power loss mid-transaction. | PG transaction rolls back cleanly via WAL. | Incomplete transaction is discarded. Watch stream re-delivers the event; re-applied cleanly. |
| **3. After PG Commit** | Both etcd and PG updated. | None. State is consistent. | Normal execution resumes. Next event processed. |
| **4. Process Restart** | Node restarts after failure. | In-memory state lost. | Queries PostgreSQL for `last_applied_index`. Connects to etcd with `startRevision` corresponding to `last_applied_index + 1`. Replays missing events to memory. |
| **5. etcd Compaction** | Node was offline; etcd compacted WAL past `last_applied_index`. | Watch stream fails with `EtcdCompactedError`. | Adapter terminates watch. Node initiates **Snapshot Catch-up**: fetches full keyspace at current etcd revision, re-seeds PostgreSQL projections, updates `last_applied_index`, and resumes watch. |
| **6. Snapshot Restore** | etcd cluster restored from catastrophic disaster backup. | Potential revision divergence if PG has newer data. | Reconciliation tool compares etcd `last_index` with PG `last_applied_index`. If PG is ahead, PG rolls back or quarantines divergent epochs (`chk_epochs_quarantine_consistency`). |

---

## 6. KMS Fencing and Authorization Architecture

### 6.1 The Stale Leader Threat Model
In cloud environments, Cloud KMS (AWS KMS and Google Cloud KMS) endpoints are stateless HTTPS web services. They authenticate requests via cloud IAM credentials, but have **zero knowledge of etcd leases, Raft terms, or cluster leadership**.

If Node A is partitioned from the cluster:
* Nodes B and C elect Node B as the new leader for Term $T+1$.
* Node A (stale leader, Term $T$) may still receive requests or have in-flight operations.
* If Node A calls `CloudKmsSigner.signReceipt()`, the cloud KMS API **will successfully sign the payload**, because Node A's cloud IAM permissions are valid!
* This creates a split-brain signing hazard where two conflicting receipts exist for the same sequence number.

### 6.2 Comparison of Fencing Strategies

| Strategy | Mechanism | Prevents KMS Call? | Prevents Rogue Assertion? | Operational Complexity | Assessment |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **1. Direct KMS Access** | App pod calls KMS with long-lived IAM role. | **NO** | **NO** | Low | **UNSAFE:** Stale leader signs freely. |
| **2. Pre-Sign Lease Probe** | Node verifies active etcd lease with linearizable quorum read immediately before signing. | **YES** (probabilistic within lease window) | **NO** (if GC pause occurs after probe) | Medium | **RECOMMENDED COMPONENT:** Blocks >99.9% of stale calls. |
| **3. Centralized Signing Gateway** | Dedicated signing proxy holding KMS keys that verifies leader lease tokens. | **YES** | **YES** | High (New SPOF, network hop, cluster) | Over-engineered for current phase. |
| **4. Cryptographic Term Binding (Preimage v2)** | Raft term & log index embedded in signed preimage; verifiers reject stale terms. | **NO** (KMS still called) | **YES** (Signatures rendered cryptographically invalid) | Low | **MANDATORY COMPONENT:** Prevents acceptance of stale assertions. |

### 6.3 Recommended Architecture: Dual-Barrier Fencing
To guarantee that stale leaders cannot generate valid assertions, Web3User adopts a **Dual-Barrier Fencing Architecture**:

```
[Witness Commit Request]
           |
           v
+---------------------------------------------------------------------------------------+
| BARRIER 1: Pre-Sign Linearizable Lease Barrier (Physical Protection)                  |
| - Proposer verifies active etcd leader lease via linearizable read with 500ms timeout.|
| - If lease has expired or quorum is lost -> Reject immediately with                   |
|   StaleWorkerFencedError. KMS is NEVER called.                                        |
+---------------------------------------------------------------------------------------+
           |
     (Lease Valid)
           v
+---------------------------------------------------------------------------------------+
| BARRIER 2: Cryptographic Term Binding in Preimage v2 (Cryptographic Protection)        |
| - Embedded Fields: formatCanonicalPreimageV2(epochId, raftTerm, logIndex, seqNum...)   |
| - If a network race or GC pause causes a stale leader to sign anyway, the signature   |
|   contains term T, while the cluster is on term T+1.                                   |
| - Verifiers and clients check the published cluster epoch certificate:                |
|   assert(receipt.raftTerm == currentEpochTerm && receipt.logIndex == expectedIndex);   |
| - Result: Stale signature is rejected as cryptographically invalid!                   |
+---------------------------------------------------------------------------------------+
```

### 6.4 Receipt Preimage v2 Format

```
web3user-witness-receipt-v2
witness.version:2
witness.witnessId:<witness_id>
witness.epochId:<epoch_id>
consensus.raftTerm:<raft_term>
consensus.logIndex:<app_log_index>
consensus.etcdRevision:<etcd_revision>
witness.sequenceNumber:<sequence_number>
ticket.ticketId:<ticket_id>
artifact.authorizationId:<authorization_id>
artifact.bindingDigest:<binding_digest>
policy.policyId:<policy_id>
policy.policyRevision:<policy_revision>
budget.debitedAmount:<debited_amount>
budget.windows:<encoded_windows>
witness.committedAtSeconds:<timestamp>
```

---

## 7. Failure-Mode Analysis

| Failure Scenario | Trigger Condition | Detection Point | System Behavior | Fail-Safe State |
| :--- | :--- | :--- | :--- | :--- |
| **Asymmetric Network Partition** | Leader isolated from followers; followers form new quorum. | Pre-Sign Barrier (Barrier 1) fails linearizable lease read. | Fails closed with `StaleWorkerFencedError`. Signing aborted. | Zero double-signing. |
| **GC Pause Race** | Leader pauses for 3s after lease check; lease expires during pause. | Verification check (Barrier 2). | Stale leader signs with Term $T$. Verifiers observe cluster at Term $T+1$ and reject receipt. | Rogue assertion cryptographically rejected. |
| **Out-of-Order Watch Event** | Network jitter delivers log entry $N+2$ before $N+1$. | `StateMachine.apply()` monotonic guard. | Gap detected ($N+2 \ne N+1$). Entry buffered or stream rewound. | Zero log fork; state machine does not corrupt. |
| **Duplicate Event Delivery** | Watch reconnects and re-delivers already processed entries. | PostgreSQL `last_applied_index` check. | $N \le \text{last\_applied\_index}$. Logged as idempotent no-op; transaction rolls back. | Idempotent duplicate rejection. |
| **PostgreSQL Disk Full** | Database out of storage during projection commit. | PG transaction throws `53100 DISK FULL`. | Rollback. In-memory state machine pauses. etcd WAL remains committed. | Node reports unhealthy (`503`). Reconnects upon recovery. |
| **etcd Cluster Quorum Loss** | 2 of 3 etcd nodes crash. | `EtcdClientAdapter` gRPC call times out. | Throws `EtcdUnavailableError` within 3000ms. | Fail-closed: all write and signing operations halted. |

---

## 8. Multi-Node Validation Architecture

To rigorously validate consensus, failover, and fencing before production deployment, an automated 3-node local etcd cluster harness must be constructed:

### 8.1 Harness Topology (`scripts/test-etcd-cluster.mjs`)
* **Binary:** Canonical `etcd-v3.5.18-windows-amd64` (extracted in `.bin/`).
* **Node 1:** Client `127.0.0.1:2379`, Peer `127.0.0.1:2380`, Data dir `.tmp/etcd-node-1`
* **Node 2:** Client `127.0.0.1:2389`, Peer `127.0.0.1:2390`, Data dir `.tmp/etcd-node-2`
* **Node 3:** Client `127.0.0.1:2399`, Peer `127.0.0.1:2400`, Data dir `.tmp/etcd-node-3`
* **Cluster Token:** `web3user-test-cluster`
* **Initial Cluster:** `node1=http://127.0.0.1:2380,node2=http://127.0.0.1:2390,node3=http://127.0.0.1:2400`

### 8.2 Test Suite Specification (`test/witness/etcd-cluster-3node.real.test.ts`)
The harness must execute 10 mandatory integration test scenarios:

1. **Cluster Formation & Health:** Assert all 3 nodes report `healthy: true` and agree on `cluster_id` and `raft_term`.
2. **Leader Failover Election Time:** Terminate current leader with `SIGKILL`. Assert remaining 2 nodes elect a new leader and `healthCheck()` succeeds on remaining endpoints within $< 3000\text{ms}$.
3. **Minority Partition Rejection:** Isolate Node 3 from Nodes 1 & 2. Assert writes to Node 3 fail with `EtcdUnavailableError` or timeout, while writes to Nodes 1 & 2 succeed.
4. **Majority Quorum Availability:** Kill Node 1. Verify cluster continues processing CAS transactions on Nodes 2 & 3.
5. **Client Endpoint Failover:** Configure `EtcdClientAdapter` with `endpoints: [port2379, port2389, port2399]`. Kill active endpoint mid-operation; assert adapter transparently switches endpoints without data loss.
6. **Watch Resumption across Leader Crash:** Open watch on prefix. Kill etcd leader. Propose entries on new leader. Assert watch reconnects and delivers all entries sequentially without missed events.
7. **Compaction & Snapshot Recovery:** Propose 1,000 entries. Compact etcd up to revision 900. Reconnect watcher with `startRevision: 100`. Assert adapter catches `EtcdCompactedError`, triggers snapshot fetch, and resynchronizes.
8. **Partition Rejoin & WAL Catch-up:** Stop Node 3. Propose 50 entries to Nodes 1 & 2. Restart Node 3. Assert Node 3 replays WAL and synchronizes to match the cluster revision.
9. **Stale Leader Proposal Rejection:** Simulate partitioned node attempting a CAS proposal with an old term/revision. Assert proposal is rejected.
10. **Dual-Barrier KMS Fencing Under Partition:** Simulate leader network partition. Trigger signing request on partitioned node. Assert Barrier 1 aborts signing before KMS API call is dispatched.

---

## 9. Alternatives Considered

| Alternative | Pros | Cons | Verdict |
| :--- | :--- | :--- | :--- |
| **Bespoke In-Process Raft in TypeScript** | Pure JS runtime, single binary. | Huge surface area, unproven in production, bugs in leader election / log compaction lead to data loss. | **REJECTED:** Canonical etcd v3 provides proven Raft engine. |
| **Distributed 2-Phase Commit (etcd + PG)** | Theoretical strict synchronization across stores. | Blocking protocol; coordinator crash leaves locks hanging; high latency; extreme complexity. | **REJECTED:** Downstream idempotent projection is crash-safe and simpler. |
| **Transactional Outbox in PostgreSQL** | Uses PG ACID transactions to queue consensus proposals. | Inverts dependency: makes PG the single point of failure (SPOF) and commit authority, defeating Raft's purpose. | **REJECTED:** etcd must be the authoritative commit point. |
| **Centralized KMS Signing Proxy** | Isolates KMS credentials to a single secured microservice. | Introduces another distributed node, network hop, and failure domain. | **DEFERRED:** Dual-barrier fencing provides equivalent safety without new infrastructure. |

---

## 10. Design Decisions Requiring Approval

The following architectural decisions are submitted for formal project review:

| Decision ID | Topic | Recommendation | Classification |
| :---: | :--- | :--- | :--- |
| **DDR-01** | **Consensus Architecture** | etcd v3 is the sole distributed consensus engine; TypeScript layer is strictly a deterministic state-machine apply layer (`apply(state, cmd)`). | **RECOMMENDED** |
| **DDR-02** | **Ordering Model** | Adopt Dual-Cursor Ordering: physical `(etcd_revision, sub_index)` for wire watch resumption, and contiguous `app_log_index` (1, 2, 3...) for state-machine ordering. | **RECOMMENDED** |
| **DDR-03** | **Persistence Pattern** | PostgreSQL is a downstream, at-least-once idempotent projection store driven by committed etcd watch events. Reject distributed 2PC. | **RECOMMENDED** |
| **DDR-04** | **KMS Fencing Strategy** | Adopt Dual-Barrier Fencing: (1) Pre-sign linearizable lease check, and (2) Cryptographic Raft term/index binding in Receipt Preimage v2. | **REQUIRES APPROVAL** |
| **DDR-05** | **Receipt Preimage v2** | Upgrade canonical receipt preimage from v1 to v2 to incorporate `consensus.raftTerm`, `consensus.logIndex`, and `consensus.etcdRevision`. | **REQUIRES APPROVAL** |
| **DDR-06** | **Multi-Node Testing Order** | Construct 3-node local etcd test harness (Stage 3-A) *before* multi-node state machine integration (Stage 3-B). | **RECOMMENDED** |

---

## 11. Proposed Implementation Sequence

To maintain safety, implementation should be phased across discrete, verified milestones:

```
[Stage 2-B0: Architecture Specification & Decision Record] <--- (CURRENT COMPLETED STAGE)
                               |
                               v
[Stage 2-B1: State Machine Interfaces & In-Memory Reducer]
- Implement src/witness/state-machine-types.ts & src/witness/state-machine.ts
- Pure unit tests in test/witness/state-machine.test.ts (zero external I/O)
                               |
                               v
[Stage 3-A: Automated 3-Node Local Cluster Test Harness]
- Implement scripts/test-etcd-cluster.mjs (ports 2379, 2389, 2399)
- Automated cluster health check, leader election, and teardown
                               |
                               v
[Stage 2-B2: PostgreSQL Projection & Watch Integration]
- Wire EtcdClientAdapter watch stream to StateMachine.apply()
- Connect StateMachine.apply() to PostgreSQL 003 projection transaction
- Test crash recovery and idempotent replay
                               |
                               v
[Stage 3-B: Multi-Node Quorum, Failover & Fencing Verification]
- Execute 10 multi-node integration tests in test/witness/etcd-cluster-3node.real.test.ts
- Validate leader failover < 3000ms, minority partition fail-closed, and KMS fencing
                               |
                               v
[Stage 3-C: End-to-End Witness gRPC Pipeline & Regression]
- Upgrade Receipt Preimage to v2 in src/witness/signing.ts
- Wire GrpcWitnessServer to propose via etcd and verify pre-sign lease barrier
- Run full 760+ test regression suite
```

---

## 12. Acceptance Criteria for Subsequent Implementation

Any future pull request implementing Stage 2-B must satisfy these objective criteria:

1. **Ordering Contiguity:** The state machine strictly rejects any log entry where `app_log_index != last_applied_index + 1n`, unless it is an idempotent replay where `app_log_index <= last_applied_index`.
2. **Idempotent Replay:** Replaying 1,000 already-committed entries against PostgreSQL results in zero changes to domain tables and zero database exceptions.
3. **Fail-Closed on Quorum Loss:** When etcd loses quorum (2 of 3 nodes terminated), all proposals and signing requests fail closed within 3000ms.
4. **Leader Failover Time:** Upon leader `SIGKILL`, a new leader is elected and resumes transaction processing within 3000ms.
5. **Zero Stale Signatures:** Under simulated network partition, zero KMS signatures are generated by the isolated leader node.
6. **Zero Regression:** All existing 760 tests pass with zero failures.

---

*Specification complete. This document is strictly an advisory architecture design record. No implementation or git modifications have been executed.*
