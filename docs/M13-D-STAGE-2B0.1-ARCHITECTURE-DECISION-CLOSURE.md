# Milestone 13-D Stage 2-B0.1: Architecture Decision Closure

**Document ID:** `M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE`  
**Date:** 2026-11-23  
**Status:** DRAFT / PENDING FORMAL ARCHITECTURAL APPROVAL  
**Document Type:** Architectural Refinement, Decision Record & Safety Proof  
**Target Milestone:** Milestone 13-D (Distributed Consensus Engine) — Stage 2-B  
**Auditor / Architect:** Antigravity Autonomous Security & Architecture Reviewer  

---

## 1. Executive Summary

This document establishes the definitive architectural decisions and technical refinements required to close all outstanding ambiguities from `M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md`.

### 1.1 Critical Corrections Resolved in this Closure
1. **Mathematical Correction to Dual-Cursor Tracking:** Clarifies the exact invariant connecting physical stream coordinates `(etcd_revision, sub_index)` to logical application sequence `app_log_index`. Demonstrates how multiple events within a single etcd revision and unrelated keyspace revision leaps are processed deterministically across node crashes and restarts.
2. **PostgreSQL Single-Transaction Atomicity:** Formulates the exact ACID transaction boundary that couples logical state projection, physical cursor progression, and idempotent deduplication into an indivisible unit of work. Proves crash recovery behavior at every execution micro-boundary.
3. **Refutation of Pre-Sign Lease Check as Independent Fencing:** Provides formal proof showing why client-side lease probes fail to prevent stale signing during Stop-The-World (STW) Garbage Collection pauses or thread starvation.
4. **Architectural Demarcation between Prevention and Detection:**
   * **Signing Prevention (Upstream Barrier):** Requires isolating cloud KMS credentials to a **Dedicated Fenced Signing Gateway** (or lease-bound STS ephemeral sessions). Stale leaders are physically blocked from invoking the KMS API.
   * **Signature Detection & Rejection (Downstream Barrier):** Embedding Raft terms in **Receipt Preimage v2** ensures that if any anomalous or out-of-band signature is ever generated, it is universally rejected by verifiers.
5. **Receipt Preimage Migration & Compatibility Matrix:** Establishes a non-breaking, forward/backward compatible migration path from Receipt Preimage v1 to v2 across historical archives, legacy SDK clients, and upgraded verifiers.

---

## 2. Dual-Cursor Ordering & Recovery Model

### 2.1 The Four Cursor Coordinates Defined
To guarantee deterministic execution and crash recovery, four explicit cursor coordinates must be distinguished:

| Symbol | Coordinate Name | Scope & Authority | Format | Semantics & Role |
| :--- | :--- | :--- | :--- | :--- |
| $R_{etcd}$ | `etcd_revision` | etcd Cluster Global | `int64` (`bigint`) | Monotonically increasing revision counter across the entire etcd keyspace. Advanced by any write to any key in etcd. |
| $S_{idx}$ | `sub_index` | Transaction Local | `int32` (`number`) | 0-based offset identifying the relative order of key-value operations committed within a single etcd `Txn`. |
| $L_{app}$ | `app_log_index` | Epoch Stream Logical | `int64` (`bigint`) | Strictly contiguous monotonic integer ($1, 2, 3\dots$) per epoch. Embedded in command payloads. Drives state machine transitions. |
| $A_{app}$ | `last_applied_app_index` | PostgreSQL State Machine | `int64` (`bigint`) | The highest $L_{app}$ applied to the local PostgreSQL database and application projections. |

### 2.2 Mathematical Relationship & Non-Contiguity Mapping
Because etcd `mod_revision` is shared across all keys, $R_{etcd}$ exhibits non-contiguous leaps from the perspective of an application watch stream. Conversely, multiple events committed in a single etcd transaction share the exact same $R_{etcd}$.

The physical stream coordinate is the lexicographical tuple:
$$C_{phys} = (R_{etcd}, S_{idx})$$

The logical application coordinate is the integer:
$$C_{logic} = L_{app}$$

```
========================================================================================
DUAL-CURSOR STREAM MAPPING EXAMPLE
========================================================================================

Physical etcd Stream Events                  Application State Machine
(R_etcd, S_idx)                              (L_app, CommandType)
----------------------------------------------------------------------------------------
(1001, 0) ---------------------------------> L_app = 1 (EPOCH_INITIALIZE)
(1001, 1) [Same Txn, S_idx=1] -------------> L_app = 2 (POLICY_UPDATE)
  -- Revisions 1002-1007 written to
     unrelated leases / keyspace --
(1008, 0) [Revision leap +7] --------------> L_app = 3 (TICKET_COMMIT)
(1009, 0) ---------------------------------> L_app = 4 (TICKET_COMMIT)
(1012, 0) [Revision leap +3] --------------> L_app = 5 (DELEGATION_REVOKE)
========================================================================================
```

### 2.3 Resumption and Recovery Algorithm
* **Watch Resumption:** The etcd watch stream is established using $R_{etcd}$. When reconnecting, the adapter opens:
  $$\text{watch}(\text{prefix}, \text{startRevision} = R_{etcd\_persisted} + 1)$$
* **Sub-Index Filtering on Resumption:** If an etcd revision contained multiple events and the node crashed mid-revision, the state machine loads both $R_{etcd\_persisted}$ and $S_{idx\_persisted}$. Any event matching $R_{etcd} == R_{etcd\_persisted}$ where $S_{idx} \le S_{idx\_persisted}$ is skipped as already processed.
* **Logical Index Guard:** The state machine strictly asserts:
  $$L_{app} == A_{app} + 1$$
  If $L_{app} \le A_{app}$, it is an idempotent duplicate (ignored). If $L_{app} > A_{app} + 1$, a logical gap is detected, immediately tripping fail-closed stream quarantine.

---

## 3. PostgreSQL Atomicity and Compaction Architecture

### 3.1 Single-Transaction Atomicity Specification
All projections, historical logging, and dual-cursor advancements occur within **exactly one ACID database transaction**. No database updates occur outside this transaction boundary.

```sql
-- ATOMIC PROJECTION TRANSACTION BOUNDARY
BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- 1. Deterministic Concurrency Lock: Lock the raft state row for the specific epoch
SELECT 
    last_applied_index,
    last_applied_term,
    last_applied_etcd_revision,
    last_applied_sub_index
FROM witness_raft_state
WHERE cluster_id = $1 AND epoch_id = $2
FOR UPDATE;

-- 2. Duplicate Check: Idempotent short-circuit
IF $in_app_log_index <= last_applied_index THEN
    ROLLBACK;
    -- Acknowledge event as already applied; no mutations performed
    RETURN;
END IF;

-- 3. Invariant Assertion: Strict logical contiguity
IF $in_app_log_index <> last_applied_index + 1 THEN
    RAISE EXCEPTION 'LOGICAL_INDEX_GAP: Expected % but received % for epoch %', 
        last_applied_index + 1, $in_app_log_index, $2;
END IF;

-- 4. Append to Historical Audit Log
INSERT INTO witness_consensus_log (
    epoch_id,
    log_index,
    term,
    etcd_revision,
    sub_index,
    payload_type,
    payload,
    payload_hash,
    proposal_id,
    committed_at_seconds
) VALUES (
    $2, $in_app_log_index, $in_term, $in_etcd_revision, $in_sub_index,
    $in_payload_type, $in_payload, $in_payload_hash, $in_proposal_id, $in_committed_at
);

-- 5. Mutate Domain Projections
-- Example: Update ticket status and spend allocations
UPDATE witness_tickets
SET state = 'COMMITTED', updated_at_seconds = $in_committed_at
WHERE ticket_id = $in_ticket_id;

-- 6. Atomically Advance Both Cursors
UPDATE witness_raft_state
SET 
    last_applied_index         = $in_app_log_index,
    last_applied_term          = $in_term,
    last_applied_etcd_revision = $in_etcd_revision,
    last_applied_sub_index     = $in_sub_index,
    last_applied_hash          = $in_new_state_hash,
    updated_at_seconds         = EXTRACT(EPOCH FROM clock_timestamp())::BIGINT
WHERE cluster_id = $1 AND epoch_id = $2;

COMMIT;
```

### 3.2 Crash Behavior Across Transaction Micro-Boundaries

```
                        (Event Delivered via Watch)
                                     |
               +---------------------v---------------------+
               | Point 1: Before BEGIN TRANSACTION         |
               +-------------------------------------------+
                                     | (Crash -> etcd retains WAL; PG untouched.
                                     |  Recovery: Watch re-delivers event on restart)
               +---------------------v---------------------+
               | Point 2: Active Transaction Execution     |
               +-------------------------------------------+
                                     | (Crash -> PostgreSQL aborts; WAL rolled back.
                                     |  Zero dirty reads or partial projection updates.
                                     |  Recovery: Watch re-delivers event on restart)
               +---------------------v---------------------+
               | Point 3: WAL Flushed, After COMMIT        |
               +-------------------------------------------+
                                     | (Crash -> State and both cursors committed.
                                     |  Recovery: Restart reads new cursor coordinates;
                                     |  Watch resumes from next physical coordinate)
```

### 3.3 Event Retention & etcd Compaction Reality
A critical distributed systems invariant must be enforced:
> **Once etcd compacts its WAL past revision $R$, etcd cannot replay history prior to $R$.**

* **PostgreSQL Event Retention:** PostgreSQL retains all historical events in `witness_consensus_log` indefinitely (protected by `trg_witness_consensus_log_immutable`). PostgreSQL is the permanent audit trail.
* **Compaction Recovery Protocol:** If a witness node is offline longer than etcd's compaction retention window, its watch request with `startRevision = last_applied_etcd_revision + 1` will fail with `EtcdCompactedError`.
* **Snapshot Catch-up Procedure:**
  1. The node catches `EtcdCompactedError`.
  2. The node queries etcd for a full linearizable snapshot of active state at the current revision $R_{current}$ (`/web3user/epochs/`, `/web3user/consensus/state/`).
  3. The node reconciles PostgreSQL domain tables to match the snapshot.
  4. The node updates `witness_raft_state` with `last_applied_etcd_revision = R_{current}`.
  5. The watch stream resumes at $R_{current} + 1$.

---

## 4. Redesign of KMS Fencing and Authorization

### 4.1 Proof: Why Client-Side Lease Checks Cannot Prevent Stale Signing
Consider the timeline of a leader node undergoing a Stop-The-World (STW) Garbage Collection pause or vCPU preemption:

```
Timeline (ms)
T = 0ms     : Node A is Leader. Active lease L expires at T = 3000ms.
T = 10ms    : Node A performs linearizable lease check. etcd confirms: "Lease L is valid."
T = 15ms    : Node A enters STW GC pause (or hypervisor CPU freeze). Thread suspended.
T = 3000ms  : Lease L expires in etcd cluster.
T = 3200ms  : Nodes B & C detect heartbeat timeout, advance term to T+1, elect Node B as Leader.
T = 3300ms  : Node B obtains Lease L2 and begins committing new transactions.
T = 6000ms  : Node A GC pause ends. Thread resumes on instruction IMMEDIATELY FOLLOWING lease check.
T = 6005ms  : Node A calls AWS/GCP KMS API: signReceipt(payload).
T = 6050ms  : AWS/GCP KMS validates Node A's IAM credentials and signs the payload!
========================================================================================
RESULT: Stale leader Node A successfully signed an unauthorized, split-brain receipt!
========================================================================================
```

**Conclusion:** A pre-sign lease check performed inside the application process **cannot** independently guarantee the prevention of stale signing.

### 4.2 Comprehensive Evaluation of Fencing Architectures

| Evaluation Criterion | Option A: Direct KMS with App Lease Check | Option B: Centralized Fenced Signing Gateway | Option C: Centralized Authorization Service | Option D: Short-Lived Lease-Bound STS Credentials |
| :--- | :---: | :---: | :---: | :---: |
| **Stale Leader Resistance** | **FAIL** (Vulnerable to GC/pause) | **HIGH** (Gateway enforces atomic fencing) | **MEDIUM** (Still vulnerable if app calls KMS) | **PROVABLE** (Credential expires before lease) |
| **Network Partition Safe** | **FAIL** (Partitioned node retains creds) | **YES** (Gateway verifies cluster term) | **YES** | **YES** (STS token expires) |
| **Credential Isolation** | **POOR** (All app pods hold KMS keys) | **EXCELLENT** (Only Gateway holds KMS keys)| **POOR** (App pods hold KMS keys) | **GOOD** (Pods hold ephemeral 5s tokens) |
| **Fail-Closed Semantics** | High | High | High | High |
| **Operational Complexity** | Lowest | High (New clustered service) | High (New proxy service) | Medium (AWS/GCP STS token minting) |
| **Availability Risk** | Low (Direct cloud API) | High (Gateway is new SPOF) | High (Auth service is SPOF) | Low (Decentralized token validation) |
| **Prevents KMS Call?** | **NO** | **YES** | **NO** | **YES** (KMS rejects expired token) |

### 4.3 Recommended Dual-Action Strategy: Prevention + Rejection

```
+---------------------------------------------------------------------------------------+
| LAYER 1: SIGNING PREVENTION (Physical Boundary)                                       |
| Mechanism: Ephemeral Lease-Bound STS Session Credentials (or Gateway)                 |
| - The leader node holds cloud KMS IAM credentials that are valid ONLY for a           |
|   bounded duration: TTL = (Lease_TTL - Max_Clock_Skew - KMS_Request_Timeout).         |
| - In AWS: AssumeRole with duration / scoped session policy.                           |
| - In GCP: Downscoped short-lived OAuth access tokens.                                 |
| - Result: If a node experiences an STW pause that outlasts its lease, its cloud       |
|   credentials EXPIRE BEFORE execution resumes. The KMS API physically rejects         |
|   the call with HTTP 401/403!                                                         |
+---------------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------+
| LAYER 2: SIGNATURE DETECTION & REJECTION (Cryptographic Boundary)                     |
| Mechanism: Receipt Preimage v2 Term & Index Embedding                                 |
| - Embedded Fields: consensus.raftTerm, consensus.logIndex, consensus.etcdRevision     |
| - Result: If any rogue signature is ever generated via out-of-band means, every       |
|   verifying client rejects it upon observing that the receipt term is stale.          |
+---------------------------------------------------------------------------------------+
```

---

## 5. Receipt Preimage v2 Migration & Compatibility Matrix

Upgrading from Receipt Preimage v1 to v2 must preserve historical verifiability and avoid breaking existing SDK consumers.

### 5.1 Preimage Format Comparison

#### Legacy Preimage v1 (`src/monotonic-witness.ts`)
```
web3user-witness-receipt-v1\n
witness.version:1\n
witness.witnessId:<id>\n
witness.epochId:<epoch>\n
witness.sequenceNumber:<seq>\n
ticket.ticketId:<ticket>\n
artifact.authorizationId:<auth_id>\n
artifact.bindingDigest:<digest>\n
policy.policyId:<policy>\n
policy.policyRevision:<rev>\n
budget.debitedAmount:<amt>\n
budget.windows:<windows>\n
witness.committedAtSeconds:<time>\n
```

#### Upgraded Preimage v2
```
web3user-witness-receipt-v2\n
witness.version:2\n
witness.witnessId:<id>\n
witness.epochId:<epoch>\n
consensus.raftTerm:<term>\n
consensus.logIndex:<app_log_index>\n
consensus.etcdRevision:<etcd_revision>\n
witness.sequenceNumber:<seq>\n
ticket.ticketId:<ticket>\n
artifact.authorizationId:<auth_id>\n
artifact.bindingDigest:<digest>\n
policy.policyId:<policy>\n
policy.policyRevision:<rev>\n
budget.debitedAmount:<amt>\n
budget.windows:<windows>\n
witness.committedAtSeconds:<time>\n
```

### 5.2 Ecosystem Compatibility Matrix

| Actor / Component | Interacting With | Compatibility Status | Behavior & Handling |
| :--- | :--- | :---: | :--- |
| **Existing v1 Receipts** | Legacy Verifier | **COMPATIBLE** | Verifies successfully using v1 canonical formatting. |
| **Existing v1 Receipts** | Upgraded v2 Verifier | **COMPATIBLE** | Upgraded verifier checks `receipt.version`. If `version == 1`, it executes `canonicalWitnessReceiptPayloadV1()`. Historical receipts remain 100% valid. |
| **New v2 Receipts** | Upgraded v2 Verifier | **COMPATIBLE** | Verifier validates Ed25519 signature over v2 preimage AND validates that `consensus.raftTerm` matches the published epoch consensus certificate. |
| **New v2 Receipts** | Legacy v1 Verifier | **FAIL-CLOSED** | Legacy verifier checks `receipt.version !== 1` and throws `Error("Invalid parameters for canonicalWitnessReceiptPayload")`. Stale verifiers safely reject new receipts. |
| **Legacy SDK Client** | Upgraded Witness Server | **NEGOTIATED** | Server supports request field `supported_receipt_version`. If client specifies `v1`, server falls back to v1 (only permitted during initial migration phase). |
| **Upgraded SDK Client** | Upgraded Witness Server | **NATIVE v2** | Issues and verifies v2 receipts with full cryptographic term fencing. |

---

## 6. Formal Approval Decisions Matrix

| Decision ID | Architectural Decision | Evaluated Options | Recommended Option | Security & Operational Impact |
| :---: | :--- | :--- | :--- | :--- |
| **DDR-01** | **Authoritative Ordering Model** | **A:** Raw etcd revisions.<br>**B:** Dual-cursor (etcd revision + app log index). | **Option B (Dual-Cursor)** | Eliminates gaps from unrelated keyspace writes; guarantees contiguous $1, 2, 3\dots$ state-machine transitions. |
| **DDR-02** | **PostgreSQL Projection Pattern** | **A:** Distributed 2PC.<br>**B:** Single-transaction downstream idempotent consumer. | **Option B (Idempotent Consumer)** | Eliminates distributed deadlocks; guarantees zero partial writes; bounded by `last_applied_index`. |
| **DDR-03** | **Compaction Catch-up Mechanism** | **A:** Require infinite etcd WAL retention.<br>**B:** State snapshot resynchronization on `EtcdCompactedError`. | **Option B (Snapshot Catch-up)** | Prevents unbounded disk consumption in etcd; enables safe catch-up for lagging nodes. |
| **DDR-04** | **Stale Leader KMS Fencing** | **A:** App lease check only.<br>**B:** Short-lived STS tokens + Preimage v2 term binding. | **Option B (Dual Protection)** | Physically prevents KMS calls past lease expiry via credential timeout; cryptographically invalidates stale signatures. |
| **DDR-05** | **Receipt Preimage Evolution** | **A:** Retain v1 indefinitely.<br>**B:** Upgrade to Preimage v2 with backwards-compatible verification. | **Option B (Preimage v2)** | Provides cryptographic non-repudiation of Raft terms; fully preserves verification of historical v1 receipts. |
| **DDR-06** | **Implementation Phasing** | **A:** Implement state machine and cluster simultaneously.<br>**B:** Stage 2-B.1 (Contracts) -> Stage 3-A (Cluster Harness) -> Stage 2-B.2 (Integration). | **Option B (Phased Delivery)** | Decouples pure domain logic from multi-process orchestration, ensuring 100% testability at each boundary. |

---

## 7. Proposed Implementation Phasing

```
========================================================================================
REVISED IMPLEMENTATION PHASING (STAGE 2-B THROUGH STAGE 3)
========================================================================================

PHASE 1: In-Memory State Machine Contracts (Stage 2-B.1)
----------------------------------------------------------------------------------------
- Scope: Zero database or network dependencies.
- Deliverables:
  * `src/witness/state-machine-types.ts`: Define command types, committed entries, apply results.
  * `src/witness/state-machine.ts`: Implement pure reducer with `apply(state, entry)`.
  * `test/witness/state-machine.test.ts`: 100% in-memory unit tests (gap detection, duplicates).
- Verification Gate: `npm test` passes purely in memory; zero side effects.

PHASE 2: Automated 3-Node Local Cluster Harness (Stage 3-A)
----------------------------------------------------------------------------------------
- Scope: Node orchestration for real etcd testing.
- Deliverables:
  * `scripts/test-etcd-cluster.mjs`: Programmatic 3-node etcd runner (ports 2379, 2389, 2399).
  * Fault injection API: `killNode(id)`, `restartNode(id)`, `partitionNode(id)`.
  * `test/witness/etcd-cluster-3node.real.test.ts`: Automated cluster health & failover tests.
- Verification Gate: Leader election and failover verified < 3000ms.

PHASE 3: PostgreSQL Projection & Dual-Cursor Integration (Stage 2-B.2)
----------------------------------------------------------------------------------------
- Scope: Connect etcd watch stream to single-transaction PostgreSQL projection.
- Deliverables:
  * Extend `witness_raft_state` with `last_applied_etcd_revision` and `last_applied_sub_index`.
  * Implement atomic projection transaction in `src/witness/consensus-projector.ts`.
  * Integration tests for crash recovery, duplicate event replay, and compaction catch-up.
- Verification Gate: Zero divergent rows under simulated process kill.

PHASE 4: Fenced KMS Signing & Preimage v2 Rollout (Stage 3-C)
----------------------------------------------------------------------------------------
- Scope: End-to-end integration with KMS and gRPC service.
- Deliverables:
  * Implement `formatCanonicalPreimageV2()` in `src/witness/signing.ts`.
  * Update `verifyWitnessReceipt()` with dual-version support (v1 and v2).
  * Integrate pre-sign lease check and ephemeral credential expiration in `CloudKmsSigner`.
  * Full regression run: 760+ existing tests pass.
- Verification Gate: Zero stale signatures under simulated network partition.
========================================================================================
```

---

## 8. Summary of Findings & Next Steps

1. **Dual-Cursor Semantics Confirmed:** $C_{phys} = (R_{etcd}, S_{idx})$ handles transport resumption; $C_{logic} = L_{app}$ governs strictly contiguous application state transitions.
2. **PostgreSQL Projection Atomicity Specified:** A single ACID transaction atomically checks $L_{app}$, inserts into `witness_consensus_log`, updates projections, and advances $A_{app}$, $R_{etcd}$, and $S_{idx}$.
3. **KMS Fencing Redesigned:** Client-side lease checks are proven insufficient during STW pauses. Prevention is achieved via short-lived lease-bound credentials; detection is achieved via Preimage v2 term embedding.
4. **All Operations Read-Only:** Zero application code, test files, dependencies, roadmaps, or mindmaps were modified. All working-tree changes remain preserved.

*Architectural Decision Closure complete. Standing by for formal project approval of Decisions DDR-01 through DDR-06.*
