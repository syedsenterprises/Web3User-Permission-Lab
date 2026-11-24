# Milestone 13-D Phase D3: Raft Consensus — Independent Architecture Challenge

**Document ID:** `M13-D-PHASE-D3-ARCHITECTURE-CHALLENGE`  
**Date:** 2026-11-23  
**Status:** DRAFT / PENDING REVIEW  
**Audit Type:** Second-Pass Read-Only Architecture Challenge & Technical Verification  
**Target Document:** `docs/M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT.md`  
**Auditor:** Antigravity Autonomous Security & Architecture Reviewer  

---

## 1. Executive Verdict

```
================================================================================
AUDIT VERDICT: CRITIQUE SUSTAINED — REVISED WITH ARCHITECTURAL CORRECTIONS
================================================================================
```

The initial engineering readiness assessment (`docs/M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT.md`) correctly identified that Web3User does not implement a bespoke in-process Raft protocol engine in TypeScript and properly established `READY WITH PREREQUISITES` as its high-level verdict.

However, this second-pass audit reveals **critical technical inaccuracies, unverified safety assumptions, and architectural ambiguities** in the initial assessment:

1. **Categorical Error on PostgreSQL "Raft Safety":** Attributing Raft protocol properties (such as Log Matching and State Machine Safety) to PostgreSQL table constraints (`PRIMARY KEY`, `CHECK`) is categorically incorrect. Relational constraints protect local database row integrity upon insert; they provide zero distributed consensus guarantees, cannot prevent split-brain proposals, and cannot resolve Raft log divergence.
2. **Fencing Token Inadequacy:** Treating raw etcd `modRevision` as an effective fencing token for downstream operations is unsupported. In actual code (`src/witness/cloud-kms-signer.ts`), Cloud KMS signing APIs have zero awareness of etcd revisions or terms. Furthermore, in `src/witness/grpc-service.ts`, `fencingGen` is currently hardcoded to `1`.
3. **Stale Leader KMS Signing Vulnerability:** The claim that etcd leases prevent stale leaders from signing is **false** under the current implementation. An unseated or partitioned leader holding valid KMS credentials can invoke `CloudKmsSigner.signReceipt()` directly without consulting etcd, producing valid signatures on stale state.
4. **Dual-Store Partial Failure Divergence:** The initial assessment understated the dual-write hazard. Because there is no 2-Phase Commit (2PC) or transactional outbox between etcd transactions and PostgreSQL commits, network or database errors during Phase 3 of witness processing lead to silent, unrecoverable state divergence between etcd and PostgreSQL.
5. **Flawed Execution Sequence:** Proposing an in-process state machine (Stage 2-B) before establishing a multi-node cluster test harness (Stage 3-A) creates an untestable abstraction. State-machine catch-up, watch reconnection upon leader election, and snapshot compaction cannot be validated against a single-node etcd instance.

---

## 2. Verified Architecture

To prevent design errors, the system architecture must strictly delineate three separate layers:

```
+---------------------------------------------------------------------------------------+
| LAYER 1: Core Raft Distributed Consensus Engine (External / Canonical)                |
| - Implementation: CoreOS / etcd v3.5.18 (Go runtime engine)                           |
| - Responsibilities:                                                                   |
|   * Leader election via randomized timeouts and term increments                      |
|   * Distributed log replication via AppendEntries RPC                                  |
|   * Majority quorum calculation: (N/2) + 1 nodes                                      |
|   * Linearizable read index enforcement                                               |
|   * Native Write-Ahead Log (WAL) persistence and Raft snapshot compaction             |
+---------------------------------------------------------------------------------------+
                                           |
                                  gRPC API / Watch Stream
                                           v
+---------------------------------------------------------------------------------------+
| LAYER 2: Application State-Machine Apply Layer (src/witness/state-machine.ts)         |
| - Implementation: TypeScript deterministic command reducer                            |
| - Responsibilities:                                                                   |
|   * Consumes strictly committed, linearized entries from etcd watch streams           |
|   * Pure transition function: f(State_{i-1}, Command_i) -> State_i                     |
|   * Monotonic index application guard: enforces i == last_applied_index + 1            |
|   * Enforces idempotency and rejects replayed or out-of-order log indices             |
|   * Dispatches side effects (KMS signing) ONLY on the current verified leader         |
|   * CRITICAL DESIGN PRINCIPLE: This layer is an APPLY layer, NOT a consensus layer.   |
|     It MUST NOT implement voting, terms, elections, or quorum logic.                  |
+---------------------------------------------------------------------------------------+
                                           |
                               Relational Projections / Audit
                                           v
+---------------------------------------------------------------------------------------+
| LAYER 3: Relational Projection & Historical Audit Store (PostgreSQL 16)               |
| - Implementation: src/witness/postgres-store.ts & Migration 003 SQL                   |
| - Responsibilities:                                                                   |
|   * Read-only relational projections for SQL queries, reporting, and client audits    |
|   * Append-only history table: witness_consensus_log                                  |
|   * Applied state tracker: witness_raft_state (last_applied_index, last_applied_term) |
|   * CRITICAL DESIGN PRINCIPLE: PostgreSQL is a DOWNSTREAM PROJECTION REPLICA.         |
|     It is NOT a consensus participant and provides NO distributed consensus safety.  |
+---------------------------------------------------------------------------------------+
```

### 2.1 Role of the Proposed `src/witness/state-machine.ts`
The proposed `src/witness/state-machine.ts` must be strictly an **Application State-Machine Apply Layer**.
- It must take committed log events emitted by etcd's linearizable log and apply them to local memory and PostgreSQL projections.
- It is **not** a second consensus implementation. Any attempt to introduce peer voting, term increments, or quorum logic into `state-machine.ts` would constitute a dangerous, redundant, and error-prone duplicate consensus layer.

---

## 3. Disputed Claims & Findings Matrix

Every contested claim from the initial assessment was audited against the codebase (`src/witness/`, `test/witness/`, and `src/witness/migrations/`):

| Claim # | Claim Evaluated | Classification | Source Evidence / Location | Finding & Required Correction |
| :---: | :--- | :---: | :--- | :--- |
| **C-01** | *PostgreSQL constraints provide Raft safety guarantees (Log Matching & State Machine Safety).* | **INCORRECT** | `src/witness/migrations/003_d3_consensus_state.sql` L130-144, L178-188 | Database constraints (`PRIMARY KEY`, `CHECK`) only reject conflicting local inserts. They do not prevent a partitioned node from proposing or committing conflicting logs in Raft. Raft safety is enforced solely by etcd quorum and WAL. PostgreSQL is a downstream sink. |
| **C-02** | *etcd revisions (`modRevision`) are sufficient fencing tokens for downstream operations.* | **INCORRECT** | `src/witness/cloud-kms-signer.ts` L434-450; `src/witness/grpc-service.ts` L494 | In `cloud-kms-signer.ts`, `signReceipt(preimage, fencingGeneration)` sends raw preimages to AWS/GCP KMS. The cloud KMS provider has no mechanism to validate etcd revisions. In `grpc-service.ts`, `fencingGen` is hardcoded as `const fencingGen = 1`. A raw revision fences nothing unless the verifier or downstream store actively validates it. |
| **C-03** | *Stale leaders cannot perform KMS signing after leadership changes.* | **INCORRECT (VULNERABILITY)** | `src/witness/cloud-kms-signer.ts` L434-450; `src/witness/grpc-service.ts` L675 | A former leader whose etcd lease has expired or been revoked can still execute `this.signer.signReceipt()`. AWS/GCP KMS will sign any payload provided valid IAM credentials exist. Without an immediate linearizable etcd check or term embedding in the signed preimage, stale signing can occur. |
| **C-04** | *PostgreSQL and etcd maintain consistency during execution.* | **UNSUPPORTED / DUAL-WRITE HAZARD** | `src/witness/grpc-service.ts` L496-681 | Witness operations use a 3-phase flow: Phase 1 (PG reserve), Phase 2 (KMS sign), Phase 3 (PG finalize). etcd is not even involved in `grpc-service.ts`. Even when wired to etcd, a crash between etcd CAS and PostgreSQL insert produces permanent divergence without a reconciliation outbox. |
| **C-05** | *Replay and recovery are idempotent.* | **PARTIALLY VERIFIED** | `src/witness/migrations/003_d3_consensus_state.sql` L157-173 | `witness_consensus_log` has an immutable trigger preventing `UPDATE`/`DELETE`. An identical replay `INSERT` throws a `23505 Unique Violation` unless written with `ON CONFLICT (epoch_id, log_index) DO NOTHING`. No state-machine replay function currently exists in TypeScript. |
| **C-06** | *Committed etcd entries can be applied more than once safely.* | **UNSUPPORTED** | `src/witness/` (No state machine exists) | There is currently no code reading or updating `witness_raft_state.last_applied_index` during request processing. Re-applying a committed entry (e.g. sequence increment or budget deduction) would result in double-counting without explicit monotonic guards. |
| **C-07** | *`last_applied_index` survives restart and supports deterministic recovery.* | **PARTIALLY VERIFIED** | `src/witness/migrations/003_d3_consensus_state.sql` L178-189 | The table `witness_raft_state` persists `last_applied_index` across DB restarts. However, the recovery loop that queries etcd starting from `last_applied_index + 1` does not exist in application code. |
| **C-08** | *`EtcdClientAdapter` handles compaction during watch resumption.* | **VERIFIED** | `src/witness/etcd-client-adapter.ts` L641-651 | When etcd returns `OUT_OF_RANGE` / `compacted`, the adapter halts reconnect retries and raises `EtcdCompactedError`. However, the application has no snapshot catch-up handler to recover from this error. |
| **C-09** | *Ambiguous transaction recovery is deterministic.* | **VERIFIED** | `src/witness/etcd-client-adapter.ts` L677-748 | Uses linearizable probe reads with payload/fingerprint matching, and returns `INDETERMINATE` until the bounded gRPC deadline has expired. |
| **C-10** | *Single-node test suite proves Raft partition and failover safety.* | **INCORRECT** | `test/witness/etcd-client-adapter.real.test.ts` L1-50 | All 26 tests run against a single etcd instance (`localhost:2379`). Quorum loss, partition minority behavior, and split-brain recovery have zero verification. |

---

## 4. State-Machine Design Requirements

To ensure `src/witness/state-machine.ts` operates strictly as an apply layer without architectural bloat or consensus confusion, it must be implemented against the following rigorous requirements:

### 4.1 Pure Deterministic Transition Contract
The state machine must be modeled as a pure reducer:
$$\text{apply}(\text{State}_{i-1}, \text{Command}_i) \longrightarrow (\text{State}_i, \text{Receipt}_i)$$
1. **Zero External I/O during State Calculation:** The reducer must not perform network calls, read system clocks, or generate random numbers. All inputs (timestamp, proposer ID, command payload) must originate from the canonical log entry.
2. **Monotonic Index Enforcement:**
   ```typescript
   if (command.logIndex !== this.lastAppliedIndex + 1n) {
     if (command.logIndex <= this.lastAppliedIndex) {
       // Idempotent duplicate: ignore without state mutation
       return { status: "ALREADY_APPLIED", index: command.logIndex };
     }
     // Gap detected: log sequence broken; trigger catch-up
     throw new StateMachineGapError(`Expected index ${this.lastAppliedIndex + 1n}, received ${command.logIndex}`);
   }
   ```
3. **Sequential Commit Ordering:** Even if watch events arrive out-of-order over the network, the state machine must buffer them and apply them strictly sequentially.

### 4.2 Handling Log Compaction & Snapshot Catch-up
When a witness node lags behind and etcd compacts its WAL, the watch stream fails with `EtcdCompactedError`. The state machine must handle this via a 3-step snapshot protocol:
1. **Catch-up Pause:** Suspend local signing and mark node health as `SYNCING`.
2. **Snapshot Fetch:** Read full state from the etcd key-space at the current linearizable `revision`.
3. **State & Projection Reset:** Atomically update PostgreSQL tables (`witness_epochs`, `witness_tickets`, `witness_raft_state`) to match the snapshot revision and resume the watch stream at `snapshotRevision + 1n`.

---

## 5. Fencing and KMS Integration Requirements

### 5.1 The Stale Leader Problem in KMS Signing
Because AWS KMS and GCP KMS are external, multi-tenant cloud services accessed via HTTPS, they **do not know about etcd cluster state, terms, or leases**. If a network partition isolates Node A (the former leader) while Nodes B and C elect Node B as the new leader, Node A can still successfully call `kmsClient.sign()` if instructed by a rogue or lagging client.

### 5.2 Mandatory Fencing Controls
To eliminate split-brain signing and ensure strict single-signer safety:

1. **Pre-Sign Linearizable Lease Check:**
   Before invoking `CloudKmsSigner.signReceipt()`, the leader node MUST perform a linearizable probe or verify its active etcd leader lease within a tight, bounded window ($\le 500\text{ms}$).
2. **Cryptographic Term & Revision Binding in Preimage:**
   The canonical preimage formatted for KMS signing (`formatCanonicalPreimage` in `src/witness/signing.ts`) MUST embed the etcd Raft term and log index:
   ```
   WEB3USER:WITNESS:RECEIPT:v2|<epoch_id>|<raft_term>|<log_index>|<sequence_number>|<authorization_id>|<binding_digest>
   ```
   *Benefit:* Any client or verifier observing a receipt with a stale Raft term can reject it immediately, rendering signatures by stale leaders cryptographically invalid.
3. **Double-Signing Prevention:**
   The state machine must maintain an in-memory and PostgreSQL record of signed log indices per epoch. If a signing request is received for an index that has already been signed, it must return the cached receipt and reject duplicate KMS invocation.

---

## 6. Persistence and Recovery Requirements

### 6.1 Eliminating the Dual-Write Divergence Hazard
Currently, writing to etcd and writing to PostgreSQL are independent operations. To guarantee that etcd (the consensus authority) and PostgreSQL (the query replica) remain synchronized:

```
[Client Proposes Command]
           |
           v
[1. Commit to etcd via CAS Transaction]
           |
     +-----+-----+
     |           | (etcd Commit Fails -> Fail Closed immediately)
     v           v
(Success)    [Return Error to Client]
     |
     v
[2. State Machine receives committed event via local etcd Watch]
     |
     v
[3. Apply to PostgreSQL in a single ACID Transaction]
     * INSERT INTO witness_consensus_log ... ON CONFLICT (epoch_id, log_index) DO NOTHING;
     * UPDATE witness_raft_state SET last_applied_index = command.log_index ...;
     * Update domain tables (witness_epochs, witness_receipts);
     * COMMIT;
```

*Architectural Invariant:* The application must **never** write uncommitted proposals to PostgreSQL. Writes to PostgreSQL must occur strictly downstream of etcd commit confirmation, driven by the deterministic State Machine event stream.

### 6.2 Crash Recovery Invariants
Upon node startup:
1. Connect to PostgreSQL and query `SELECT last_applied_index, last_applied_term FROM witness_raft_state WHERE cluster_id = $1 AND epoch_id = $2`.
2. Connect to etcd and check current cluster `revision`.
3. If `etcd_revision > last_applied_index`:
   - Replay missing entries from etcd watch/range starting at `startRevision = last_applied_index + 1n`.
   - Apply each entry sequentially to PostgreSQL.
4. Mark the witness node as `READY` only after `last_applied_index == etcd_revision`.

---

## 7. Revised Implementation Sequence

The implementation sequence proposed in the initial assessment had a critical flaw: attempting to build and verify Stage 2-B (State Machine Dispatch and Replay) before having a multi-node cluster harness (Stage 3-A).

The sequence is hereby restructured into a logical, dependency-ordered path:

```
========================================================================================
REVISED IMPLEMENTATION PHASING
========================================================================================

PHASE 1: Specification & In-Memory Contracts (Stage 2-B.1)
----------------------------------------------------------------------------------------
- Goal: Define pure contracts without infrastructure dependencies.
- Deliverables:
  * Define `ConsensusCommand`, `StateTransition`, and `StateMachine` interfaces.
  * Implement pure reducer in `src/witness/state-machine.ts`.
  * Unit tests with mocked out-of-order streams, duplicate indices, and gap detection.
- Gate: 100% unit test pass; zero I/O side effects in reducer.

PHASE 2: Multi-Node Local Cluster Harness (Stage 3-A)
----------------------------------------------------------------------------------------
- Goal: Provide an automated 3-node etcd cluster environment for integration testing.
- Deliverables:
  * Local cluster orchestrator (`scripts/test-etcd-cluster.mjs`).
  * Spawns 3 isolated etcd processes on ports 2379, 2389, 2399 with peer routing.
  * Programmatic controls: `killNode(id)`, `restartNode(id)`, `partitionNode(id)`.
- Gate: Automated bring-up, leader election, and clean teardown in CI/test runner.

PHASE 3: State Machine & Multi-Node Integration (Stage 2-B.2 & Stage 3-B)
----------------------------------------------------------------------------------------
- Goal: Connect State Machine to real multi-node etcd watches and test failure modes.
- Deliverables:
  * Connect `EtcdClientAdapter.watch()` to `StateMachine.apply()`.
  * Multi-node integration test: kill leader -> observe election -> verify watch resumes.
  * Partition test: minority node fails closed with `EtcdUnavailableError`.
  * Dual-store reconciliation: assert PostgreSQL `last_applied_index` matches etcd revision.
- Gate: All multi-node failure tests pass without manual intervention.

PHASE 4: End-to-End Consensus-to-KMS Witness Pipeline (Stage 3-C)
----------------------------------------------------------------------------------------
- Goal: Full system integration with Cloud KMS signing and gRPC service.
- Deliverables:
  * Integrate `CloudKmsSigner` with term-fenced preimages.
  * Wire `GrpcWitnessServer` to propose commands through etcd and wait for state apply.
  * End-to-end regression run: 760+ existing tests + new consensus test suite.
- Gate: Independent security audit pass; zero dual-signing under simulated partition.
========================================================================================
```

---

## 8. Remaining Blockers

The following unresolved blockers from `docs/web3user-engineering-roadmap-2026-11-03.md` directly gate production readiness for Milestone 13-D:

1. **Blocker 1 (Revocation Freshness SLA):** Revocations committed in etcd must propagate to all witness node memory caches within $\le 30\text{s}$. Unresolved until watch streaming is integrated with the state machine.
2. **Blocker 5 (Cross-Store Restore Reconciliation):** Restoring PostgreSQL from a backup while etcd retains later revisions results in silent projection corruption. An automated restore reconciliation tool is required.
3. **Blocker 6 (Live Authority Single Point of Failure):** Currently, `src/witness/grpc-service.ts` still queries PostgreSQL directly as the live authority, leaving PostgreSQL as a single point of failure. etcd must become the live authority.
4. **Blocker 7 (Measured RPO/RTO Drills):** Recovery Point Objective (RPO) and Recovery Time Objective (RTO) have never been measured under catastrophic node/cluster failure.
5. **Architectural Blocker (Hardcoded Fencing Generation):** `src/witness/grpc-service.ts` line 494 hardcodes `const fencingGen = 1;`. This must be replaced with real etcd term/revision tracking before multi-node deployment.

---

## 9. Recommended First Implementation Milestone

### Milestone Name: `M13-D-STAGE-2B1-STATE-MACHINE-CONTRACTS`

**Scope of First Action:**
Do **NOT** attempt multi-node cluster deployment or modify `grpc-service.ts` yet. The immediate next milestone should be strictly confined to:
1. Creating `src/witness/state-machine-types.ts` defining canonical types:
   - `ConsensusCommandPayload`
   - `CommittedConsensusEntry`
   - `StateMachineApplyResult`
2. Creating `src/witness/state-machine.ts` containing the pure in-memory state transition logic:
   - Gap detection and out-of-order rejection
   - Idempotent deduplication using `last_applied_index`
   - Replay verification
3. Creating unit tests in `test/witness/state-machine.test.ts` verifying all state transitions against synthesized log entries without requiring running databases or etcd clusters.

**Authorization Status:**
This challenge report is strictly advisory and diagnostic. Implementation of Milestone `M13-D-STAGE-2B1-STATE-MACHINE-CONTRACTS` requires **explicit user authorization**.
