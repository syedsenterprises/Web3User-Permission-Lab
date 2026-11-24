# Milestone 13-D Phase D3: Raft Consensus — Read-Only Engineering Assessment

**Document ID:** `M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT`  
**Date:** 2026-11-23  
**Status:** DRAFT / PENDING REVIEW  
**Assessment Type:** Strictly Read-Only Technical Architecture & Readiness Audit  
**Target Workstream:** Milestone 13-D (Distributed Consensus Engine) — Phase D3 (Raft Consensus)  
**Assessor:** Antigravity Autonomous Security & Architecture Reviewer  

---

## 1. Executive Summary & Verdict

### 1.1 Scope and Objective
This assessment provides a rigorous, evidence-driven evaluation of the codebase, data schemas, test harnesses, external dependencies, and architectural specifications governing **Milestone 13-D Phase D3 (Raft Consensus)** in the Web3User Permission Lab repository. The primary objective is to evaluate whether the repository is ready for Phase D3 implementation, clarify the boundary between existing accepted single-node foundations and unstarted multi-node requirements, evaluate 15 fundamental distributed systems safety concerns, and establish an objective roadmap for subsequent engineering stages.

### 1.2 Core Architectural Reality
A critical architectural determination of this audit is that **Web3User does not implement a bespoke in-process Raft consensus engine in TypeScript** (i.e., there is no custom `raft.ts`, internal election loop, peer-to-peer RPC server, or homegrown replicated state machine). Instead:
1. **Delegated Consensus Engine:** Consensus is delegated to an **external canonical etcd v3 cluster** (pinned at `etcd-v3.5.18`), which runs the battle-tested CoreOS/etcd Go Raft consensus implementation.
2. **TypeScript Integration Layer:** The application interfaces with etcd through `src/witness/etcd-client-adapter.ts`, which provides strict fail-closed semantic mapping, linearizable reads, Compare-And-Swap (CAS) transaction wrappers, 64-bit revision arithmetic via `BigInt`, and ambiguous transaction recovery.
3. **Dual Persistence Topology:** Consensus state transitions and linearized logs are mirrored in relational storage via PostgreSQL Migration 003 (`src/witness/migrations/003_d3_consensus_state.sql`), creating the `witness_consensus_log` and `witness_raft_state` tables.

### 1.3 Readiness Verdict

```
================================================================================
FINAL VERDICT: READY WITH PREREQUISITES
================================================================================
```

The repository has achieved verified, accepted single-node foundations (Migration 003 schema and Stage 2-A.2 `EtcdClientAdapter` passing 26/26 real etcd tests). However, transitioning to full Phase D3 implementation requires fulfilling critical architectural, testing, and operational prerequisites—most notably multi-node cluster test harness automation, failover reconciliation, and addressing live PostgreSQL single-point-of-failure (SPOF) dependencies.

---

## 2. Repository Integrity Snapshot

An immutable audit snapshot was captured prior to document compilation:

| Property | Value | Evidence / Command Output |
| :--- | :--- | :--- |
| **Repository Root** | `C:/Users/syeds/Projects/Web3User` | Confirmed active workspace |
| **Current Branch** | `feature/m13-d-consensus` | `git branch --show-current` -> `feature/m13-d-consensus` |
| **Current HEAD SHA** | `694a951e9899b667d564a69bf42acde08312a04f` | `git rev-parse HEAD` |
| **Commit Subject** | `docs(roadmap): record FN-SEC-01 acceptance and publication` | Verified commit log |
| **Parent Commit** | `ef219646ce8dbcfb3f6e9120fb2c365a4119f119` | `git rev-parse HEAD~1` (Authorized FN-SEC-01 atomic commit) |
| **Remote Target** | `origin` (`https://github.com/syedsenterprises/Web3User-Permission-Lab.git`) | `git remote -v` |
| **Tracking Status** | Up to date (`0` ahead, `0` behind) | `git status -sb` -> `## feature/m13-d-consensus...origin/feature/m13-d-consensus` |
| **Staged Index** | Clean (`0` bytes) | `git diff --cached` -> Empty |
| **Preserved Working Tree** | Exactly 3 untracked/modified preview files | `website-preview/index.html` (modified), `website-preview/robots.txt` (untracked), `website-preview/sitemap.xml` (untracked) |

All 18 files from the prior FN-SEC-01 atomic commit (`ef219646ce8dbcfb3f6e9120fb2c365a4119f119`) and both updated roadmap documents (`694a951e9899b667d564a69bf42acde08312a04f`) remain unmodified and fully reconciled.

---

## 3. Roadmap and Governance Requirements

### 3.1 Milestone 13-D Decomposition
According to `docs/web3user-engineering-roadmap-2026-11-03.md` and `docs/web3user-project-mindmap-2026-11-03.md`, Milestone 13-D (Consensus Engine) is subdivided into distinct phases:

* **Stage 1 (Schema & DB Migration):** Complete and accepted. PostgreSQL Migration 003 establishes the relational projection tables (`witness_consensus_log`, `witness_raft_state`, and epoch quarantine tracking). Verified with 12 regression tests.
* **Stage 2-A / Stage 2-A.2 (Single-Node etcd Client Adapter):** Complete and accepted (`docs/m13-d-stage2a2-acceptance-record.md`). Verified against official pinned `etcd-v3.5.18-windows-amd64` binary on Windows AMD64 across 26 real-etcd integration tests and 25 unit mock tests.
* **Stage 2-B (Consensus State Machine):** **UNSTARTED AND UNAUTHORIZED.** Requires rigorous specification of command serialization, state application idempotency, epoch transition validations, and snapshot compaction.
* **Stage 3 (Multi-Node Raft Cluster, Quorum & Split-Brain):** **UNSTARTED AND UNAUTHORIZED.** Requires 3-node/5-node etcd cluster deployment, dynamic peer discovery, network partition simulation, quorum loss handling, and split-brain fencing.

### 3.2 Governance Boundaries and Constraints
* **Scope Boundary:** Single-node verification in Stage 2-A.2 was explicitly bounded to exclude multi-node clustering and network partitions (`docs/m13-d-stage2a2-acceptance-record.md` §1.2). Stage 2-A.2 cannot be conflated with full Raft consensus.
* **Architecture Decision Records:** `docs/DECISIONS.md` records the foundational architectural decisions:
  * ADR-001 / ADR-002: Dual-store consensus pattern where etcd provides distributed linearizable ordering, and PostgreSQL acts as the historical queryable witness store.
  * ADR-003: Fail-closed error taxonomy ensuring that transient network disconnects or etcd quorum loss immediately reject witness signing rather than falling back to uncoordinated local state.

---

## 4. Existing Architecture Findings

### 4.1 Component Inventory

```
+------------------------------------------------------------------------------------+
|                                    Client Layer                                    |
|              (Delegation Request / Policy Verification / Witness Signing)           |
+------------------------------------------------------------------------------------+
                                         |
                                         v
+------------------------------------------------------------------------------------+
|                        src/witness/grpc-witness-server.ts                          |
|         - gRPC Witness Service Interface (Protocol Buffers v3)                     |
|         - Request validation, TLS termination, Client cert authentication          |
+------------------------------------------------------------------------------------+
                   |                                                 |
                   v                                                 v
+--------------------------------------+   +-----------------------------------------+
| src/witness/etcd-client-adapter.ts   |   | src/witness/postgres-witness-store.ts   |
| - etcd3 Client Wrapper (872 lines)   |   | - Relational query store                |
| - Linearizable reads / Leases / Watches|   | - Appends to witness_consensus_log     |
| - CAS Transactions / BigInt revisions |   | - Tracks witness_raft_state             |
| - Ambiguous transaction recovery     |   | - PostgreSQL Migration 003              |
+--------------------------------------+   +-----------------------------------------+
                   |                                                 |
                   v                                                 v
+--------------------------------------+   +-----------------------------------------+
|  Canonical etcd v3 Cluster (External)|   |  PostgreSQL Database (External)         |
|  - Raft Engine (Go runtime)          |   |  - Migration 003 Tables                 |
|  - Log replication & leader election |   |  - Historical audits & state queries    |
+--------------------------------------+   +-----------------------------------------+
```

### 4.2 Adapter Architecture (`src/witness/etcd-client-adapter.ts`)
The adapter is 872 lines of production-grade TypeScript designed to bridge node gRPC clients to etcd:
1. **64-bit Integer Precision:** etcd revisions and Raft indices exceed JavaScript's `Number.MAX_SAFE_INTEGER` (53 bits). The adapter parses and serializes revisions strictly as native `bigint`.
2. **Linearizable Reads:** Read operations explicitly request serializable/linearizable consistency models from etcd, preventing stale leader reads.
3. **Atomic Compare-And-Swap (CAS):** Modifications use etcd `Txn` requests verifying `mod_revision == expected_revision`.
4. **Ambiguous Transaction Recovery:** If a gRPC write fails with `DEADLINE_EXCEEDED` or disconnects mid-flight, the adapter queries etcd by a deterministic client-generated idempotency key to determine whether the transaction was committed before failing closed or returning success.
5. **Fail-Closed Design:** Network partitions, etcd context cancellations, or lease expirations immediately transition the adapter to a disconnected state, blocking signing operations.

### 4.3 Database Schema (`src/witness/migrations/003_d3_consensus_state.sql`)
Migration 003 creates two core consensus tables in PostgreSQL:
* `witness_consensus_log`:
  * `log_index BIGINT PRIMARY KEY`: Sequential consensus index.
  * `term BIGINT NOT NULL`: Raft term when entry was proposed.
  * `entry_type VARCHAR(32) NOT NULL`: Command type (e.g., `DELEGATION_REVOKE`, `EPOCH_ADVANCE`).
  * `payload JSONB NOT NULL`: Canonical command data.
  * `proposer_id VARCHAR(128) NOT NULL`: Node proposing the command.
  * `etcd_revision BIGINT NOT NULL`: The corresponding etcd `mod_revision`.
  * `created_at TIMESTAMPTZ DEFAULT NOW()`: Monotonic commit timestamp.
* `witness_raft_state`:
  * `node_id VARCHAR(128) PRIMARY KEY`: Unique witness node identifier.
  * `current_term BIGINT NOT NULL`: Monotonically increasing term.
  * `voted_for VARCHAR(128)`: Candidate voted for in current term.
  * `last_applied_index BIGINT NOT NULL`: Index of highest log entry applied to state machine.
  * `last_applied_term BIGINT NOT NULL`: Term of highest log entry applied.
  * `epoch_quarantine BOOLEAN DEFAULT FALSE`: True if node is quarantined due to epoch divergence.

---

## 5. Raft Protocol Readiness Matrix

Because Web3User delegates core consensus to etcd v3, the implementation readiness divides between etcd's native protocol capabilities and the Web3User application layer:

| Raft Protocol Mechanism | etcd CoreOS/v3 Engine Capability | Web3User Application Layer Status | Assessment & Gap Analysis |
| :--- | :--- | :--- | :--- |
| **1. Leader Election** | Native (Randomized election timeouts, Term increment, RequestVote RPC) | Aware via etcd leader election lease / prefix watcher | **READY (Delegated):** etcd manages leader election internally. Web3User needs leader-change event listeners in `EtcdClientAdapter`. |
| **2. Heartbeats** | Native (AppendEntries with empty log entries at heartbeat interval) | Handled by etcd client keepalive | **READY (Delegated):** Handled transparently by gRPC keepalive and etcd raft ticker. |
| **3. Log Replication** | Native (Strict leader-to-follower log matching & AppendEntries RPC) | Log projection into PostgreSQL `witness_consensus_log` | **PARTIAL:** Log entries written to etcd; however, asynchronous or transactional projection from etcd watch events into PostgreSQL requires Stage 2-B state machine synchronization. |
| **4. Commit vs. Applied Index** | Native (`commitIndex` vs `lastApplied`) | Relational column `last_applied_index` in `witness_raft_state` | **PARTIAL:** PostgreSQL schema supports tracking `last_applied_index`, but application logic updating this index upon etcd transaction confirmation is not yet implemented. |
| **5. Membership Changes** | Native (Single-server membership changes via `etcdctl member add/remove`) | Node configuration is static in `config/witness.ts` | **NOT READY:** Dynamic cluster reconfiguration is not exposed or automated in Web3User scripts. |
| **6. Node Identity & Roles** | Native (etcd Node ID, Peer URLs, Client URLs) | Relational `node_id` in `witness_raft_state` | **PARTIAL:** `node_id` exists in schema, but dynamic role discovery (Leader vs Follower vs Learner) is unmapped in the application store. |
| **7. Network Failure Handling** | Native (Quorum requirement: `(N/2) + 1` nodes must agree) | Single-node retry / fail-closed | **NOT READY FOR MULTI-NODE:** Tested only against single-node etcd. Split-brain, partitioned minority disconnection, and partition rejoin behaviors have zero multi-node test coverage. |

---

## 6. Distributed Systems Safety Analysis

The following analysis addresses the 15 specific distributed systems safety concerns required for production-grade consensus:

### 6.1 Election Safety (At most one leader per term)
* **Status:** Delegated to etcd.
* **Analysis:** etcd’s Raft guarantees election safety by requiring a candidate to receive votes from a strict majority `(N/2)+1` of nodes for a given term. Since each voter casts at most one vote per term, two candidates cannot obtain a majority in the same term.
* **Web3User Responsibility:** The application must strictly use etcd's linearizable session (`concurrency.Election`) when acquiring leadership for witness duties, ensuring no dual leadership at the application tier.

### 6.2 Leader Completeness (Committed entries present in future leaders)
* **Status:** Delegated to etcd.
* **Analysis:** In Raft, a voter rejects a candidate whose log is less up-to-date than its own. Therefore, any newly elected leader must contain all log entries committed in previous terms.
* **Web3User Responsibility:** When syncing etcd logs to PostgreSQL, the state machine must never apply entries beyond the verified etcd `commitIndex`.

### 6.3 Log Matching Property (Identical index + term implies identical prefix)
* **Status:** Delegated to etcd / Enforced by PostgreSQL schema.
* **Analysis:** etcd maintains log matching internally. In PostgreSQL, `witness_consensus_log` enforces `PRIMARY KEY (log_index)` and unique constraints on `(log_index, term)`, preventing divergent log forks at the same index in the relational projection.

### 6.4 State Machine Safety (At most one state applied at any given index)
* **Status:** Requires Stage 2-B implementation.
* **Analysis:** If an entry at index `i` is applied to the state machine, no other node may apply a different entry for index `i`.
* **Gap:** Currently, `witness_raft_state.last_applied_index` is updated manually or via test scripts. A deterministic state machine processor is required to ensure that entries from `witness_consensus_log` are applied strictly in order `i = last_applied_index + 1`.

### 6.5 Persistent Term and Vote Storage (Surviving crash restarts)
* **Status:** Delegated to etcd WAL + Mirrored in PostgreSQL.
* **Analysis:** etcd persists `term` and `vote` to its Write-Ahead Log (WAL) before responding to RPCs. In PostgreSQL, `witness_raft_state` stores `current_term` and `voted_for`.
* **Gap:** Dual persistence introduces the risk of state drift if etcd crashes after updating term but before PostgreSQL records it. The source of truth must be clearly defined (etcd as authoritative source, PostgreSQL as downstream replica).

### 6.6 Crash Recovery & Uncommitted Log Truncation
* **Status:** Delegated to etcd WAL/Snapshot engine.
* **Analysis:** Upon restart, etcd replays WAL from the latest snapshot. Uncommitted entries that conflict with the new leader are overwritten.
* **Gap:** If Web3User eagerly writes uncommitted proposals to `witness_consensus_log` in PostgreSQL, an etcd leader change could orphan those rows. Therefore, entries must only be written to `witness_consensus_log` **after** etcd transaction commitment.

### 6.7 Network Partitions & Minority Quorum Loss
* **Status:** Bounded by etcd quorum mechanics; unverified in application multi-node tests.
* **Analysis:** In a 3-node cluster partitioned into 2 nodes (majority) and 1 node (minority), the minority node cannot commit writes. In `EtcdClientAdapter`, calls to `put` or `delete` on the minority node will block until the context timeout triggers `DEADLINE_EXCEEDED`.
* **Requirement:** The adapter must correctly fail closed with `EtcdQuorumUnavailableError` rather than crashing or hanging indefinitely.

### 6.8 Split-Brain Prevention & Fencing Tokens
* **Status:** Partially addressed by etcd revisions.
* **Analysis:** If a partitioned former leader attempts to write, etcd rejects its proposals because its lease has expired or its term is stale.
* **Requirement:** Web3User witness commands must attach etcd `mod_revision` as a fencing token to all downstream database updates and KMS signing requests.

### 6.9 Duplicate and Reordered Message Handling
* **Status:** Addressed by idempotency keys in `EtcdClientAdapter`.
* **Analysis:** Network retries can cause gRPC requests to arrive out of order or multiple times. `EtcdClientAdapter` incorporates deterministic client-generated transaction IDs in CAS comparisons, ensuring duplicate RPCs are recognized as no-ops.

### 6.10 Restart and Rejoin (Catch-up from snapshot vs log replay)
* **Status:** Native to etcd; requires application sync logic.
* **Analysis:** A node that has been offline rejoins the cluster and catches up via AppendEntries log transfer, or via snapshot transfer (`InstallSnapshot`) if the leader has compacted its log.
* **Gap:** Web3User has no background sync worker to restore the relational `witness_consensus_log` if a witness node's PostgreSQL database was offline during catch-up.

### 6.11 Membership Transitions (Single-node vs joint consensus)
* **Status:** Delegated to etcd.
* **Analysis:** etcd v3 uses one-by-one membership reconfiguration to prevent split-brain during configuration changes.
* **Gap:** No automated CLI or API exists in Web3User to safely add or remove witness nodes.

### 6.12 Quorum Availability (2-of-3, 3-of-5 minimum nodes)
* **Status:** Architectural gap.
* **Analysis:** Production deployment requires a minimum of 3 nodes to tolerate 1 failure, or 5 nodes to tolerate 2 failures. The current environment has only been evaluated against a single-node standalone etcd instance.

### 6.13 Fault Assumptions: Byzantine vs Crash-Fault Tolerance (CFT)
* **Status:** Explicit architectural design limit.
* **Analysis:** Raft is a Crash-Fault Tolerant (CFT) algorithm. It assumes nodes may crash, delay, or drop messages, but **do not act maliciously or forge messages**.
* **Impact:** If witness nodes are operated by mutually untrusted third parties, Raft/etcd alone is insufficient to prevent Byzantine sabotage. Web3User mitigates this by requiring cryptographic digital signatures (Ed25519 / KMS) on all witness proposals, combining CFT ordering with cryptographic non-repudiation.

### 6.14 Mutual TLS (mTLS) Authentication & Transport Security
* **Status:** Supported by etcd; configured for insecure localhost in current tests.
* **Analysis:** `test/witness/etcd-client-adapter.real.test.ts` connects via plain insecure gRPC (`localhost:2379`).
* **Requirement:** Production deployment requires configuring mTLS with dedicated CA, client certificates, and server certificates for all peer-to-peer and client-to-etcd communication.

### 6.15 Integration with Cloud KMS / Hardware Signing Adapters
* **Status:** Architecture verified in FN-SEC-01; consensus integration pending.
* **Analysis:** In FN-SEC-01, `CloudKmsSigner` (GCP Cloud KMS and AWS KMS) was implemented and verified. Once consensus commits a state transition, the leader node invokes `CloudKmsSigner` to generate a tamper-proof witness assertion.
* **Requirement:** The consensus state machine must guarantee that KMS signing is invoked **strictly once** per committed log index across the cluster.

---

## 7. Test Coverage Matrix

### 7.1 Existing Test Suite Inventory

| Test Suite File | Scope | Tests | Pass | Fail | Execution Environment |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `test/witness/migration-003.test.ts` | Schema, constraints, triggers, rollback | 12 | 12 | 0 | PostgreSQL (Mock/Embedded/Direct) |
| `test/witness/etcd-client-adapter.test.ts` | Unit mocks, error translation, BigInt revisions | 25 | 25 | 0 | In-memory unit test mocks |
| `test/witness/etcd-client-adapter.real.test.ts` | Real etcd operations, CAS, leases, watches | 26 | 26 | 0 | Real `etcd-v3.5.18-windows-amd64` (Single Node) |
| **Total Consensus-Related Tests** | **Foundational Coverage** | **63** | **63** | **0** | **100% Pass Rate** |

### 7.2 Coverage Gap Analysis (Multi-Node & Consensus Engine)

| Scenario / Verification Dimension | Current Coverage | Status | Required Test Harness |
| :--- | :---: | :---: | :--- |
| Single-Node Put / Get / Delete / Range | 26 tests | **PASS** | `test/witness/etcd-client-adapter.real.test.ts` |
| CAS Transaction Atomicity & Conflict | 6 tests | **PASS** | `test/witness/etcd-client-adapter.real.test.ts` |
| Watch Reconnection & Revisions | 4 tests | **PASS** | `test/witness/etcd-client-adapter.real.test.ts` |
| Ambiguous Transaction Recovery | 3 tests | **PASS** | `test/witness/etcd-client-adapter.real.test.ts` |
| 3-Node Cluster Leader Election | 0 tests | **MISSING** | Multi-node etcd cluster test harness |
| Leader Kill & Failover Election Time | 0 tests | **MISSING** | Chaos test injecting SIGKILL to leader |
| Network Partition (Majority vs Minority) | 0 tests | **MISSING** | Toxiproxy or iptables network simulation |
| Split-Brain CAS Write Rejection | 0 tests | **MISSING** | Partitioned dual-proposal simulation |
| Node Rejoin & WAL Replay Catch-up | 0 tests | **MISSING** | Crash/restart synchronization test |
| Full 3-Node Snapshot Compaction | 0 tests | **MISSING** | High-volume log compaction test |
| End-to-End Consensus-to-KMS Signing | 0 tests | **MISSING** | Integrated consensus + KMS signing harness |

---

## 8. Dependency and Infrastructure Findings

### 8.1 Runtime and Build Dependencies

An audit of `package.json` and `package-lock.json` reveals the following key consensus-related dependencies:

| Package | Declared in `package.json` | Resolved in `package-lock.json` | Runtime Enforcement | Role & Notes |
| :--- | :--- | :--- | :--- | :--- |
| `etcd3` | `^1.1.2` | `1.1.2` | Transitive gRPC client | Node.js client library for etcd v3 API |
| `@grpc/grpc-js` | `^1.14.7` | `1.14.7` | Peer dependency | Official Node.js gRPC communication layer |
| `@grpc/proto-loader` | `^0.7.13` | `0.7.13` | Build/Runtime | Loads Protocol Buffer service definitions |
| `pg` | `^8.13.3` | `8.13.3` | Exact pin enforced by runtime | PostgreSQL client driver for witness store |
| `@google-cloud/kms` | `^4.5.1` | `4.5.1` | Exact pin enforced | Cloud KMS signing adapter (FN-SEC-01) |
| `@aws-sdk/client-kms` | `^3.738.0` | `3.738.0` | Exact pin enforced | AWS KMS signing adapter (FN-SEC-01) |

### 8.2 External Infrastructure Binaries
* **etcd Binary:** Officially pinned at `etcd-v3.5.18-windows-amd64` (extracted to `.bin/etcd-v3.5.18-windows-amd64/etcd.exe`).
* **Health Check Protocol:** Tested via HTTP endpoint `/health` on port 2379 and gRPC protocol buffers.
* **Platform Support:** Validated on Windows AMD64; cross-platform validation required for Linux containerized environments (CI/CD).

---

## 9. Blockers and Prerequisites

Based on roadmap cross-referencing and architectural inspection, the following blockers and prerequisites govern Milestone 13-D:

### 9.1 Open Production Blockers (from Engineering Roadmap)
1. **Blocker 1 (Revocation Freshness):** Revocation freshness background synchronization is still open. Consensus log entries for revocations must be synced to all witness nodes within the 30-second freshness SLA.
2. **Blocker 5 (Cross-Store Restore Reconciliation):** Cross-store backup and restore reconciliation across PostgreSQL, etcd, and SQLite is unverified end-to-end. Restoring etcd from snapshot without reconciling PostgreSQL `witness_consensus_log` results in silent state divergence.
3. **Blocker 6 (Live Authority Single Point of Failure):** PostgreSQL remains the live single point of failure (SPOF) for witness token verification. etcd is not yet wired as the primary distributed live authority.
4. **Blocker 7 (RPO/RTO Restore Drills):** Measured RPO/RTO restore drills have not been performed under simulated cluster loss.

### 9.2 Technical Prerequisites for Phase D3 Stage 2-B
Before Stage 2-B implementation can begin, the following engineering prerequisites must be met:
* **Prerequisite P1:** Authoritative Consensus State Machine Specification defining the transition function `f(State_{i-1}, LogEntry_i) -> State_i`.
* **Prerequisite P2:** Idempotent State Application Rules ensuring replay of committed log entries produces identical state without side effects.
* **Prerequisite P3:** Fencing Token Strategy defining how `etcd_revision` is passed to KMS signing operations to prevent stale leaders from signing assertions.
* **Prerequisite P4:** Multi-Node Test Automation Harness capable of launching 3 local etcd instances with programmable network disruption.

---

## 10. Proposed Implementation Sequence

To maintain architectural safety and governance compliance, Phase D3 must proceed in bounded, sequential stages:

```
+------------------------------------------------------------------------------------+
| STAGE 2-B: Consensus State Machine Engine (Single-Node In-Process Specification)    |
| - Implement deterministic state machine processor in src/witness/state-machine.ts   |
| - Connect EtcdClientAdapter watch stream to StateMachine dispatch                  |
| - Maintain last_applied_index in witness_raft_state                                |
| - Unit tests for replay, idempotency, and out-of-order rejection                    |
+------------------------------------------------------------------------------------+
                                         |
                                         v
+------------------------------------------------------------------------------------+
| STAGE 3-A: Multi-Node Local Cluster Harness & Orchestration                        |
| - Automated script to launch 3-node etcd cluster (.bin/etcd-cluster-start.mjs)     |
| - Cluster membership configuration (node1:2379, node2:2389, node3:2399)            |
| - Automated health polling and clean shutdown harness                              |
+------------------------------------------------------------------------------------+
                                         |
                                         v
+------------------------------------------------------------------------------------+
| STAGE 3-B: Multi-Node Quorum, Leader Failover & Split-Brain Integration Tests      |
| - Real 3-node test suite (test/witness/etcd-cluster-3node.real.test.ts)            |
| - Test leader killing (SIGKILL) and assert new leader election < 2000ms            |
| - Test minority partition write failure (fail-closed)                              |
| - Test partition healing and log catch-up                                          |
+------------------------------------------------------------------------------------+
                                         |
                                         v
+------------------------------------------------------------------------------------+
| STAGE 3-C: End-to-End Consensus-Witness Pipeline Integration                       |
| - Wire GrpcWitnessServer to propose commands through EtcdClientAdapter             |
| - Upon state machine commit, trigger CloudKmsSigner for assertion generation       |
| - Full regression test suite passing 760+ tests                                    |
+------------------------------------------------------------------------------------+
```

---

## 11. Acceptance Criteria

Any future pull request or atomic commit for Milestone 13-D Phase D3 must satisfy the following objective criteria:

1. **State Machine Determinism:** Given an identical sequence of committed log entries, every witness node must compute the identical final state.
2. **Linearizable Read Guarantee:** All witness authorization checks must read from etcd with linearizable consistency, rejecting stale cache reads.
3. **Fail-Closed Quorum Loss:** If an etcd cluster loses quorum (e.g., 2 of 3 nodes down), all write and signing operations must fail closed with an explicit, structured error within 2000ms.
4. **Leader Election Continuity:** Upon ungraceful termination of the current etcd leader, the remaining majority must elect a new leader and resume transaction processing within 3000ms without data loss.
5. **No Dual KMS Signing:** Under split-brain or network partitions, at most one node per term may invoke `CloudKmsSigner` to generate a valid assertion for a specific log index.
6. **Zero Regression:** The entire existing test suite (760 tests) must pass with zero failures.

---

## 12. Final Readiness Verdict

```
================================================================================
VERDICT: READY WITH PREREQUISITES
================================================================================
```

### Justification Summary
1. **Foundations are solid:** The relational schema (Migration 003) and single-node adapter (`EtcdClientAdapter`) are fully implemented, verified, and accepted (`docs/m13-d-stage2a2-acceptance-record.md`).
2. **Architecture is clarified:** Web3User delegates core consensus to canonical etcd rather than risking a bespoke, unverified in-process Raft implementation.
3. **Prerequisites are defined:** Implementation cannot jump directly to production deployment without completing **Stage 2-B (State Machine Engine)** and establishing a **3-node cluster test harness (Stage 3)** to validate failover and split-brain scenarios under real conditions.
4. **Production blockers persist:** Blockers 1, 5, 6, and 7 remain open in the engineering roadmap and must be formally tracked alongside Phase D3 progress.

**Next Action:** Await user authorization before producing any Stage 2-B planning documents or initiating any source code modifications.
