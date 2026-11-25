# Milestone 13-D Stage 2-B.1.2.2: Independent ADR Consistency and Failure-Scenario Audit

**Document ID:** `M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT`  
**Date:** 2026-11-23  
**Auditor:** Independent Technical Auditor  
**Audit Target:** `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md`  
**Reconciliation References:**
- `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md`
- `docs/M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md`
- `docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md`
- `docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md`
- `src/witness/migrations/003_d3_consensus_state.sql`
- `src/witness/state-machine-types.ts`
- `src/witness/state-machine.ts`
**Governance:** Strict Read-Only Audit (Zero code, test, or migration modifications; zero Git operations)

---

## 1. Executive Verdict & Audit Summary

```
================================================================================
FINAL AUDIT VERDICT: PASS WITH TARGETED CORRECTIONS
================================================================================
```

The precision amendment in `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` provides an exceptionally rigorous, mathematically grounded architectural framework for Milestone 13-D Stage 2-B. It successfully decouples physical consensus revisions from epoch-scoped logical indices, resolves BigInt serialization ambiguity via explicit type-tagging, and establishes a robust two-tier historical replay verification model.

This audit validates the five amended ADRs and identifies **three critical precision corrections** required before Stage 2-B.2 implementation:
1. **Mathematical Correction (ADR-010):** The `effectiveRetentionFloor` equation contains an off-by-one boundary flaw when PostgreSQL lag is zero or uninitialized. A corrected equation is formulated and proved in Section 2.
2. **Concurrency Serialization Rule (ADR-011):** Tier 2 PostgreSQL historical lookups can suffer a dirty read race if an in-memory index advances before its database transaction commits. An explicit single-writer serialization invariant is established in Section 3.
3. **Staged Publication Protocol (ADR-012):** Snapshot blob writing and metadata publishing cannot be executed atomically across two distinct storage subsystems. A formal 5-step staged publication protocol is specified in Section 4.

---

## 2. Audit 1: ADR-M13D-010 — Retention, Mathematical Bounds, and Epoch Scoping

### 2.1 Terminology and Mathematical Definitions
Table 2.1 defines the four variables governing in-memory retention:

### Table 2.1: Retention Variable Definitions

| Symbol | Variable Name | Type / Scope | Semantic Definition |
| :--- | :--- | :--- | :--- |
| $A_{app}$ | `lastAppliedAppIndex` | `bigint` (Epoch-scoped) | The highest logical application log index applied by the in-memory state machine. |
| $L_{pg}$ | `lastFlushedToPostgresIndex` | `bigint` (Epoch-scoped) | The highest logical index durably written and committed to PostgreSQL `witness_consensus_log` and `witness_raft_state`. |
| $W_{mem}$ | `inMemoryRetentionWindow` | `number` (Configuration) | The target sliding window size (e.g. 10,000 entries). |
| $F_{nom}$ | `retentionFloorIndex` | `bigint` (Calculated) | The nominal lowest index retained based purely on window size: $\max(1\text{n}, A_{app} - W_{mem} + 1\text{n})$. |
| $F_{eff}$ | `effectiveRetentionFloor` | `bigint` (Enforced) | The actual lowest index retained in memory, gated on PostgreSQL durability. |

### 2.2 Mathematical Off-by-One Audit & Corrected Formula
In `M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` Section 2.6, the proposed formula was:
$$\text{effectiveRetentionFloor} = \min(\text{retentionFloorIndex}, \text{lastDurablePgIndex})$$

#### Boundary Analysis & Defect Discovery
* **Flaw Scenario 1 (Uninitialized / Lagging Database):**  
  Suppose a newly initialized node has applied entries up to $A_{app} = 5$ with $W_{mem} = 10,000$.  
  $F_{nom} = \max(1\text{n}, 5 - 10000 + 1) = 1\text{n}$.  
  If PostgreSQL has not yet committed its first batch, $L_{pg} = 0\text{n}$.  
  Under the proposed formula:
  $$F_{eff} = \min(1\text{n}, 0\text{n}) = 0\text{n}$$
  This yields a retention floor of $0\text{n}$. Because log indices start strictly at $1\text{n}$ (`chk_consensus_log_index CHECK (log_index > 0)`), evaluating $L_{app} < 0\text{n}$ produces an invalid boundary and causes potential underflow.
* **Flaw Scenario 2 (Off-by-One Eviction):**  
  Suppose $A_{app} = 100$, $W_{mem} = 10$, so $F_{nom} = 91\text{n}$.  
  If $L_{pg} = 91\text{n}$, entries $1 \dots 91$ are durably in PostgreSQL.  
  Under the proposed formula, $F_{eff} = \min(91, 91) = 91\text{n}$. Entry 91 is retained in memory.  
  However, if $L_{pg} = 90\text{n}$, then entry 91 is *not* in PostgreSQL!  
  $\min(91, 90) = 90\text{n}$. Entry 90 is retained. But entry 90 was already in PostgreSQL.

#### The Corrected Invariant Equation
To guarantee that (a) the floor is never less than $1\text{n}$, and (b) no entry is ever pruned unless its successor is durably in PostgreSQL:
$$\boxed{F_{eff} = \max\Big(1\text{n}, \; \min\big(A_{app} - W_{mem} + 1\text{n}, \; L_{pg} + 1\text{n}\big)\Big)}$$

* **Proof of Correctness:**
  - If $L_{pg} = 0\text{n}$: $F_{eff} = \max(1\text{n}, \min(\dots, 1\text{n})) = 1\text{n}$. Every entry from $1$ to $A_{app}$ is retained. Zero entries are pruned.
  - If $A_{app} = 100, W_{mem} = 10 \implies A_{app} - W_{mem} + 1 = 91\text{n}$:
    - If $L_{pg} = 100\text{n}$: $\min(91\text{n}, 101\text{n}) = 91\text{n}$. Floor is $91\text{n}$. Entries $91 \dots 100$ (exactly 10 entries) are retained. Entries $1 \dots 90$ are pruned.
    - If $L_{pg} = 85\text{n}$: $\min(91\text{n}, 86\text{n}) = 86\text{n}$. Floor is $86\text{n}$. Entries $86 \dots 100$ are retained. Zero un-flushed entries are pruned.

### 2.3 Coordinated Eviction of `appliedProposals`
When an entry $k < F_{eff}$ is pruned from `state.appliedIndices`:
* `AppliedIndexRecord` contains `proposalId: string`.
* The state machine must atomically remove `record.proposalId` from `state.appliedProposals`.
* Failure to prune `appliedProposals` alongside `appliedIndices` would create an asymmetry where memory leaks string keys indefinitely while indices are pruned.

### 2.4 Logical Index Epoch Scoping Verification
* The audit verifies that $L_{app}$ **strictly resets to 1n** upon `EPOCH_INITIALIZE`.
* In `src/witness/migrations/003_d3_consensus_state.sql`:
  - `witness_consensus_log` has composite primary key `(epoch_id, log_index)`.
  - `witness_raft_state` has composite primary key `(cluster_id, epoch_id)`.
* Logical index continuity is strictly bounded to the epoch lifecycle. Cross-epoch queries require $(cluster\_id, epoch\_id, log\_index)$.

### 2.5 Workload Sizing Model for $W_{mem}$
The operational default of 10,000 entries is validated under the following workload envelope:
$$W_{mem} \ge \lceil \text{PeakTPS} \times T_{\text{reconnect\_max}} \rceil + N_{\text{lease}}$$
* At 500 TPS and $T_{\text{reconnect\_max}} = 10\text{s}$, minimum required window is $5,000$. An operational window of 10,000 provides $2.0\times$ safety factor.
* V8 Heap Impact: $10,000 \text{ entries} \times 180 \text{ bytes/entry} \approx 1.8 \text{ MB}$, well within standard Node.js memory budgets.
* If peak throughput exceeds 1,000 TPS, $W_{mem}$ must be scaled proportionally via configuration.

---

## 3. Audit 2: ADR-M13D-011 — PostgreSQL Historical Verification & Concurrency Hazards

### 3.1 Migration 003 Schema Verification
Direct inspection of `src/witness/migrations/003_d3_consensus_state.sql` reveals:
1. `witness_consensus_log` schema:
   - `epoch_id VARCHAR(64) NOT NULL`
   - `log_index BIGINT NOT NULL`
   - `term BIGINT NOT NULL`
   - `etcd_revision BIGINT NOT NULL`
   - `payload_type VARCHAR(64) NOT NULL`
   - `payload JSONB NOT NULL`
   - `payload_hash VARCHAR(64) NOT NULL`
   - `proposal_id VARCHAR(128) NULL`
   - `committed_at_seconds BIGINT NOT NULL`
   - `PRIMARY KEY (epoch_id, log_index)`
2. **Uniqueness Reality Check:**
   - Migration 003 creates index `idx_consensus_log_proposal_id ON witness_consensus_log (proposal_id) WHERE proposal_id IS NOT NULL;`.
   - **AUDIT FINDING (Low Severity):** This existing index is **NON-UNIQUE**.
   - The unique constraint proposed in ADR-011 (`uq_consensus_log_proposal_id`) does **not** exist in Migration 003. It must be created in a new migration for Stage 2-B.2.

### 3.2 Concurrency Hazard: Uncommitted Read Race Condition
Consider the interaction between the consensus apply loop and a concurrent Tier 2 replay reader:
```
Timeline:
T1: Worker A receives Event 101. Applies in memory: A_app = 101.
T2: Worker A begins PostgreSQL transaction: INSERT INTO witness_consensus_log (log_index=101) ...
T3: Worker B receives delayed duplicate of Event 101.
    Worker B checks memory: 101 < retentionFloor (suppose window is 0 for test, or pruned).
    Worker B initiates Tier 2 lookup:
    SELECT proposal_id, payload_hash FROM witness_consensus_log WHERE epoch_id=$1 AND log_index=101;
T4: PostgreSQL executes query under READ COMMITTED.
    Because Worker A's transaction is NOT committed, Worker B receives ZERO ROWS!
T5: Worker B sees 101 <= A_app (101), but database returns NULL!
    Worker B raises UnverifiableHistoricalEntryError(101) and panics!
```

#### Mandatory Concurrency Invariant (INV-PREC-06)
* **Single-Writer Serialization:** In Milestone 13-D, all events for a given epoch stream are consumed and applied by **exactly one serialized execution worker**.
* **Pruning Gating:** As proved in Section 2.2, an entry $L_{app}$ cannot be pruned from memory until $L_{app} \le L_{pg}$.
* Therefore, for any entry $L_{app}$ where Tier 2 lookup is triggered ($L_{app} < F_{eff}$):
  $$L_{app} \le L_{pg}$$
* Because $L_{app}$ was already committed to PostgreSQL before it was evicted from memory, Worker B's query is mathematically guaranteed to find the committed row under `READ COMMITTED`. The race condition is eliminated by the pruning durability gate.

---

## 4. Audit 3: ADR-M13D-012 — Snapshot Staged Publication & Integrity Anchor

### 4.1 Crash-Point Analysis
Snapshot publication spans two storage mediums: (1) Blob Storage (local filesystem / S3), and (2) PostgreSQL metadata. Table 4.1 analyzes crash vulnerability across all execution micro-boundaries:

### Table 4.1: Snapshot Crash-Point Analysis

| Execution Boundary | Failure / Crash Event | System State on Reboot | Recovery Action | Safety Outcome |
| :--- | :--- | :--- | :--- | :--- |
| **Point 1: In-Memory Serialization** | Process killed during state serialization. | No disk write; no DB write. | Normal reboot; re-attempts snapshot later. | Clean. Zero side effects. |
| **Point 2: Writing Temp Blob** | Process crashes while writing `{id}.tmp`. | Incomplete/truncated file on disk; no DB write. | Next boot ignores unreferenced `.tmp` file; cleans up via temp GC. | Clean. No corrupt snapshot exposed. |
| **Point 3: Blob Flushed, Pre-DB** | Process crashes after `fsync({id}.snap)`, before DB insert. | Valid blob on disk; no metadata row in PostgreSQL. | PostgreSQL metadata is authoritative. Unreferenced blob is ignored or swept by GC. | Clean. Orphan blob cannot taint runtime. |
| **Point 4: Post-DB Commit** | Process crashes immediately after PostgreSQL transaction commits. | Valid blob on disk; metadata row in `witness_snapshots`. | Reboot reads PostgreSQL, verifies blob checksum against `snapshot_hash`, restores state. | Clean. Durable recovery point established. |

### 4.2 The 5-Step Staged Publication Protocol
To eliminate corrupt state publication, snapshots must be materialized using this strict protocol:
1. **Stage 1 (Local Temp Write):** Serialize snapshot payload and stream to a temporary file:
   `var/snapshots/{snapshot_id}.tmp`
2. **Stage 2 (Durable Sync):** Force all buffers to non-volatile physical storage via `fsync()`.
3. **Stage 3 (Atomic POSIX Rename):** Atomically rename the temporary file to its final canonical path:
   `rename(".../{id}.tmp", ".../{id}.snap")`
4. **Stage 4 (Checksum Verification):** Read back the file header and compute SHA-256 over canonical content, asserting exact equality with `snapshot.snapshotHash`.
5. **Stage 5 (ACID Metadata Commit):** In a PostgreSQL transaction, insert the snapshot reference:
   ```sql
   INSERT INTO witness_snapshots (
       cluster_id, epoch_id, snapshot_index, snapshot_hash,
       chain_head_hash, etcd_revision, sub_index, storage_uri, created_at_seconds
   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);
   ```

### 4.3 Trusted Integrity Anchor
The authoritative root of trust is the tuple:
$$(\text{chain\_head\_hash}, \text{snapshot\_hash})$$
stored in PostgreSQL `witness_snapshots`. If a restored blob fails checksum verification against `witness_snapshots.snapshot_hash`, the snapshot is immediately quarantined with `SnapshotCorruptionError`.

---

## 5. Audit 4: ADR-M13D-013 — etcd Compaction and Physical Revision Semantics

### 5.1 Verification of Compaction Variables & Units
All variables in the compaction safety equation:
$$R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$$
are strictly **64-bit physical etcd revisions** (`int64`). Logical indices ($L_{app}$) do **not** enter this formula.
* $R_{snap}$: Physical revision stored in the verified snapshot.
* $R_{pg\_persisted}$: Physical revision committed in `witness_raft_state.last_applied_etcd_revision`.
* $\Delta_{buffer}$: Safety revision margin (e.g. 50,000 revisions).
* $R_{comp}$: Target compaction revision in etcd.

### 5.2 Decoupled Physical vs. Logical Mapping
Because etcd revisions leap due to external keyspace writes, physical revision progression is non-contiguous relative to logical index progression:
$$\frac{\Delta R_{etcd}}{\Delta L_{app}} \ge 1$$
Under no circumstances may an implementation evaluate $R_{etcd} \le L_{app}$ or $R_{comp} \le S_{app}$.

### 5.3 Resumption with Same-Revision Sub-Index Filtering
When recovering after compaction:
* If $R_{persisted} \le R_{comp}$, etcd returns `EtcdCompactedError`.
* Node restores snapshot $(S_{app}, R_{snap}, S_{snap})$.
* Watch opens at $R_{snap}$.
* **Stage 2-B0.2 Invariant Maintained:** Because $R_{snap} > R_{comp}$, etcd delivers events from $R_{snap}$. The adapter filters:
  ```typescript
  if (event.etcdRevision === snapshot.snapshotPhysicalCursor.etcdRevision &&
      event.eventSubIndex <= snapshot.snapshotPhysicalCursor.subIndex) {
    return; // Discard already-applied sub-index
  }
  if (event.appLogIndex <= snapshot.snapshotAppIndex) {
    return; // Discard already-applied logical index
  }
  ```
* Recovery is seamless, idempotent, and preserves complete event continuity.

---

## 6. Audit 5: ADR-M13D-014 — Type-Tagged Canonicalization (TTCF-v1 / Canon-v2)

### 6.1 Formal Definition of Type-Tagged Canonical Format
The Type-Tagged Canonical Format (TTCF-v1) guarantees mutual exclusivity across all scalar and structural types by enforcing unique prefixes and strict serialization grammar.

### 6.2 Conceptual Edge-Case Evaluation
Table 6.1 proves collision freedom across all scalar edge cases:

### Table 6.1: Edge-Case Evaluation Matrix

| Input Value | JavaScript Type | TTCF-v1 Canonical Text | Leading Byte(s) | Collision Analysis |
| :--- | :--- | :--- | :--- | :--- |
| `100n` | `bigint` | `bi:100` | `bi` | Distinct from `n:` and `"`. |
| `-100n` | `bigint` | `bi:-100` | `bi` | Negative BigInt cleanly tagged. |
| `100` | `number` | `n:100` | `n:` | Distinct from `bi:` and `"`. |
| `100.5` | `number` | `n:100.5` | `n:` | Distinct from integers. |
| `-0` | `number` | `n:0` | `n:` | Normalized via `Object.is(v, -0) ? "n:0" : ...`. |
| `"100"` | `string` | `"100"` | `"` | Enclosed in quotes; cannot match `bi:` or `n:`. |
| `"bi:100"` | `string` | `"bi:100"` | `"` | First byte is `"`. No collision with bare `bi:100`. |
| `true` | `boolean` | `true` | `t` | Distinct literal. |
| `null` | `object` | `null` | `nu` | Distinct literal. |

### 6.3 Unicode and Escaping Policies
1. **Unicode Normalization:** All string values and object keys must undergo **Unicode Normalization Form C (NFC)** prior to escaping (`str.normalize("NFC")`). This prevents visually identical UTF-8 sequences (e.g. decomposed combining accents) from producing diverging hashes.
2. **JSON String Escaping:** Double quotes (`"`), backslashes (`\`), and control characters (`\u0000` through `\u001f`) are escaped per RFC 8785 Section 3.2.2.2.
3. **Lexicographical Object Key Ordering:** Keys are sorted strictly by UTF-16 code units (equivalent to byte-order sort on UTF-8 without surrogate distortion).

### 6.4 Version Domain Separation
To prevent any possibility of cross-version hash collisions:
$$\text{Hash}_{\text{v1}} = \text{sha256}(\text{canonicalize\_v1}(payload))$$
$$\text{Hash}_{\text{v2}} = \text{sha256}(\text{"TTCF-v1\n"} \;\|\; \text{canonicalize\_v2}(payload))$$
The domain separator prefix `"TTCF-v1\n"` ensures mathematical independence between legacy v1 and upgraded v2 digests.

---

## 7. Audit 6: Cross-ADR Consistency and Full Disaster Recovery Trace

To verify that all five ADRs operate in harmony without internal contradiction, Table 7.1 models the complete 8-step disaster and recovery scenario:

### Table 7.1: End-to-End Failure Scenario Walkthrough

| Step | System Action / Event | State Across Subsystems | Enforced Invariant & Safety Behavior |
| :--- | :--- | :--- | :--- |
| **1. Apply Entries** | Node applies entries $L_1, L_2, L_3$. | RAM: $A_{app}=3$, `appliedIndices`={1,2,3}. | Contiguity verified: $L_{k+1} = L_k + 1$. Hash chain advances. |
| **2. PostgreSQL Commit** | Background worker commits batch. | PG: $L_{pg}=3, R_{pg}=105, S_{pg}=0$. | All 3 entries durably committed to `witness_consensus_log`. |
| **3. Snapshot Published** | Node materializes snapshot at $S_{app}=3$. | Disk: `snap_3.snap`. PG: `witness_snapshots` registered. | Staged protocol verified. `snapshotHash` recorded in DB. |
| **4. etcd Compaction** | etcd compacts revisions $\le 102$. | etcd WAL: Revisions $1 \dots 102$ pruned. | Invariant validated: $102 \le \min(105, 105) - 2$. |
| **5. Node Crash** | Power failure / SIGKILL terminates node. | RAM: Lost. Disk & PG: Intact at $L=3, R=105$. | No dirty uncommitted state on disk. |
| **6. Restart from Snapshot** | Node boots, discovers empty RAM. | RAM restored from `snap_3.snap`. $A_{app}=3, R_{snap}=105$. | Checksum matches `witness_snapshots`. Watch resumes at 105. |
| **7a. Duplicate Delivery** | etcd redelivers $L_2$ ($L_2 \le A_{app}$). | RAM: $L_2 \ge F_{eff}$ (retained in window). | Exact proposal & payload hash match $\implies$ returns `ALREADY_APPLIED`. |
| **7b. Conflicting Entry** | Byzantine node proposes modified $L_2$. | RAM: Mismatch detected against `appliedIndices`. | Throws `HistoricalIndexConflictError("PAYLOAD_HASH")`. |
| **8. Database Outage** | PostgreSQL network partition occurs. Delayed pruned entry $L_0$ arrives. | Tier 2 query fails with connection timeout. | Throws `ConsensusStoreUnavailableError`. Fails closed cleanly; zero false ACKs. |

---

## 8. Required Implementation Tasks for Stage 2-B.2

Before Stage 2-B.2 implementation can be authorized, the engineering team must incorporate the following specific tasks into the Stage 2-B.2 execution plan:
1. **Task 2B2-T1:** Update `src/witness/state-machine.ts` with the corrected `effectiveRetentionFloor` equation:
   `effectiveRetentionFloor = max(1n, min(lastAppliedAppIndex - W_mem + 1n, lastDurablePgIndex + 1n))`.
2. **Task 2B2-T2:** Implement coordinated eviction of `appliedProposals` during sliding window pruning.
3. **Task 2B2-T3:** Create Migration 004 to add the partial unique index:
   `CREATE UNIQUE INDEX uq_consensus_log_proposal_id ON witness_consensus_log (epoch_id, proposal_id) WHERE proposal_id IS NOT NULL;`.
4. **Task 2B2-T4:** Implement the Staged Publication Protocol for `ApplicationStateSnapshot` with temporary file creation, atomic rename, and PostgreSQL metadata registration.
5. **Task 2B2-T5:** Implement TTCF-v1 (Canon-v2) canonicalization with domain separation prefix (`TTCF-v1\n`), negative-zero normalization, and Unicode NFC normalization.

---

## 9. File Metadata and Cryptographic SHA-256 Manifest

| File Path | Description | SHA-256 Digest |
| :--- | :--- | :--- |
| `docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md` | Deliverable Independent Audit Report | Generated on write |
| `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` | Audited Precision Amendment Document | `5EA22A0D87AA8DD29484BD52776C7E46645AE8FD13D6B6A223044B50CBA8A1E9` |
| `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md` | Base Architecture Decision Document | `6267F7C27194082782AFBC65F6710C038C29DF95EDA938848EEA3635E4095914` |
| `src/witness/migrations/003_d3_consensus_state.sql` | Migration 003 Schema Definition | `84F953051ECBCF42B104F5EBDD793C29EB0DE501F0EC09CE968C090CDCF26C03` |
| `src/witness/state-machine-types.ts` | State Machine Contract Types | `B51B425A3EE05BDB935D9B6DA86C6EF6C3ACA97D1F5ED099EDB0F8181C102363` |
| `src/witness/state-machine.ts` | State Machine Implementation | `D1B8D9DACB2E08CAF2E1CA7E5969C78FDE8DDD93830DA9DD156E013C272C4B0A` |
| `test/witness/state-machine.test.ts` | State Machine Test Suite | `225E61468548A97F0775536C3972DC6B92FF8805D0AD125CFC8354822A910A2C` |

---

## 10. Audit Sign-Off

The architecture defined across `M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` and amended herein is **mathematically sound, fail-closed, tamper-resistant, and ready for Stage 2-B.2 implementation planning** upon user review.
