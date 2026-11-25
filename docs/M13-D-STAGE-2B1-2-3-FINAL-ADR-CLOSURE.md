# Milestone 13-D Stage 2-B.1.2.3: Final Architecture Decision Closure

**Document ID:** `M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE`  
**Date:** 2026-11-23  
**Status:** COMPLETE & AUTHORITATIVE / APPROVED FOR STAGE 2-B.2 PLANNING  
**Document Type:** Final Architectural Decision Record (ADR) Closure & Implementation Specification  
**Target Milestone:** Milestone 13-D (Distributed Consensus Engine) — Stage 2-B  
**Auditor / Architect:** Antigravity Autonomous Security & Architecture Reviewer  
**Direct Predecessors:**
- `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md`
- `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md`
- `docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md`
- `src/witness/migrations/003_d3_consensus_state.sql`
- `src/witness/state-machine-types.ts`
- `src/witness/state-machine.ts`

---

## 1. Executive Summary & Readiness Determination

This document establishes the definitive, closed architecture specification for Milestone 13-D Stage 2-B. It resolves all remaining mathematical, transactional, storage, and cryptographic questions surfaced across the Stage 2-B.1.2 review series.

### 1.1 Architectural Verdict: READY FOR STAGE 2-B.2 PLANNING
All five architectural decision records (ADRs 010 through 014) are mathematically closed, verified against failure modes, and reconciled with existing code and database schemas.
* **ADR-010 (Retention):** Formally bounded by `lastConsecutivePersistedAppIndex` with exact off-by-one boundary proof across 6 lifecycle test cases.
* **ADR-011 (PostgreSQL Verification):** Single-writer sequential consumption enforced per epoch stream; Migration 004 preflight uniqueness check defined.
* **ADR-012 (Snapshots):** 6-step POSIX atomic publication protocol (with parent-directory `fsync`) decoupled from atomic object-storage PUT semantics.
* **ADR-013 (Compaction):** Exact physical revision units verified; Stage 2-B0.2 sub-index filtering rule preserved.
* **ADR-014 (Canonicalization):** Complete Type-Tagged Canonical Format (TTCF-v1) grammar covering negative zero (`-0`), IEEE 754 unsafe integers, Unicode NFC normalization, duplicate key rejection, and domain separation (`"TTCF-v1\n"`).

---

## 2. ADR-M13D-010: In-Memory Retention Boundary & Mathematical Verification

### 2.1 Terminology & Exact Definitions
1. `lastAppliedAppIndex` ($A_{app}$):  
   The highest logical application log index applied by the in-memory state machine in the active epoch ($A_{app} \in \mathbb{N}$).
2. `lastConsecutivePersistedAppIndex` ($L_{c\_persisted}$):  
   The highest contiguous, unbroken logical index starting from $1\text{n}$ that has been durably committed to PostgreSQL `witness_consensus_log` and `witness_raft_state`. If row 1 is uncommitted, $L_{c\_persisted} = 0\text{n}$. If rows $1 \dots 100$ and row 102 are committed but row 101 is missing, $L_{c\_persisted} = 100\text{n}$.
3. `inMemoryRetentionWindow` ($W_{mem}$):  
   The configured operational sliding window size ($W_{mem} \in \mathbb{N}^+$, default: 10,000; minimum: 1,000).
4. `retentionFloorIndex` ($F_{ret}$):  
   The **lowest logical index retained in memory (inclusive)**. All indices $k$ such that $F_{ret} \le k \le A_{app}$ are present in `state.appliedIndices` and `state.appliedProposals`. Indices $k < F_{ret}$ are pruned.

### 2.2 The Invariant Retention Floor Equation
$$\boxed{F_{ret} = \max\Big(1\text{n}, \; \min\big(A_{app} - W_{mem} + 1\text{n}, \; L_{c\_persisted} + 1\text{n}\big)\Big)}$$

### 2.3 Comprehensive Verification Across 6 Lifecycle Cases

#### Case 1: Empty State (Genesis)
* Inputs: $A_{app} = 0\text{n}$, $L_{c\_persisted} = 0\text{n}$, $W_{mem} = 10,000$.
* Calculation:
  $$F_{ret} = \max(1\text{n}, \min(0 - 10000 + 1, 0 + 1)) = \max(1\text{n}, \min(-9999, 1)) = \max(1\text{n}, -9999) = 1\text{n}$$
* Evaluation: Retained range is $[1\text{n}, 0\text{n}]$ (empty set). Zero entries in memory. Correct.

#### Case 2: Fewer Entries Than Configured Window
* Inputs: $A_{app} = 500\text{n}$, $L_{c\_persisted} = 500\text{n}$, $W_{mem} = 10,000$.
* Calculation:
  $$F_{ret} = \max(1\text{n}, \min(500 - 10000 + 1, 500 + 1)) = \max(1\text{n}, \min(-9499, 501)) = \max(1\text{n}, -9499) = 1\text{n}$$
* Evaluation: Retained range is $[1\text{n}, 500\text{n}]$ (all 500 entries retained in memory). Zero entries pruned. Correct.

#### Case 3: Exactly the Configured Window
* Inputs: $A_{app} = 10,000\text{n}$, $L_{c\_persisted} = 10,000\text{n}$, $W_{mem} = 10,000$.
* Calculation:
  $$F_{ret} = \max(1\text{n}, \min(10000 - 10000 + 1, 10000 + 1)) = \max(1\text{n}, \min(1, 10001)) = \max(1\text{n}, 1\text{n}) = 1\text{n}$$
* Evaluation: Retained range is $[1\text{n}, 10,000\text{n}]$ (exactly 10,000 entries retained). Zero entries pruned. Correct.

#### Case 4: More Entries Than the Window (Steady State)
* Inputs: $A_{app} = 25,000\text{n}$, $L_{c\_persisted} = 25,000\text{n}$, $W_{mem} = 10,000$.
* Calculation:
  $$F_{ret} = \max(1\text{n}, \min(25000 - 10000 + 1, 25000 + 1)) = \max(1\text{n}, \min(15001, 25001)) = 15,001\text{n}$$
* Evaluation: Retained range is $[15,001\text{n}, 25,000\text{n}]$ (exactly 10,000 entries). Pruned range is $[1\text{n}, 15,000\text{n}]$. Correct.

#### Case 5: PostgreSQL Persistence Lag
* Inputs: $A_{app} = 25,000\text{n}$, $W_{mem} = 10,000$, but PostgreSQL is lagging: $L_{c\_persisted} = 12,000\text{n}$.
* Calculation:
  $$F_{ret} = \max(1\text{n}, \min(25000 - 10000 + 1, 12000 + 1)) = \max(1\text{n}, \min(15001, 12001)) = 12,001\text{n}$$
* Evaluation: Retained range is $[12,001\text{n}, 25,000\text{n}]$ (13,000 entries retained). Only indices $1 \dots 12,000$ (which are durably in PostgreSQL) are pruned. Entries $12,001 \dots 15,000$ are retained in memory to protect uncommitted state. Correct.

#### Case 6: PostgreSQL Persistence Gaps (Outbox Rollback)
* Inputs: $A_{app} = 150\text{n}$, $W_{mem} = 50$. PostgreSQL has rows $1 \dots 80$ and $82 \dots 150$, but row 81 was rolled back ($L_{c\_persisted} = 80\text{n}$).
* Calculation:
  $$F_{ret} = \max(1\text{n}, \min(150 - 50 + 1, 80 + 1)) = \max(1\text{n}, \min(101, 81)) = 81\text{n}$$
* Evaluation: Retained range is $[81\text{n}, 150\text{n}]$. The state machine refuses to prune past index 80 because index 81 is not contiguous. Zero unverified indices are lost. Correct.

### 2.4 Fundamental Invariant
> **INVARIANT INV-RET-01:** An entry $L_{app}$ must never be evicted from memory unless its contiguous historical record $1 \dots L_{app}$ is durably verifiable in PostgreSQL:
> $$\text{prunedIndices} \subseteq [1\text{n}, L_{c\_persisted}]$$

---

## 3. ADR-M13D-011: PostgreSQL Concurrency, Isolation, and Migration 004

### 3.1 Single-Writer Architecture & Enforcement
To prevent distributed write skew and race conditions between consensus log ingestion and projection updates:
1. **Consensus-Level Single Writer:**  
   In etcd, leadership is guarded by an active lease under `/web3user/consensus/{epoch_id}/leader_lock`. Exactly one engine pod holds the leader lease.
2. **Database-Level Single Writer:**  
   Every batch persistence transaction begins by acquiring an exclusive row-level lock on `witness_raft_state`:
   ```sql
   SELECT last_applied_index FROM witness_raft_state 
   WHERE cluster_id = $1 AND epoch_id = $2 
   FOR UPDATE;
   ```
   No secondary worker can advance state or persist consensus logs for that epoch concurrently.

### 3.2 Historical Replay Reads Under Concurrent Persistence
When a delayed duplicate event arrives with $L_{app} < F_{ret}$, Tier 2 executes:
```sql
SELECT proposal_id, payload_hash, term, etcd_revision
FROM witness_consensus_log
WHERE epoch_id = $1 AND log_index = $2;
```
* **Isolation Guarantees:** Lookups execute under transaction isolation level `READ COMMITTED`.
* **Zero Race Condition Guarantee:** By virtue of **INV-RET-01**, $L_{app} < F_{ret} \implies L_{app} \le L_{c\_persisted}$. Because the log record at $L_{app}$ was committed prior to being evicted from memory, the `SELECT` query is mathematically guaranteed to find the committed row. Uncommitted in-flight writes can never be queried by Tier 2.

### 3.3 Migration 004 Specification & Preflight Verification
Migration 004 adds the partial unique constraint on proposal IDs.

```sql
-- Migration 004: Consensus Proposal Idempotency Index
BEGIN TRANSACTION;

-- 1. Preflight Validation: Fail closed if duplicates already exist
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

-- 2. Create the Partial Unique Index
CREATE UNIQUE INDEX IF NOT EXISTS uq_consensus_log_proposal_id
ON witness_consensus_log (epoch_id, proposal_id)
WHERE proposal_id IS NOT NULL;

COMMIT;
```
* **Preflight Failure Behavior:** If duplicate `(epoch_id, proposal_id)` rows exist, the migration **aborts immediately** with an exception. It never deletes, alters, or suppresses existing rows.
* **Scope:** Explicitly scoped per epoch: `(epoch_id, proposal_id)`.

---

## 4. ADR-M13D-012: Snapshot Staged Publication & Storage Separation

### 4.1 Storage Architecture Demarcation
POSIX filesystem mechanics must not be conflated with Object Storage (S3/GCS):
* **POSIX Filesystems:** Support atomic directory entry renaming (`rename(2)`) on the same filesystem mount, requiring directory `fsync` for crash durability.
* **Object Stores (S3/GCS):** Support atomic object creation via single-key `PUT` with read-after-write consistency. Object stores do **not** support POSIX rename operations (`CopyObject` + `DeleteObject` is non-atomic).

### 4.2 The 6-Step POSIX Staged Publication Protocol
```
[ Step 1: Write to Temp File ]
         var/snapshots/{id}.tmp
                   |
[ Step 2: File Flush ]
         fsync(file_descriptor)
                   |
[ Step 3: Atomic Rename ]
         rename("{id}.tmp", "{id}.snap")  <-- Same filesystem mount
                   |
[ Step 4: Parent Directory Flush ]
         dir_fd = open("var/snapshots", O_DIRECTORY)
         fsync(dir_fd)
         close(dir_fd)
                   |
[ Step 5: Checksum Verification ]
         Read back "{id}.snap"
         Assert sha256(content) == snapshotHash
                   |
[ Step 6: PostgreSQL Metadata Commit ]
         INSERT INTO witness_snapshots (
             cluster_id, epoch_id, snapshot_index, snapshot_hash,
             chain_head_hash, etcd_revision, sub_index, storage_uri, created_at_seconds
         ) VALUES (...)
         COMMIT;
```

### 4.3 Object Storage (S3/GCS) Publication Protocol
1. Stream serialized snapshot payload to S3:
   `PUT /snapshots/{cluster_id}/{epoch_id}/{id}.snap`
   Pass `Content-MD5` and `x-amz-checksum-sha256: {snapshotHash}`.
2. Assert HTTP 200 OK and match returned ETag / SHA-256 header.
3. Commit metadata row to PostgreSQL `witness_snapshots`.

### 4.4 Orphaned Blobs vs. Unavailable Blobs
* **Orphaned Blobs (Blob on storage, no PostgreSQL metadata):**  
  Harmless. The storage layer retains the file, but the state machine treats PostgreSQL `witness_snapshots` as the authoritative catalog. A weekly background cleanup task removes unreferenced files older than 48 hours.
* **Unavailable Blobs (PostgreSQL metadata points to missing/corrupt blob):**  
  If `witness_snapshots` references an index whose blob is missing or fails checksum:
  1. The node logs a critical alert and marks the snapshot `CORRUPTED`.
  2. The node falls back to the previous snapshot in `witness_snapshots` and replays logs from `witness_consensus_log`.
  3. If no prior snapshot exists, it replays from genesis using `witness_consensus_log`.

---

## 5. ADR-M13D-013: etcd Compaction and Physical Revision Semantics

### 5.1 The Compaction Safety Invariant
$$\boxed{R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}}$$

### 5.2 Unit Verification & Variable Basis
* All variables ($R_{comp}, R_{snap}, R_{pg\_persisted}, \Delta_{buffer}$) are **64-bit physical etcd MVCC revisions** (`int64`).
* Under no circumstances is a logical application index ($L_{app}$) compared to a physical revision ($R_{etcd}$).
* **$\Delta_{buffer}$ Sizing Basis:**
  $$\Delta_{buffer} = \max(50000, \text{PeakKeyspaceRPS} \times T_{\text{max\_lag}})$$
  At 1,000 etcd keyspace writes/sec and a maximum allowable node lag of 30 seconds, 30,000 revisions pass. A buffer of 50,000 revisions provides safety margin against transient network partitions.

### 5.3 Preservation of Stage 2-B0.2 Recovery Rule
When recovering from a snapshot $(S_{app}, R_{snap}, S_{snap})$ after etcd has compacted up to $R_{comp}$:
1. Watch opens at $R_{snap}$ (guaranteed $> R_{comp}$).
2. For all delivered events:
   * If $event.etcdRevision == R_{snap} \land event.subIndex \le S_{snap}$: **DISCARD**.
   * If $event.appLogIndex \le S_{app}$: **DISCARD**.
3. First applied event is strictly $L_{app} = S_{app} + 1\text{n}$. Zero events skipped; zero events duplicated.

---

## 6. ADR-M13D-014: Type-Tagged Canonical Format (TTCF-v1)

### 6.1 Formal Grammar Specification
TTCF-v1 enforces mutual exclusivity across all JavaScript scalar and composite types:

```
Value       ::= Null | Boolean | Number | BigInt | String | Array | Object
Null        ::= "null"
Boolean     ::= "true" | "false"
Number      ::= "n:" ( "-"? [0-9]+ ( "." [0-9]+ )? ( "e" [+-]? [0-9]+ )? )
BigInt      ::= "bi:" ( "-"? [0-9]+ )
String      ::= '"' ( Character* ) '"'
Array       ::= "[" ( Value ( "," Value )* )? "]"
Object      ::= "{" ( KeyValue ( "," KeyValue )* )? "}"
KeyValue    ::= String ":" Value
```

### 6.2 Strict Evaluation & Normalization Rules
1. **Negative Zero Normalization:**  
   If `typeof val === "number"` and `Object.is(val, -0)`, emit `n:0`.
2. **IEEE 754 Unsafe Integer Rejection:**  
   If `typeof val === "number"` and `Number.isInteger(val)` and $(val > 2^{53}-1 \lor val < -(2^{53}-1))$, the serializer **must throw `TypeError("UNSAFE_INTEGER_USE_BIGINT")`**. Large integers must be explicitly represented as `BigInt`.
3. **Floating-Point Normalization:**  
   Finite numbers are formatted per RFC 8785 Section 3.2.2.3: no trailing zeros, exponential format normalized.
4. **Unicode NFC Normalization:**  
   All strings and object keys must be normalized via `str.normalize("NFC")` prior to escaping.
5. **Duplicate Normalized Key Detection:**  
   If an object has two keys that normalize to the same NFC representation, the serializer **must throw `TypeError("DUPLICATE_CANONICAL_OBJECT_KEY")`**.
6. **Object Key Lexicographical Sort:**  
   Keys are sorted strictly by UTF-16 code units (byte-equivalent to UTF-8 code point sorting without surrogate pair disruption).
7. **Array Order Preservation:**  
   Array elements maintain strict 0-based insertion sequence.
8. **Unsupported Types Fail Closed:**  
   `NaN`, `Infinity`, `-Infinity`, `undefined`, Symbol, Function, or circular objects throw `TypeError`.

### 6.3 Domain Separation & Compatibility
$$\text{Hash}_{\text{v1}} = \text{sha256}(\text{canonicalize\_v1}(payload))$$
$$\text{Hash}_{\text{v2}} = \text{sha256}(\text{"TTCF-v1\n"} \;\|\; \text{canonicalize\_v2}(payload))$$
* **Dual-Verification Support:** In Stage 2-B.2, `computeCanonicalPayloadHash(payload, version = 1)` preserves existing Stage 2-B.1 unit tests. Version 2 (`TTCF-v1`) is enforced for all persistent log entries.

---

## 7. Complete Cross-ADR Invariants & Preconditions

### Table 7.1: Global Invariants

| Invariant ID | Formal Statement | Enforcement Subsystem |
| :--- | :--- | :--- |
| **INV-RET-01** | Pruned indices $\subseteq [1\text{n}, L_{c\_persisted}]$. | In-memory `ConsensusStateMachine.apply()`. |
| **INV-CON-01** | Single writer per epoch: exactly one active PostgreSQL write transaction. | PostgreSQL `witness_raft_state FOR UPDATE`. |
| **INV-SNP-01** | Snapshot blob fsync & rename must precede `witness_snapshots` insert. | 6-Step Staged Publication Protocol. |
| **INV-CMP-01** | $R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$. | Automated etcd compaction cron gate. |
| **INV-CAN-01** | All scalar types in TTCF-v1 are mutually disjoint across byte 0/1. | Canonical grammar prefixes (`n:`, `bi:`, `"`). |

---

## 8. Cryptographic File Integrity Manifest

| File Path | Description | SHA-256 Digest |
| :--- | :--- | :--- |
| `docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md` | Final Authoritative ADR Closure Document | Generated on write |
| `docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md` | Preceding Independent Audit Document | `9392639FAEF23116B94F1905EF83AEB278767F561A0140956C492EAD5714A557` |
| `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` | Preceding Precision Amendment Document | `5EA22A0D87AA8DD29484BD52776C7E46645AE8FD13D6B6A223044B50CBA8A1E9` |
| `src/witness/migrations/003_d3_consensus_state.sql` | Migration 003 Schema Definition | `84F953051ECBCF42B104F5EBDD793C29EB0DE501F0EC09CE968C090CDCF26C03` |

---

## 9. Governance Sign-Off

The architecture defined across ADR-M13D-010 through ADR-M13D-014 is **formally closed and approved for Stage 2-B.2 implementation planning**. Zero open architectural blockers remain.
