# Milestone 13-D Stage 2-B.1.2.1: Architecture Decision Precision Amendment

**Document ID:** `M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT`  
**Date:** 2026-11-23  
**Status:** DRAFT / PENDING ARCHITECTURAL APPROVAL  
**Document Type:** Architecture Precision Amendment & Formal Specification  
**Target Milestone:** Milestone 13-D (Distributed Consensus Engine) — Stage 2-B  
**Auditor / Architect:** Antigravity Autonomous Security & Architecture Reviewer  
**Direct Refinement of:** `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md`  
**Prior Reference Architecture:**
- `docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md`
- `docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md`
- `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md`
- `src/witness/migrations/003_d3_consensus_state.sql`

---

## 1. Executive Summary & Purpose

This precision amendment refines and formally closes the five Architectural Decision Records (ADRs) defined in `M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md`. It addresses the detailed architectural review points raised regarding:
1. **Logical Index Scope & Composite Identity (ADR-M13D-010):** Formalizes that application log indices are strictly epoch-scoped ($L_{app} \in [1, \infty)$ per epoch) and defines the globally unique composite key $(cluster\_id, epoch\_id, log\_index)$. Clarifies configurable retention window semantics and durable verification prerequisites.
2. **PostgreSQL Ground-Truth Verification (ADR-M13D-011):** Reconciles Tier 2 cold-path replay verification with the exact schema, constraints, and indexes in `003_d3_consensus_state.sql`. Defines fail-closed behaviors for database disconnections, missing records, and hash mismatches.
3. **Snapshot Contract & Trusted Hash Publication (ADR-M13D-012):** Specifies independent snapshot and canonicalization versioning, consistent point-in-time state capture, trusted reference publication, and corrupt/incompatible restore handling.
4. **etcd Compaction Coordination & Resumption (ADR-M13D-013):** Formulates precise definitions for all compaction variables, defines the prerequisite durability rules, and reconciles post-compaction recovery with the Stage 2-B0.2 sub-index filtering rule.
5. **Type-Tagged Canonical Serialization (ADR-M13D-014):** Replaces raw unquoted BigInt representation with an unambiguous, type-tagged canonical serialization scheme that mathematically differentiates BigInt, Number, String, Boolean, Null, Array, and Object.

---

## 2. Amendment 1: ADR-M13D-010 — Retention, Epoch Scoping, and Bounded Memory

### 2.1 Logical Index Scope: Epoch-Scoped vs. Globally Monotonic
* **Ground-Truth Determination:** Logical application indices ($L_{app}$) are **epoch-scoped**, resetting to $1\text{n}$ upon `EPOCH_INITIALIZE` for each new epoch.
* **Architectural Rationale:**
  - As established in `src/witness/migrations/003_d3_consensus_state.sql`, `witness_consensus_log` defines:
    ```sql
    PRIMARY KEY (epoch_id, log_index)
    ```
  - `witness_raft_state` defines:
    ```sql
    PRIMARY KEY (cluster_id, epoch_id)
    ```
  - In `src/witness/state-machine.ts`, `applyEpochInitialize()` sets:
    ```typescript
    lastAppliedAppIndex: entry.appLogIndex // where appLogIndex = 1n
    ```
  - Therefore, $L_{app}$ is strictly contiguous within an epoch: $L_{app} \in \{1, 2, 3, \dots\}$. It is **not** globally contiguous across epoch transitions.
* **Physical vs. Logical Contrast:**
  - Physical etcd revision ($R_{etcd}$) is **globally monotonic** across the entire etcd cluster and all epochs.
  - Logical application index ($L_{app}$) is **epoch-scoped** and restarts at $1\text{n}$ with each epoch boundary.

### 2.2 Composite Historical Identity
Because $L_{app}$ restarts at $1\text{n}$ in each epoch, an index $L_{app} = 100$ in Epoch 1 is entirely distinct from $L_{app} = 100$ in Epoch 2.
* The globally unique composite coordinate for any historical consensus entry is:
  $$\mathbf{ID}_{\text{entry}} = (cluster\_id, epoch\_id, log\_index)$$
* All in-memory lookups, deduplication tables, and database constraints must enforce identity on this composite tuple.

### 2.3 Exact Retention-Floor Semantics
The in-memory retention floor applies strictly within the active epoch state:
$$\text{retentionFloorIndex} = \max(1\text{n}, \text{state.lastAppliedAppIndex} - W_{mem} + 1\text{n})$$
* **Hot Window ($L_{app} \ge \text{retentionFloorIndex}$):** Full verification records are retained in memory in `state.appliedIndices` and `state.appliedProposals`.
* **Pruned Window ($L_{app} < \text{retentionFloorIndex}$):** Records are evicted from memory to maintain bounded heap consumption, falling back to Tier 2 durable verification.

### 2.4 Epoch Sealing and Historical Replay Behavior
* When an epoch advances via `EPOCH_ADVANCE`:
  1. The prior epoch is marked `TERMINATED` (or `CLOSED`).
  2. The new epoch begins with `lastAppliedAppIndex = entry.appLogIndex` (and new `epochId`).
  3. All in-memory `appliedIndices` and `appliedProposals` belonging to the old epoch are **purged from the active state machine memory**.
* If a delayed entry arrives bearing a sealed `epochId`:
  - `ConsensusStateMachine.apply()` checks `entry.epochId === state.epochId` on line 278.
  - It immediately throws `EpochMismatchError(state.epochId, entry.epochId)`.
  - The historical index lookup is **never reached**. Sealed epoch isolation is preserved at the perimeter.
* Historical audits of sealed epochs are served directly from PostgreSQL `witness_consensus_log`, where sealed epoch records remain permanently immutable under database triggers.

### 2.5 Configurable Retention Window ($W_{mem}$) Rationale
The proposed window size of 10,000 entries is an **operational default**, not an invariant consensus constant.
* The minimum safe in-memory window $W_{mem}$ is dynamically governed by:
  $$W_{mem} \ge \lceil \text{MaxWatchLagSeconds} \times \text{PeakTPS} \rceil + N_{\text{in\_flight\_lease}}$$
* For example, at a peak throughput of 1,000 TPS and a maximum expected watch reconnection lag of 30 seconds, $W_{mem}$ must be $\ge 30,000$.
* Therefore, $W_{mem}$ is defined as a configurable startup parameter:
  `CONSENSUS_IN_MEMORY_RETENTION_WINDOW` (default: 10,000; minimum allowable: 1,000).

### 2.6 Durable Verification Prerequisite Before Pruning
* **Pruning Guard Rule:** An entry $L_{app}$ **must never be pruned from memory** unless it is confirmed to have been durably written and committed to PostgreSQL:
  $$\text{effectiveRetentionFloor} = \min(\text{retentionFloorIndex}, \text{lastDurablePgIndex})$$
* This ensures that in the event of an ungraceful crash or database lag, an in-memory entry is never evicted before its durable counterpart is safely flushed to disk.

---

## 3. Amendment 2: ADR-M13D-011 — PostgreSQL Historical Replay Verification & Schema Reconciliation

### 3.1 Exact Database Identity & Existing Schema Reconciliation
In `src/witness/migrations/003_d3_consensus_state.sql`, table `witness_consensus_log` exists with the following exact columns and constraints:
```sql
CREATE TABLE witness_consensus_log (
    epoch_id VARCHAR(64) NOT NULL,
    log_index BIGINT NOT NULL,
    term BIGINT NOT NULL,
    etcd_revision BIGINT NOT NULL,
    payload_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    proposal_id VARCHAR(128) NULL,
    committed_at_seconds BIGINT NOT NULL,
    PRIMARY KEY (epoch_id, log_index),
    CONSTRAINT chk_consensus_log_index CHECK (log_index > 0),
    CONSTRAINT chk_consensus_log_term CHECK (term >= 0),
    CONSTRAINT chk_consensus_log_revision CHECK (etcd_revision >= 0)
);

CREATE INDEX idx_consensus_log_payload_hash 
ON witness_consensus_log (epoch_id, payload_hash);

CREATE INDEX idx_consensus_log_proposal_id 
ON witness_consensus_log (proposal_id) 
WHERE proposal_id IS NOT NULL;
```

#### Reconciled Query Identity
When the state machine emits `HISTORICAL_RECORD_PRUNED` for an entry $(epoch\_id, L_{app})$, the store queries:
```sql
SELECT proposal_id, payload_hash, term, etcd_revision
FROM witness_consensus_log
WHERE epoch_id = $1 AND log_index = $2;
```
* **Primary Key:** `(epoch_id, log_index)` guarantees that at most one row can ever match this query.
* **No Speculative Columns:** The lookup uses only columns already defined in Migration 003 (`proposal_id`, `payload_hash`, `epoch_id`, `log_index`).

### 3.2 Proposal ID Uniqueness & Verification
* In Migration 003, `proposal_id` is indexed via `idx_consensus_log_proposal_id`, but is not declared `UNIQUE`.
* **Precision Rule:** In Stage 2-B.2, to guarantee cluster-wide proposal idempotency across arbitrary log indices within an epoch, a unique partial index must be formally added:
  ```sql
  CREATE UNIQUE INDEX IF NOT EXISTS uq_consensus_log_proposal_id
  ON witness_consensus_log (epoch_id, proposal_id)
  WHERE proposal_id IS NOT NULL;
  ```
* During Tier 2 verification:
  1. If `row.proposal_id === entry.proposalId` AND `row.payload_hash === computedPayloadHash`:
     -> Replay is verified as an authentic, exact duplicate. Return `ALREADY_APPLIED`.
  2. If `row.proposal_id !== entry.proposalId`:
     -> Proposal conflict! Throw `HistoricalIndexConflictError("PROPOSAL_ID")`.
  3. If `row.payload_hash !== computedPayloadHash`:
     -> Tampering conflict! Throw `HistoricalIndexConflictError("PAYLOAD_HASH")`.

### 3.3 Fail-Closed Behavior for Missing, Disconnected, or Corrupt Records
Table 3.1 establishes the deterministic error mapping for Tier 2 verification:

### Table 3.1: Tier 2 Error Mapping & Fail-Closed Guards

| Scenario | State Condition | Action & Error Raised | Safety Justification |
| :--- | :--- | :--- | :--- |
| **Normal Exact Replay** | Row exists; `proposal_id` & `payload_hash` match. | Return `status: "ALREADY_APPLIED"`. | Authentic duplicate confirmed by database. |
| **Conflicting Proposal ID** | Row exists; `proposal_id` differs. | Throw `HistoricalIndexConflictError("PROPOSAL_ID")`. | Prevents reusing index for distinct proposal. |
| **Conflicting Payload Hash** | Row exists; `payload_hash` differs. | Throw `HistoricalIndexConflictError("PAYLOAD_HASH")`. | Detects retroactive payload tampering. |
| **Missing Log Row** | No row found for $(epoch\_id, L_{app})$, but $L_{app} \le A_{app}$. | Throw `UnverifiableHistoricalEntryError(L_{app})`. | Fail-closed: Prevents assuming unverified events succeeded. Indicates database corruption. |
| **Database Disconnection** | PostgreSQL timeout, connection pool exhaustion, or 57P01. | Throw `ConsensusStoreUnavailableError`. | Fail-closed: Engine pauses watch and retries. Never silently succeeds. |

---

## 4. Amendment 3: ADR-M13D-012 — Snapshot Contract, Integrity Verification, and Atomic Publication

### 4.1 Independent Schema and Canonicalization Versioning
To decouple snapshot schema migrations from cryptographic hashing algorithm evolutions, the snapshot contract incorporates two distinct versions:
1. `formatVersion: number` — Tracks structural layout, field additions, and serialization format (e.g., format version 1).
2. `canonicalizationVersion: number` — Tracks the canonical serialization and hashing specification (e.g., version 2 for type-tagged canonical encoding).

### 4.2 Point-in-Time Consistent State Capture
A snapshot represents an instantaneous, atomic state slice immediately after applying index $S_{app}$.
* **Consistency Precondition:** The snapshot creation runs inside the same single-transaction ACID boundary in PostgreSQL, or is derived from a read transaction locked at:
  ```sql
  SELECT last_applied_index, last_applied_term, last_applied_hash, 
         last_applied_etcd_revision, last_applied_sub_index
  FROM witness_raft_state
  WHERE cluster_id = $1 AND epoch_id = $2
  FOR SHARE;
  ```
* **Captured Physical & Logical Coordinates:**
  - $S_{app}$: Exact logical application log index.
  - $R_{etcd}, S_{idx}$: Exact physical etcd cursor at the moment $S_{app}$ was linearized.
  - $H_{chain}$: Exact rolling `chainHeadHash` committing to all transitions up to $S_{app}$.

### 4.3 Trusted Hash Reference and Atomic Publication
* The snapshot body is canonically serialized and hashed:
  $$\text{snapshotHash} = \text{sha256}(\text{canonicalize}(\text{snapshot\_body}))$$
* **Atomic Publication Sequence:**
  1. The serialized snapshot blob is written to durable storage (PostgreSQL table `witness_snapshots` or local disk/S3).
  2. The trusted reference is atomically published in PostgreSQL:
     ```sql
     INSERT INTO witness_snapshots (
         cluster_id, epoch_id, snapshot_index, snapshot_hash, 
         chain_head_hash, etcd_revision, sub_index, created_at_seconds
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (cluster_id, epoch_id, snapshot_index) DO UPDATE
     SET snapshot_hash = EXCLUDED.snapshot_hash;
     ```
  3. The active pointer in `witness_raft_state` is updated to record the latest valid snapshot index.

### 4.4 Restoration Failure Matrix
* **Corrupt Snapshot (Hash Mismatch):** Computed SHA-256 differs from `snapshotHash`. Abort with `SnapshotCorruptionError`. Fall back to previous snapshot + WAL replay.
* **Incompatible Format Version:** `formatVersion` is unrecognized by current runtime. Abort with `IncompatibleSnapshotVersionError`.
* **Incompatible Canonicalization Version:** `canonicalizationVersion` differs from runtime capability. Abort with `IncompatibleCanonicalizationVersionError`.
* **Stale Snapshot:** Attempting to restore a snapshot with $S_{app} < A_{current}$ during normal operation. Abort with `StaleSnapshotRestorationError` unless explicit disaster recovery flag is enabled.

---

## 5. Amendment 4: ADR-M13D-013 — etcd Compaction Coordination, Resumption, and Ground-Truth Auditing

### 5.1 Exact Definition of Compaction Variables
The compaction safety equation is defined as:
$$R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$$
Where:
* $R_{etcd} \in \mathbb{N}^+$: The live, cluster-wide 64-bit monotonic revision counter in etcd.
* $R_{snap} \in \mathbb{N}^+$: The physical etcd revision recorded in the latest verified, durably persisted `ApplicationStateSnapshot`.
* $R_{pg\_persisted} \in \mathbb{N}^+$: The physical revision stored in PostgreSQL `witness_raft_state.last_applied_etcd_revision`.
* $R_{comp} \in \mathbb{N}^+$: The highest revision to which etcd's WAL is compacted (`etcdctl compact R_comp`).
* $\Delta_{buffer} \in \mathbb{N}^+$: A mandatory safety margin (e.g. 50,000 revisions) ensuring that active consumer lag does not immediately trigger compaction errors.

### 5.2 Mandatory Snapshot Durability Before Compaction
* **Safety Invariant:** Under no circumstances may etcd be compacted to revision $R$ unless:
  $$\exists \text{ verified snapshot } S \text{ such that } S.snapshotPhysicalCursor.etcdRevision \ge R$$
  AND
  $$\text{PostgreSQL } witness\_consensus\_log \text{ contains all entries up to } R$$
* If an automated compaction cron attempts to run when no durable snapshot covers the target revision, compaction is inhibited.

### 5.3 Resumption & Sub-Index Filtering Reconciled with B0.2
When recovering after compaction:
1. If local cursor $R_{client} > R_{comp}$:
   - Watch opens normally at $R_{client}$.
   - Follows Stage 2-B0.2 rule: Discards events where $R_{etcd} == R_{client} \land S_{idx} \le S_{client}$, and discards events where $L_{app} \le A_{client}$.
2. If local cursor $R_{client} \le R_{comp}$:
   - Watch fails with `EtcdCompactedError`.
   - Engine restores latest snapshot $(S_{app}, R_{snap}, S_{snap})$.
   - Watch opens at $R_{snap}$ (which is guaranteed $> R_{comp}$).
   - Discards events where $R_{etcd} == R_{snap} \land S_{idx} \le S_{snap}$, and discards events where $L_{app} \le S_{app}$.
   - Resumes strictly contiguous processing at $L_{app} = S_{app} + 1\text{n}$.

### 5.4 Permanent Accessibility of Ground-Truth History
* Even if etcd compacts all WAL revisions from 1 to $R_{comp}$, **PostgreSQL retains 100% of event history** in `witness_consensus_log`.
* etcd serves solely as the linearizable consensus coordination bus. PostgreSQL serves as the permanent, immutable linear ledger.

---

## 6. Amendment 5: ADR-M13D-014 — Unambiguous Type-Tagged Canonical Serialization

### 6.1 Replacement of Unquoted Decimal BigInt Encoding
In Stage 2-B.1.2, ADR-M13D-014 proposed emitting raw unquoted decimal digits for BigInt (`100n` $\to$ `100`). While this distinguished BigInt from quoted strings (`"100"`), it left BigInt mathematically identical to integer Numbers (`100` $\to$ `100`). In multi-language or polymorphic environments where numeric types must be strictly typed, this produces ambiguity.

### 6.2 The Type-Tagged Canonical Format (TTCF-v1 / Canon-v2)
To mathematically distinguish all seven core data types without delimiter collision, the canonical serializer implements the Type-Tagged Canonical Format:

#### Table 6.1: Type-Tagged Scalar and Structural Grammar

| JavaScript Type | Canonical Prefix / Envelope | Canonical Encoding Example | Unambiguous Separation Rule |
| :--- | :--- | :--- | :--- |
| **Null** | Literal `null` | `null` | Exact token match `null`. |
| **Boolean** | Literal `true` or `false` | `true`, `false` | Exact token match `true`/`false`. |
| **Number** | `n:<normalized_float>` | `n:42`, `n:100.5`, `n:-17` | Prefixed with `n:`; finite numbers only; formatted without leading zeros; exponential notation normalized per RFC 8785. |
| **BigInt** | `bi:<decimal_digits>` | `bi:100`, `bi:-9007199254740995` | Prefixed with `bi:`; arbitrary-precision decimal digits; optional leading `-`. |
| **String** | `"..."` (JSON escaped) | `"hello"`, `"100"`, `"bi:100"` | Enclosed in standard double quotes; control chars escaped per RFC 8785. |
| **Array** | `[elem_0,elem_1,...]` | `[bi:100,n:42,"test"]` | Enclosed in square brackets; comma-delimited; order strictly preserved. |
| **Object** | `{key_0:val_0,key_1:val_1,...}` | `{"a":bi:100,"b":"test"}` | Enclosed in curly braces; keys lexicographically sorted by UTF-16 code units; keys JSON-escaped. |

#### Formal Proof of Collision Freedom
1. **BigInt vs. String:**
   - A BigInt `100n` serializes as `bi:100` (first character is `b`).
   - A String `"bi:100"` serializes as `"\"bi:100\""` (first character is `"`).
   - Because strings are unconditionally enclosed in double quotes and quote characters inside strings are escaped (`\"`), a string can never start with bare token `bi:`.
2. **BigInt vs. Number:**
   - BigInt has prefix `bi:` (first two characters `bi`).
   - Number has prefix `n:` (first two characters `n:`).
   - BigInt `100n` (`bi:100`) and Number `100` (`n:100`) differ on byte 0.
3. **Number vs. String:**
   - Number starts with `n:`; string starts with `"`.

### 6.3 Rejection of Non-Finite and Unsupported Types
The canonicalizer fails closed with an immediate `TypeError` if it encounters:
* Non-finite numbers: `NaN`, `Infinity`, `-Infinity`.
* Direct `undefined` values.
* Functions, symbols, or unknown host objects.

### 6.4 Versioning and Dual-Verification Requirements
* `computeCanonicalPayloadHash(payload, version = 1)` defaults to Version 1 (Stage 2-B.1 compatibility) during in-memory transition testing.
* When Stage 2-B.2 introduces persistent etcd proposals, the engine activates `version = 2` (TTCF-v1) across all new proposal hashing and verification.
* Any existing Stage 2-B.1 unit tests are preserved intact. New tests for Stage 2-B.2 will validate Version 2 type-tagging across all 7 types.

---

## 7. Reconciliation Matrix with Prior Architectural Decisions

| Decision Topic | Prior Architecture (B0.1 / B0.2 / B.1) | Precision Amendment (Stage 2-B.1.2.1) | Status / Alignment |
| :--- | :--- | :--- | :--- |
| **Dual Cursor** | Lexicographical physical coordinate $(R_{etcd}, S_{idx})$; logical sequence $L_{app}$. | Confirmed. Reconciled $L_{app}$ as strictly epoch-scoped ($L_{app} \in [1, \infty)$ per epoch). | Aligned & Closed |
| **Watch Resumption** | Resume at $R_{persisted}$; filter $S_{idx} \le S_{persisted}$ and $L_{app} \le A_{app}$. | Confirmed. Sub-index filtering preserved; post-compaction catch-up resumes at snapshot physical revision. | Aligned & Closed |
| **Replay Verification** | In-memory `appliedIndices` (B.1). | Two-tier verification: In-memory sliding window + PostgreSQL `witness_consensus_log` fallback. | Aligned & Closed |
| **Compaction Rule** | Described conceptually as $R_{comp} < R$. | Exact mathematical formula: $R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$. | Aligned & Closed |
| **BigInt Hashing** | String-quoted representation (B.1). | Type-Tagged Canonical Format (TTCF-v1): `bi:<digits>`, completely collision-free against `n:<num>` and `"..."`. | Aligned & Closed |

---

## 8. Invariants & Failure Mode Matrix

### Table 8.1: Invariant Enforcement Across Execution Boundaries

| Invariant ID | Invariant Formal Statement | Enforcement Mechanism | Failure Action |
| :--- | :--- | :--- | :--- |
| **INV-PREC-01** | $\forall e, \mathbf{ID}_{\text{entry}} = (cluster\_id, epoch\_id, log\_index)$ is unique. | PostgreSQL `PRIMARY KEY (epoch_id, log_index)`. | SQLSTATE 23505 on collision. |
| **INV-PREC-02** | $L_{app}$ within an active epoch advances as $L_{k+1} = L_k + 1\text{n}$. | `ConsensusStateMachine.apply()` contiguity guard. | Throws `LogicalIndexGapError`. |
| **INV-PREC-03** | Pruned entry ($L_{app} < \text{floor}$) must verify against DB before duplicate ACK. | Tier 2 `PostgresWitnessStore` query against `witness_consensus_log`. | Throws `HistoricalIndexConflictError` or `UnverifiableHistoricalEntryError`. |
| **INV-PREC-04** | etcd compaction must not exceed durable snapshot revision. | Automated compaction gate assertion: $R_{comp} \le R_{snap} - \Delta$. | Compaction job aborts with error; WAL retained. |
| **INV-PREC-05** | BigInt, Number, and String serializations are mutually disjoint. | TTCF-v1 prefixing (`bi:`, `n:`, `"`). | Type collision mathematically impossible. |

---

## 9. Remaining Open Questions for User Alignment

1. **Compaction Automation Frequency:**  
   Should etcd compaction be driven by an external periodic cron job (e.g. every 30 minutes with $\Delta_{buffer} = 50,000$ revisions), or triggered dynamically by PostgreSQL snapshot completion? (Recommended: Hybrid — PostgreSQL snapshot completion emits a compaction watermark to etcd).
2. **Snapshot Storage Destination:**  
   For Stage 2-B.2, should `ApplicationStateSnapshot` blobs be stored directly in a dedicated PostgreSQL table (`witness_snapshots`), or staged to disk / S3 with metadata in PostgreSQL? (Recommended: PostgreSQL bytea/jsonb table for Stage 2-B.2; S3 object storage for multi-region Stage 3-A).

---

## 10. File Metadata and Cryptographic SHA-256 Manifest

| File Path | Description | SHA-256 Digest |
| :--- | :--- | :--- |
| `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` | Deliverable Precision Amendment Document | Generated on write |
| `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md` | Base Architecture Decision Document | `6267F7C27194082782AFBC65F6710C038C29DF95EDA938848EEA3635E4095914` |
| `src/witness/state-machine-types.ts` | State machine contract types | `B51B425A3EE05BDB935D9B6DA86C6EF6C3ACA97D1F5ED099EDB0F8181C102363` |
| `src/witness/state-machine.ts` | State machine reducer implementation | `D1B8D9DACB2E08CAF2E1CA7E5969C78FDE8DDD93830DA9DD156E013C272C4B0A` |
| `test/witness/state-machine.test.ts` | State machine unit tests | `225E61468548A97F0775536C3972DC6B92FF8805D0AD125CFC8354822A910A2C` |
