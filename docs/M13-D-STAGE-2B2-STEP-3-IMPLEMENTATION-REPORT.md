# Web3User — Milestone 13-D / Stage 2-B.2 / Step 3
## PostgreSQL Migration 004 Implementation Report

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-3-IMPLEMENTATION-REPORT.md`  
**Milestone:** 13-D Consensus Engine & State Machine (Stage 2-B.2 Step 3)  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Status:** IMPLEMENTED & VERIFIED — READY FOR INDEPENDENT AUDIT  
**Date:** November 24, 2026  

---

## 1. Executive Summary & Authorization

Under explicit founder authorization for **Stage 2-B.2 / Step 3**, this implementation realizes **PostgreSQL Migration 004** (`004_d3_consensus_persistence.sql`), its paired rollback migration (`004_d3_consensus_persistence.rollback.sql`), and a comprehensive migration specification test suite (`test/witness/migration-004.test.ts`).

Migration 004 prepares the relational persistence layer for the persistent consensus engine, introducing physical cursor tracking, canonicalization version persistence, partial unique proposal indexing, snapshot lifecycle state management, and strict contiguous durability backfilling.

### Key Deliverables:
1. **Migration 004 SQL (`src/witness/migrations/004_d3_consensus_persistence.sql`):**
   - Implements table-level locking (`SHARE ROW EXCLUSIVE` on `witness_consensus_log`, `EXCLUSIVE` on `witness_raft_state`).
   - Executes preflight duplicate proposal checks (`HAVING COUNT(*) > 1`) and fails closed on violations.
   - Atomically swaps the non-unique proposal index for a partial unique index (`uq_consensus_log_proposal_id`).
   - Augments `witness_consensus_log` with `canonicalization_version SMALLINT` (constrained to `{1, 2}`) and `sub_index INT`.
   - Augments `witness_raft_state` with 5 physical cursor and snapshot tracking columns + non-negative check constraints.
   - Bootstraps missing `witness_raft_state` rows using the canonical `'default-cluster'` identity.
   - Backfills contiguous durability watermarks ($L_{c\_\text{persisted}}$) using a strict gap-detecting prefix series algorithm.
   - Creates `witness_snapshots` with comprehensive metadata and lifecycle status (`STAGED`, `COMMITTED`, `DELETING`).
   - Creates `witness_snapshot_leases` for race-safe orphan cleaner coordination.
   - Enforces a deep immutability and lifecycle state machine trigger on `witness_snapshots`.
2. **Rollback Migration SQL (`src/witness/migrations/004_d3_consensus_persistence.rollback.sql`):**
   - Active data safety guard: aborts if active snapshots or persisted revisions exist unless forced via `SET stage2b2.allow_destructive_rollback = true`.
   - Reverts all schema elements, triggers, functions, constraints, and tables cleanly back to the Migration 003 baseline.
3. **Specification Test Suite (`test/witness/migration-004.test.ts`):**
   - 17 unit tests verifying contract structure, transaction framing, locking syntax, preflight logic, schema definitions, deterministic contiguous backfill simulations, snapshot lifecycle constraints, and rollback safety.
   - Zero live database mutations executed (governance-compliant offline verification).

---

## 2. Source Modifications & Artifact Inventory

### Created Files:
1. `src/witness/migrations/004_d3_consensus_persistence.sql` (Forward Migration)
2. `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` (Guarded Rollback Migration)
3. `test/witness/migration-004.test.ts` (Migration Specification & Simulation Test Suite)

### Preserved Files (Step 1 & Step 2):
- `src/witness/canonical-serializer.ts`
- `src/witness/state-machine-types.ts`
- `src/witness/state-machine.ts`
- `test/witness/canonical-ttcf.test.ts`
- `test/witness/state-machine.test.ts`

---

## 3. Schema & Architecture Decisions

### 3.1 Cluster Identity Harmonization (`'default-cluster'`)
- In Migration 003, `witness_raft_state` established `cluster_id VARCHAR(64) NOT NULL DEFAULT 'default-cluster'`.
- Earlier technical challenge notes suggested `'default'`. Inspection of the live schema confirmed that `'default-cluster'` is the canonical cluster identifier.
- Migration 004 strictly uses `'default-cluster'` in all row bootstrap insertions, preserving 100% foreign key parity and default value compatibility:
  ```sql
  INSERT INTO witness_raft_state (
      cluster_id, epoch_id, last_applied_index, last_applied_term, ...
  )
  SELECT 'default-cluster', l.epoch_id, ...
  FROM witness_consensus_log l
  GROUP BY l.epoch_id
  ON CONFLICT (cluster_id, epoch_id) DO NOTHING;
  ```

### 3.2 Dual-Version Canonicalization Persistence
- Column `canonicalization_version SMALLINT NOT NULL DEFAULT 1` is added to `witness_consensus_log`.
- Governed by `CONSTRAINT chk_consensus_log_canon_ver CHECK (canonicalization_version IN (1, 2))`.
- Historical logs default to `1` (Canon-v1). Step 4+ logs persist `2` (TTCF-v1 / Canon-v2).
- Indexed via `CREATE INDEX IF NOT EXISTS idx_consensus_log_canon_ver ON witness_consensus_log (epoch_id, canonicalization_version);`.

### 3.3 Physical Cursor Decoupling & Durability Watermarks
- In `witness_raft_state`:
  - `last_applied_etcd_revision BIGINT NOT NULL DEFAULT 0` (etcd 64-bit MVCC revision).
  - `last_applied_sub_index INT NOT NULL DEFAULT 0` (0-based transaction sub-index).
  - `last_consecutive_persisted_index BIGINT NOT NULL DEFAULT 0` (contiguous durability watermark $L_{c\_\text{persisted}}$).
  - `last_snapshot_index BIGINT NOT NULL DEFAULT 0` ($I_{\text{snap}}$).
  - `last_snapshot_hash VARCHAR(64) NOT NULL DEFAULT ''`.
- In `witness_consensus_log`:
  - `sub_index INT NOT NULL DEFAULT 0` (stores event position within multi-event etcd transactions).

### 3.4 Snapshot Lifecycle & Lease Coordination
- `witness_snapshots` table fields:
  - `snapshot_id VARCHAR(64) NOT NULL` (UUID / content-derived ID)
  - `cluster_id VARCHAR(64) NOT NULL`
  - `epoch_id VARCHAR(64) NOT NULL`
  - `snapshot_index BIGINT NOT NULL`
  - `snapshot_hash VARCHAR(64) NOT NULL` (SHA-256 digest of blob)
  - `chain_head_hash VARCHAR(64) NOT NULL` (Recursive hash-chain verification root)
  - `etcd_revision BIGINT NOT NULL`
  - `sub_index INT NOT NULL`
  - `format_version SMALLINT NOT NULL DEFAULT 1`
  - `canonicalization_version SMALLINT NOT NULL DEFAULT 2`
  - `storage_backend VARCHAR(32) NOT NULL DEFAULT 'posix_fs'` (`CHECK (storage_backend IN ('posix_fs', 's3', 'gcs'))`)
  - `storage_uri VARCHAR(512) NOT NULL`
  - `byte_size BIGINT NOT NULL DEFAULT 0`
  - `status VARCHAR(16) NOT NULL DEFAULT 'COMMITTED'` (`CHECK (status IN ('STAGED', 'COMMITTED', 'DELETING'))`)
  - `created_at_seconds BIGINT NOT NULL`
  - `updated_at_seconds BIGINT NOT NULL`
  - Primary Key: `(cluster_id, epoch_id, snapshot_index)`
  - Unique: `(snapshot_id)`
- `witness_snapshot_leases` table fields:
  - `snapshot_id VARCHAR(64) PRIMARY KEY`
  - `worker_id VARCHAR(64) NOT NULL`
  - `expires_at TIMESTAMPTZ NOT NULL`
  - `created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()`

### 3.5 Deep Immutability & Lifecycle Trigger
- `trg_witness_snapshots_lifecycle_func()` enforces:
  - Zero modification to immutable snapshot metadata (`snapshot_id`, hashes, revisions, byte_size, storage URI).
  - Strict forward state transitions: `STAGED` $\to$ `COMMITTED` $\to$ `DELETING`.
  - Database row deletion permitted **ONLY** when `status = 'DELETING'`.
  - Statement-level truncation blocked via `trg_witness_snapshots_no_truncate`.

---

## 4. Locking Strategy & Concurrency Guard

During migration execution, concurrent writes could invalidate preflight duplicate checks or corrupt backfill calculations:
```sql
-- 1. Acquire table locks upfront
LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;
```
- `SHARE ROW EXCLUSIVE` on `witness_consensus_log` blocks concurrent `INSERT`, `UPDATE`, and `DELETE` transactions, while allowing concurrent read queries (`SELECT`).
- `EXCLUSIVE` on `witness_raft_state` blocks all concurrent modifications.
- Both locks are held until `COMMIT;` or `ROLLBACK;`.

---

## 5. Contiguous Durability Backfill Algorithm

Rather than relying on `MAX(log_index)` (which falsely advances durability watermarks across gaps), Migration 004 implements a contiguous-prefix verification algorithm scoped by `(cluster_id, epoch_id)`:

```sql
DO $$
DECLARE
    r RECORD;
    v_min_index BIGINT;
    v_max_index BIGINT;
    v_total_rows BIGINT;
    v_distinct_rows BIGINT;
    v_contiguous_max BIGINT;
    v_last_persisted_rev BIGINT;
    v_last_sub_idx INT;
BEGIN
    FOR r IN SELECT cluster_id, epoch_id, last_consecutive_persisted_index FROM witness_raft_state LOOP
        SELECT MIN(log_index), MAX(log_index), COUNT(*), COUNT(DISTINCT log_index)
        INTO v_min_index, v_max_index, v_total_rows, v_distinct_rows
        FROM witness_consensus_log
        WHERE epoch_id = r.epoch_id;

        IF v_total_rows = 0 THEN
            -- Scenario A: Empty Log -> Watermark 0
            UPDATE witness_raft_state
            SET last_consecutive_persisted_index = 0
            WHERE cluster_id = r.cluster_id AND epoch_id = r.epoch_id AND last_consecutive_persisted_index = 0;
        ELSE
            -- Scenario B: Non-1 Start -> Fail Closed
            IF v_min_index != 1 THEN
                RAISE EXCEPTION 'Migration 004 aborted: epoch % log_index does not start at 1 (starts at %). Durable prefix cannot be proven.', r.epoch_id, v_min_index;
            END IF;

            -- Scenario C: Duplicate Indices -> Fail Closed
            IF v_total_rows != v_distinct_rows THEN
                RAISE EXCEPTION 'Migration 004 aborted: duplicate log_index detected in epoch % (total %, distinct %). Inconsistent log history.', r.epoch_id, v_total_rows, v_distinct_rows;
            END IF;

            -- Scenario D: Detect Gaps via Contiguous Prefix Join [1, v_max_index]
            SELECT COALESCE(MIN(expected_index) - 1, v_max_index)
            INTO v_contiguous_max
            FROM (
                SELECT generate_series(1, v_max_index) AS expected_index
            ) exp
            LEFT JOIN witness_consensus_log act
              ON act.epoch_id = r.epoch_id AND act.log_index = exp.expected_index
            WHERE act.log_index IS NULL;

            -- Fail closed on any gap
            IF v_contiguous_max < v_max_index THEN
                RAISE EXCEPTION 'Migration 004 aborted: non-contiguous log index sequence in epoch % (contiguous reaches %, max index is %). Durable prefix cannot be proven.', r.epoch_id, v_contiguous_max, v_max_index;
            END IF;

            -- Scenario E: Fetch physical cursor at max contiguous index
            SELECT etcd_revision, sub_index
            INTO v_last_persisted_rev, v_last_sub_idx
            FROM witness_consensus_log
            WHERE epoch_id = r.epoch_id AND log_index = v_contiguous_max;

            -- Apply verified contiguous watermark and physical cursor
            UPDATE witness_raft_state
            SET last_consecutive_persisted_index = v_contiguous_max,
                last_applied_etcd_revision = COALESCE(v_last_persisted_rev, last_applied_etcd_revision),
                last_applied_sub_index = COALESCE(v_last_sub_idx, last_applied_sub_index)
            WHERE cluster_id = r.cluster_id AND epoch_id = r.epoch_id AND last_consecutive_persisted_index = 0;
        END IF;
    END LOOP;
END $$;
```

---

## 6. Rollback Guarantees & Active Data Safety

The rollback script `004_d3_consensus_persistence.rollback.sql` implements an active data safeguard:
1. **Accidental Rollback Prevention:**
   If `witness_snapshots` contains rows ($> 0$) or `witness_raft_state` has persisted revisions ($> 0$) or indices ($> 0$), the rollback script aborts immediately with `RAISE EXCEPTION`.
2. **Explicit Override:**
   A destructive rollback is only permitted if the session variable `stage2b2.allow_destructive_rollback` is explicitly set:
   ```sql
   SET stage2b2.allow_destructive_rollback = true;
   ```
3. **Clean Restoration:**
   - Drops `witness_snapshot_leases` and `witness_snapshots`.
   - Reverts `witness_raft_state` columns (`last_applied_etcd_revision`, `last_applied_sub_index`, `last_consecutive_persisted_index`, `last_snapshot_index`, `last_snapshot_hash`).
   - Reverts `witness_consensus_log` proposal index to non-unique (`idx_consensus_log_proposal_id`).
   - Drops `canonicalization_version` and `sub_index` from `witness_consensus_log`.
   - Fully returns database schema to the exact Migration 003 baseline.

---

## 7. Verification & Test Evidence

### 7.1 Focused Migration 004 Specification Suite
Command executed:
`npx vitest run test/witness/migration-004.test.ts`

```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/migration-004.test.ts (17 tests) 9ms

 Test Files  1 passed (1)
      Tests  17 passed (17)
   Start at  14:50:25
   Duration  215ms (transform 49%, import 26%, tests 14%, worker 11%)
```

### 7.2 Full Subsystem Regression Suite
Command executed:
`npx vitest run test/witness/migration-004.test.ts test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts`

```
 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/lock-order-compatibility.test.ts (5 tests) 4343ms
 ✓ test/witness/disposal-and-recovery.test.ts (3 tests) 435ms
 ✓ test/witness/receipt-canonicalization.test.ts (30 tests) 20ms
 ✓ test/witness/state-machine.test.ts (32 tests) 19ms
 ✓ test/witness/canonical-ttcf.test.ts (52 tests) 15ms
 ✓ test/witness/migration-004.test.ts (17 tests) 9ms

 Test Files  6 passed (6)
      Tests  139 passed (139)
   Start at  14:50:34
   Duration  6.32s (tests 89%, import 9%, transform 2%, worker 1%)
```

### 7.3 TypeScript Build Compilation
Command executed:
`npm run build` (`tsc -p tsconfig.build.json`)

Output:
```
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json
```
Compilation completed with return code `0` and zero diagnostics.

---

## 8. Cryptographic Hashes & File Identity

| File Path | SHA-256 Checksum |
| :--- | :--- |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | `0B05F227F72A34889B7AD8CCAFFD259091536C39C1AEC086E8739AE36DE92E65` |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | `B3F469D347704835DDF4D3B3FF07FCD5AD9FA3D4A9794E0D0267FF385AFF1175` |
| `test/witness/migration-004.test.ts` | `CA5F5C542AB26D3D6D2C19F2B8EB6C30E2FEFBC81F85B71E97E94E27FFCC92C3` |
| `src/witness/state-machine-types.ts` | `DD006076305D262D28CF1BA57C9FF762C516C916264AD04FD923726A8A3EC620` |
| `src/witness/state-machine.ts` | `C2CB8BFAF70D0F4D568DFB5CC23F8892FFB4E6869BAFEBB7850B9E949A1A9335` |
| `test/witness/state-machine.test.ts` | `3BF0051891E0A58DBA10727F005C8B1E33F64E7F58B19C5F95F9E90A139C73E8` |
| `src/witness/canonical-serializer.ts` | `DF8EA55DD5B0666BD4714E63C09A5D6AF1445BFFA6FCB21EF64D80746077D3F5` |
| `test/witness/canonical-ttcf.test.ts` | `C49DA311AA71C103564857B49CFD1DD813169789CFDCCAAC2A7CC8E143D00549` |

---

## 9. Scope Boundaries & Governance Compliance

### 9.1 Boundary Audit:
- **No Database Modification:** Migration 004 has **not** been applied to any production, staging, or development database.
- **No Step 4 Code:** `src/witness/consensus-store.ts` has **not** been created.
- **No Step 5 Code:** `src/witness/snapshot-manager.ts` has **not** been created.
- **No Step 6 Code:** `src/witness/compaction-coordinator.ts` has **not** been created.
- **No Wire/Protobuf Alterations:** Receipt schemas and protobuf interfaces remain untouched.
- **Zero Git Modifications:** Zero commits, zero pushes, zero PR updates.
- **Untracked Artifacts Preserved:** All architectural records and funding applications are intact.

---

## 10. Unverified Integration Requirement & Remaining Risks

### Unverified Live Database Execution Requirement:
Per explicit governance instructions, Migration 004 DDL was **not** applied to any database during this step. While all SQL scripts, table locks, preflight queries, backfill algorithms, and trigger definitions have been statically verified and algorithmically simulated in unit tests, live execution against an ephemeral PostgreSQL database instance will be verified during the Step 4 integration phase or upon separate founder authorization.

---

## 11. Conclusion & Recommendation

Milestone 13-D / Stage 2-B.2 / Step 3 is fully implemented, verified, and compliant with all accepted architecture decisions.

**Recommended Next Step:**
Submit this implementation report for the **Stage 2-B.2 Step 3 Independent Acceptance Audit**. Await audit closure and explicit founder authorization before proceeding to Step 4 (`PostgresConsensusStore`).
