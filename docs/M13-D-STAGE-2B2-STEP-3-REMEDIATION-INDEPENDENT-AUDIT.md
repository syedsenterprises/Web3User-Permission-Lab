# Web3User — Milestone 13-D / Stage 2-B.2 / Step 3
## Independent Remediation Audit: F-STEP3-02 and F-STEP3-03

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-INDEPENDENT-AUDIT.md`  
**Milestone:** 13-D Consensus Engine & State Machine (Stage 2-B.2 Step 3 Remediation Audit)  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Audit Target:** Remediation of Findings `F-STEP3-02` and `F-STEP3-03`  
**Audit Date:** November 25, 2026  
**Auditor:** Independent PostgreSQL Migration & Consensus Systems Auditor  
**Verdict:** **ACCEPTED** (F-STEP3-01 retained as a separately tracked Step 4 integration condition)  

---

## 1. Executive Summary & Audit Mandate

This independent remediation audit evaluates the authorized code and DDL corrections resolving findings **F-STEP3-02** and **F-STEP3-03** from the Step 3 Independent Acceptance Audit (`docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md`).

The audit independently reviewed the actual repository SQL files, application transaction hierarchy, regression test suite, and rollback definitions without relying solely on author claims or remediation report narratives.

### Audit Verdict: **ACCEPTED**
- **F-STEP3-02 Resolved:** Migration 004 table lock acquisition order has been inverted to lock `witness_raft_state` in `EXCLUSIVE` mode prior to acquiring `SHARE ROW EXCLUSIVE` on `witness_consensus_log`. This aligns with the application transaction write hierarchy (`witness_raft_state` $\to$ `witness_consensus_log`) and eliminates `40P01` deadlock cycles. Concurrency protection against uncommitted writes during preflight and backfill is fully preserved.
- **F-STEP3-03 Resolved:** `004_d3_consensus_persistence.rollback.sql` has been corrected to restore `idx_consensus_log_proposal_id` on `(proposal_id) WHERE proposal_id IS NOT NULL`, establishing exact schema parity with Migration 003 line 149.
- **F-STEP3-01 Retained as Step 4 Integration Gate:** In accordance with audit governance, live execution of Migration 004 against an ephemeral PostgreSQL test database remains an explicit milestone requirement for Step 4 integration testing before production deployment.

---

## 2. Inspected Artifacts & Cryptographic Identity

| File Path | SHA-256 Checksum | Classification |
| :--- | :--- | :--- |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | `98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341` | Remediated Forward SQL |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | `85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74` | Remediated Rollback SQL |
| `test/witness/migration-004.test.ts` | `521E9315BCF8DFB09051C70783E46A6A7F72F1C362FAE7E4FC87D8B83FA6FD01` | Remediated Test Suite |
| `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-REPORT.md` | `13369895AA8449D3FABE7F0CB653EC15F1A0B3848667C991BA26D3F25757B6C1` | Remediation Report |
| `docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md` | `87D9CD8731419210ED9681D0EC26157007867179EDA2C41025618E1CA44E83CA` | Baseline Audit Document |
| `src/witness/migrations/003_d3_consensus_state.sql` | `C7E05E1C3FAED9B3BCE312BF0016E5572DF032483838E75C417A5785C0A4FE06` | Migration 003 Reference |

---

## 3. Independent Audit of Finding F-STEP3-02 (Lock Ordering)

### 3.1 Source Verification
Inspection of `src/witness/migrations/004_d3_consensus_persistence.sql` lines 10–19:
```sql
-- EXCLUSIVE blocks concurrent write access and row-level locking on witness_raft_state,
-- aligning with application transaction lock hierarchy (witness_raft_state -> witness_consensus_log)
-- to prevent 40P01 deadlocks during concurrent execution.
LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;

-- SHARE ROW EXCLUSIVE blocks concurrent INSERT, UPDATE, DELETE on witness_consensus_log
-- while permitting concurrent read transactions.
LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;
```

### 3.2 Application Transaction Hierarchy Analysis
1. **Application Transaction Hierarchy:**
   Tracing the consensus write path in `docs/M13-D-STAGE-2B2-IMPLEMENTATION-PLAN.md` (lines 353–362) and `test/witness/lock-order-compatibility.test.ts` demonstrates the exact order of operation:
   - Step 1: `SELECT * FROM witness_raft_state WHERE cluster_id = $1 AND epoch_id = $2 FOR UPDATE;` (acquires row-level exclusive lock, which takes a table-level `ROW SHARE` lock on `witness_raft_state`).
   - Step 2: `INSERT INTO witness_consensus_log (...) VALUES (...);` (takes a table-level `ROW EXCLUSIVE` lock on `witness_consensus_log`).
   - Step 3: Domain projection mutations.
   - Step 4: `UPDATE witness_raft_state SET ...;` (updates row in `witness_raft_state`).
2. **Deadlock Freedom Proof:**
   - Under the previous ordering (`consensus_log` $\to$ `raft_state`), a concurrent writer holding `ROW SHARE` on `witness_raft_state` while requesting `ROW EXCLUSIVE` on `witness_consensus_log` clashed with the migration holding `SHARE ROW EXCLUSIVE` on `witness_consensus_log` while requesting `EXCLUSIVE` on `witness_raft_state`, forming an AB-BA deadlock cycle (`40P01`).
   - Under the corrected ordering (`witness_raft_state` $\to$ `witness_consensus_log`):
     - Migration attempts `LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;`. If an application writer is in progress, the migration blocks at step 1 before touching `witness_consensus_log`.
     - Conversely, if the migration acquires `EXCLUSIVE` on `witness_raft_state` first, any subsequent application transaction attempting `SELECT ... FOR UPDATE` blocks at step 1 before touching `witness_consensus_log`.
     - Both migration and application acquire locks strictly in the order `witness_raft_state` $\to$ `witness_consensus_log`.
     - **Result:** No circular wait can develop. Deadlock freedom is mathematically proven.
3. **Sufficiency of Concurrency Protection:**
   - Both table locks are acquired inside `BEGIN TRANSACTION; ... COMMIT;` prior to running preflight duplicate proposal checks (lines 22–38) or the contiguous durability backfill (lines 173–239).
   - `SHARE ROW EXCLUSIVE` on `witness_consensus_log` continues to block concurrent `INSERT`, `UPDATE`, and `DELETE`.
   - `EXCLUSIVE` on `witness_raft_state` continues to block all concurrent modifications.
   - Zero concurrent writes can invalidate preflight checks or the contiguous-prefix calculation.

---

## 4. Independent Audit of Finding F-STEP3-03 (Rollback Proposal Index Parity)

### 4.1 Schema Comparison
1. **Migration 003 Definition (`003_d3_consensus_state.sql` lines 149–151):**
   ```sql
   CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id 
   ON witness_consensus_log (proposal_id) 
   WHERE proposal_id IS NOT NULL;
   ```
2. **Remediated Rollback Definition (`004_d3_consensus_persistence.rollback.sql` lines 83–87):**
   ```sql
   DROP INDEX IF EXISTS uq_consensus_log_proposal_id;

   CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id
   ON witness_consensus_log (proposal_id)
   WHERE proposal_id IS NOT NULL;
   ```

### 4.2 Reversibility & Parity Analysis
- **Exact Parity Established:**
  - Index Name: `idx_consensus_log_proposal_id` (identical).
  - Target Table: `witness_consensus_log` (identical).
  - Indexed Column: `(proposal_id)` (strictly single-column, identical).
  - Partial Predicate: `WHERE proposal_id IS NOT NULL;` (identical).
  - Uniqueness: Non-unique (`CREATE INDEX`, identical).
- **Idempotency & Stale Definition Safety:**
  `DROP INDEX IF EXISTS uq_consensus_log_proposal_id;` is executed immediately prior to index creation. Because the original `idx_consensus_log_proposal_id` was dropped during forward migration (line 44 of `004_d3_consensus_persistence.sql`), `CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id` creates the index cleanly without preserving any incompatible definition.
- **Result:** The forward and rollback scripts constitute an exact, reversible pair returning the schema to the exact Migration 003 baseline.

---

## 5. Regression Test Adequacy & Critique

### 5.1 Test Assertions Evaluated
In `test/witness/migration-004.test.ts`:
1. **Lock Ordering Assertion (Test 2 & Test 13):**
   ```typescript
   const raftLockIndex = migration004Sql.indexOf("LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;");
   const logLockIndex = migration004Sql.indexOf("LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;");
   expect(raftLockIndex).toBeGreaterThan(-1);
   expect(logLockIndex).toBeGreaterThan(-1);
   expect(raftLockIndex).toBeLessThan(logLockIndex);
   ```
   *Audit assessment:* Proves that `witness_raft_state` lock statement occurs strictly prior to `witness_consensus_log` in the forward SQL string. Would fail if the lock order were reverted.
2. **Rollback Index Parity Assertion (Test 11 & Test 13):**
   ```typescript
   expect(rollback004Sql).toMatch(
     /CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+idx_consensus_log_proposal_id\s+ON\s+witness_consensus_log\s*\(proposal_id\)\s+WHERE\s+proposal_id\s+IS\s+NOT\s+NULL;/
   );
   expect(rollback004Sql).not.toContain("ON witness_consensus_log (epoch_id, proposal_id)");
   ```
   *Audit assessment:* Strict regex assertion enforcing exact single-column definition and negative assertion ensuring composite `(epoch_id, proposal_id)` definition is absent. Would fail if composite definition or missing predicate were present.

### 5.2 Test Limits (Text Assertions vs Live Engine Behavior)
- The tests are static text assertions and deterministic TypeScript algorithmic simulations.
- They prove that the authored SQL text matches the specification, but do not execute against a running PostgreSQL engine.
- As established under governance, live database DDL execution was unauthorized during Step 3.
- This limitation is formally recognized and tracked under **F-STEP3-01**.

---

## 6. Verification of Execution Evidence & Scope Integrity

### 6.1 Subsystem Execution Evidence
Independent verification commands were executed during this audit:
1. `npx vitest run test/witness/migration-004.test.ts`: **18 passed (18)**.
2. Full subsystem regression suite: **140 passed (140)** across 6 test suites (`migration-004`, `state-machine`, `canonical-ttcf`, `receipt-canonicalization`, `lock-order-compatibility`, `disposal-and-recovery`).
3. TypeScript build (`npm run build` / `tsc -p tsconfig.build.json`): **0 errors, exit code 0**.

### 6.2 Scope Verification & Working Tree Cleanliness
- **Modified files:**
  - `src/witness/migrations/004_d3_consensus_persistence.sql`
  - `src/witness/migrations/004_d3_consensus_persistence.rollback.sql`
  - `test/witness/migration-004.test.ts`
- **Created files:**
  - `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-REPORT.md`
  - `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-INDEPENDENT-AUDIT.md` (this report)
- **Unmodified historical records:** All previous implementation reports, audit documents, and funding artifacts remain completely untouched.
- **Database Safety:** Zero migrations executed against any live database.
- **Git State:** Zero commits, zero pushes, zero PR merges.

---

## 7. Retained Step 3 Integration Condition (F-STEP3-01)

Condition **F-STEP3-01** remains active and is transferred to the Step 4 entry gate:

> **Integration Condition F-STEP3-01:**  
> During authorized Step 4 integration testing (`consensus-store.test.ts`), forward Migration 004 and rollback must be executed against an ephemeral test PostgreSQL database to verify:
> 1. Complete PostgreSQL engine syntax and PL/pgSQL parsing.
> 2. Table lock acquisition behavior.
> 3. Constraint creation and trigger binding.
> 4. Clean rollback execution and schema restoration.
> This live validation must succeed before deployment to staging or production.

---

## 8. Final Audit Verdict

**Verdict:** **ACCEPTED**

### Audit Conclusion:
- **F-STEP3-02:** Table lock acquisition hierarchy is resolved, eliminating `40P01` deadlock cycles.
- **F-STEP3-03:** Rollback proposal index definition parity with Migration 003 is resolved.
- **F-STEP3-01:** Retained and tracked as an authorized Step 4 integration gate.

Milestone 13-D Stage 2-B.2 Step 3 remediation is fully accepted. Proceeding to **Step 4 (`PostgresConsensusStore`)** is recommended upon founder review and explicit authorization.
