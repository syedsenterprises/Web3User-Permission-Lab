# Web3User — Milestone 13-D / Stage 2-B.2 / Step 3
## Remediation Report: F-STEP3-02 and F-STEP3-03

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-REPORT.md`  
**Milestone:** 13-D Consensus Engine & State Machine (Stage 2-B.2 Step 3 Remediation)  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Authorization:** Founder-approved remediation of findings from `docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md`  
**Date:** November 24, 2026  

---

## 1. Executive Summary & Audit Context

Following the **Step 3 Independent Acceptance Audit** (`docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md`), which delivered a verdict of **ACCEPTED WITH CONDITIONS**, the founder authorized targeted remediation of the two identified code/DDL findings:

1. **F-STEP3-02 (Low Severity): Table Lock Acquisition Order Inversion**
2. **F-STEP3-03 (Low Severity): Rollback Proposal Index Definition Parity**

Both items have been remediated in the SQL migration files, verified with new regression tests, and audited for zero regression impact across all existing test suites.

---

## 2. Itemized Remediations

### 2.1 Remediation of F-STEP3-02 — Table Lock Acquisition Order

#### Original Audit Reference:
- Audit Finding: `F-STEP3-02` (Section 5, `docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md`)
- File: `src/witness/migrations/004_d3_consensus_persistence.sql` lines 13–16

#### Problem Analysis:
Migration 004 previously acquired table locks in the order:
1. `LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;`
2. `LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;`

However, application write transactions (as specified for `PostgresConsensusStore` in Step 4) acquire row locks on `witness_raft_state` first via `SELECT ... FOR UPDATE` (which acquires a table-level `ROW SHARE` lock), and subsequently execute `INSERT INTO witness_consensus_log` (which acquires a table-level `ROW EXCLUSIVE` lock).

If Migration 004 were executed concurrently with application write activity, an interleaved lock acquisition could trigger a PostgreSQL deadlock (`40P01`):
- Application holds `ROW SHARE` on `witness_raft_state`, requests `ROW EXCLUSIVE` on `witness_consensus_log`.
- Migration holds `SHARE ROW EXCLUSIVE` on `witness_consensus_log`, requests `EXCLUSIVE` on `witness_raft_state`.

#### Technical Correction:
The lock acquisition order in `004_d3_consensus_persistence.sql` was inverted to lock `witness_raft_state` first:
```sql
-- Before:
LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;

-- After:
LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;
LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;
```

#### Technical Justification & Concurrency Preservation:
1. **Deadlock Freedom:** Aligning the migration's table lock acquisition hierarchy (`witness_raft_state` $\to$ `witness_consensus_log`) with the application transaction hierarchy eliminates lock inversion deadlocks.
2. **Unweakened Protection:** Both locks remain held within the single outer transaction (`BEGIN ... COMMIT`). `EXCLUSIVE` on `witness_raft_state` blocks any concurrent transaction attempting `SELECT ... FOR UPDATE` or state updates. `SHARE ROW EXCLUSIVE` on `witness_consensus_log` blocks any concurrent transaction attempting `INSERT`, `UPDATE`, or `DELETE`. Concurrent writers cannot insert duplicate proposals or alter log sequences during preflight or contiguous backfill.

---

### 2.2 Remediation of F-STEP3-03 — Rollback Proposal Index Definition Parity

#### Original Audit Reference:
- Audit Finding: `F-STEP3-03` (Section 5, `docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md`)
- File: `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` lines 83–87

#### Problem Analysis:
In Migration 003 (`003_d3_consensus_state.sql` line 149), the original non-unique proposal index was defined as:
```sql
CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id 
ON witness_consensus_log (proposal_id) 
WHERE proposal_id IS NOT NULL;
```
In Migration 004, this was replaced by a composite partial unique index:
```sql
CREATE UNIQUE INDEX IF NOT EXISTS uq_consensus_log_proposal_id
ON witness_consensus_log (epoch_id, proposal_id)
WHERE proposal_id IS NOT NULL;
```
However, the rollback script `004_d3_consensus_persistence.rollback.sql` inadvertently restored a composite non-unique index on `(epoch_id, proposal_id)` rather than restoring Migration 003's single-column index on `(proposal_id)`.

#### Technical Correction:
The rollback script was updated to restore the exact original index definition:
```sql
-- Before:
DROP INDEX IF EXISTS uq_consensus_log_proposal_id;
CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id
ON witness_consensus_log (epoch_id, proposal_id)
WHERE proposal_id IS NOT NULL;

-- After:
DROP INDEX IF EXISTS uq_consensus_log_proposal_id;
CREATE INDEX IF NOT EXISTS idx_consensus_log_proposal_id
ON witness_consensus_log (proposal_id)
WHERE proposal_id IS NOT NULL;
```

#### Technical Justification:
Executing the rollback now guarantees 100% byte-for-byte fidelity with the Migration 003 schema baseline.

---

## 3. Regression Tests & Test Evidence

`test/witness/migration-004.test.ts` was updated with explicit assertions for both remediations:
1. **Lock Ordering Assertion (Test 2 & Test 13):**
   ```typescript
   const raftLockIndex = migration004Sql.indexOf("LOCK TABLE witness_raft_state IN EXCLUSIVE MODE;");
   const logLockIndex = migration004Sql.indexOf("LOCK TABLE witness_consensus_log IN SHARE ROW EXCLUSIVE MODE;");
   expect(raftLockIndex).toBeGreaterThan(-1);
   expect(logLockIndex).toBeGreaterThan(-1);
   expect(raftLockIndex).toBeLessThan(logLockIndex);
   ```
2. **Rollback Proposal Index Parity (Test 11 & Test 13):**
   ```typescript
   expect(rollback004Sql).toMatch(
     /CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+idx_consensus_log_proposal_id\s+ON\s+witness_consensus_log\s*\(proposal_id\)\s+WHERE\s+proposal_id\s+IS\s+NOT\s+NULL;/
   );
   expect(rollback004Sql).not.toContain("ON witness_consensus_log (epoch_id, proposal_id)");
   ```

### 3.1 Focused Migration 004 Test Execution
```
> npx vitest run test/witness/migration-004.test.ts

 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/migration-004.test.ts (18 tests) 10ms

 Test Files  1 passed (1)
      Tests  18 passed (18)
   Start at  15:03:53
   Duration  257ms (transform 49%, import 25%, tests 15%, worker 11%)
```

### 3.2 Full Witness Regression Test Execution
```
> npx vitest run test/witness/migration-004.test.ts test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts

 RUN  v5.0.5 C:/Users/syeds/Projects/Web3User

 ✓ test/witness/lock-order-compatibility.test.ts (5 tests) 8370ms
 ✓ test/witness/disposal-and-recovery.test.ts (3 tests) 486ms
 ✓ test/witness/receipt-canonicalization.test.ts (30 tests) 25ms
 ✓ test/witness/state-machine.test.ts (32 tests) 20ms
 ✓ test/witness/canonical-ttcf.test.ts (52 tests) 16ms
 ✓ test/witness/migration-004.test.ts (18 tests) 12ms

 Test Files  6 passed (6)
      Tests  140 passed (140)
   Start at  15:04:02
   Duration  10.55s (tests 93%, import 5%, transform 1%)
```

### 3.3 TypeScript Build Compilation
```
> npm run build
> web3user-permission-lab@0.1.0-rc.1 build
> tsc -p tsconfig.build.json
```
Exit code `0` with zero diagnostic errors.

---

## 4. Cryptographic File Checksums (SHA-256)

| File Path | SHA-256 Checksum | Classification |
| :--- | :--- | :--- |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | `98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341` | Remediated Forward SQL |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | `85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74` | Remediated Rollback SQL |
| `test/witness/migration-004.test.ts` | `521E9315BCF8DFB09051C70783E46A6A7F72F1C362FAE7E4FC87D8B83FA6FD01` | Remediated Test Suite |
| `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-REPORT.md` | *(This file)* | Remediation Report |

---

## 5. Scope Verification & Governance Boundaries

- **Files Modified:**
  - `src/witness/migrations/004_d3_consensus_persistence.sql`
  - `src/witness/migrations/004_d3_consensus_persistence.rollback.sql`
  - `test/witness/migration-004.test.ts`
- **Files Created:**
  - `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-REPORT.md`
- **Preserved Artifacts:** All original reports (`M13-D-STAGE-2B2-STEP-3-IMPLEMENTATION-REPORT.md`, `M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md`), earlier Step 1 & Step 2 sources, and funding records remain untouched.
- **Database Safety:** Neither Migration 004 nor its rollback was executed against any PostgreSQL database.
- **Git State:** Zero commits, zero pushes, zero PR updates.

---

## 6. Remaining Risks & Unresolved Conditions

- **Condition 1 (Unverified Live DB Execution):** As required by governance, live DDL execution against a database was not executed. Live execution against an ephemeral PostgreSQL instance remains an explicit milestone requirement for Step 4 integration testing.
- **Maintenance Window Planning:** While the corrected lock order prevents deadlocks with application writers, executing large migrations during a designated low-traffic or maintenance window remains a recommended best practice.

---

## 7. Conclusion

Remediations for **F-STEP3-02** and **F-STEP3-03** are complete, mathematically justified, and verified by 18 unit tests and 140 regression tests.

Stopping in accordance with audit guidelines to await fresh independent audit closure and founder authorization.
