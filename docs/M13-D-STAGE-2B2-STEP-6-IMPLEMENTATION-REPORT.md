# Web3User — Milestone 13-D / Stage 2-B.2 / Step 6
## Implementation Report: CompactionCoordinator

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-6-IMPLEMENTATION-REPORT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 6  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Date:** November 25, 2026  
**Status:** COMPLETE — AWAITING INDEPENDENT ACCEPTANCE AUDIT  

---

## 1. Architecture Decisions Followed

- **ADR-M13D-013 & INV-COMP-01 (Physical Compaction Safety):** Enforces $R_{comp} \le \min(R_{snap}, R_{pg\_persisted}) - \Delta_{buffer}$ strictly in 64-bit physical etcd MVCC revisions (`bigint`), never conflating logical consensus indices (`appLogIndex`) with physical revisions.
- **Stage 2-B.2 Final Architecture Gate (Multi-Event Revision Completeness):** Treats tip revision $R_{last}$ in `witness_raft_state` conservatively as $R_{last} - 1$ unless `confirmedCompleteRevision >= R_last` proves all sub-indices of $R_{last}$ are durably committed.
- **Dimensional Buffer & Disabled-by-Default Gating:** Implements `calculateDimensionalSafetyBuffer()` ($\Delta_{buffer} = \max(\Delta_{buffer\_min}, \lceil S_f \times R_{rate\_p99} \times T_{reconnect\_p99} \rceil)$) and gates automatic compaction (`automaticCompactionEnabled = false` by default) behind `operationalBaselineVerified: true`.
- **Preservation of Step 5 Advisory Findings:** Step 5's `F-STEP5-01` through `F-STEP5-04` remain untouched in `snapshot-manager.ts`; `CompactionCoordinator` delegates snapshot verification to `SnapshotManager.loadAndVerify()` without duplicating verification logic or weakening snapshot safety.

---

## 2. Files Created and Modified

| File Path | Action | Purpose |
| :--- | :--- | :--- |
| `src/witness/compaction-coordinator.ts` | **Created** | `CompactionCoordinator`, pure `calculateCompactionEligibility()`, `calculateDimensionalSafetyBuffer()`, `Etcd3CompactionClient`, advisory locking, and structured metrics. |
| `test/witness/compaction-coordinator.test.ts` | **Created** | 6 test suites/cases covering pure eligibility math, PostgreSQL 16 + `SnapshotManager` safety, fault-injected etcd outcomes, concurrency locking, and real `etcd v3.5.18` compaction. |
| `docs/M13-D-STAGE-2B2-STEP-6-IMPLEMENTATION-REPORT.md` | **Created** | This Step 6 implementation report. |

Zero pre-existing source files, migrations, or accepted historical reports were modified.

---

## 3. Eligibility Formula and Safety Proof

`calculateCompactionEligibility()` evaluates:
1. Validates `safetyBuffer > 0n`, `alreadyCompactedRevision >= 0n`, and optional `maxRevisionAdvancePerOp > 0n`.
2. Returns `NO_OP` (`eligible: false`) if `snapshotRevision === null`, `pgPersistedRevision === null`, or either is `<= 0n`.
3. Computes `minDurable = min(snapshotRevision, pgPersistedRevision)`.
4. Underflow guard: if `minDurable <= safetyBuffer`, returns `NO_OP` (`BELOW_SAFETY_BUFFER`), preventing `0n` or negative compaction.
5. `safeBoundary = minDurable - safetyBuffer`. If `safeBoundary <= alreadyCompactedRevision`, returns `NO_OP` (`ALREADY_COMPACTED_OR_NO_PROGRESS`).
6. Applies optional `maxRevisionAdvancePerOp` cap and asserts `0n < candidate <= safeBoundary` and `candidate > alreadyCompactedRevision`.

---

## 4. Snapshot and PostgreSQL Watermark Validation

- **PostgreSQL Durability (`readVerifiedPgDurability`):** Queries `witness_raft_state` (`last_consecutive_persisted_index`, `last_applied_etcd_revision`) and verifies `MAX(log_index) <= last_consecutive_persisted_index` in `witness_consensus_log`. Never substitutes `last_consecutive_persisted_index` for `etcd_revision`. Conservatively returns `R_last - 1` unless `confirmedCompleteRevision >= R_last`.
- **Snapshot Eligibility (`readVerifiedSnapshotRevision`):** Queries `witness_snapshots` (`status = 'COMMITTED'`, `snapshot_index <= L_c_persisted`, `ORDER BY snapshot_index DESC`), delegates cryptographic verification to `SnapshotManager.loadAndVerify()`, and verifies `etcdRevision > 0n` and `snapshotIndex` parity. `STAGED`, `DELETING`, and corrupt snapshots are rejected.

---

## 5. etcd API Integration

- `Etcd3CompactionClient` wraps the pinned `etcd3` (`etcd v3.5.18`) client API:
  - `maintenance.status()` for `currentRevision`.
  - `kv.compact({ revision: revision.toString(), physical: true }, { deadline: Date.now() + timeoutMs })` bounded by `withDeadline()`.
- Translates `"required revision has been compacted"` into `ALREADY_COMPACTED` (`alreadyCompacted: true`), timeouts into `ETCD_TIMEOUT` (failing closed without advancing `lastSuccessfulCompactionRevision`), and transient unavailability/leader errors into `ETCD_UNAVAILABLE` (bounded retry up to `maxRetries`).

---

## 6. Configuration and Disabled-by-Default Behavior

- `automaticCompactionEnabled` defaults to `false`; `operationalBaselineVerified` defaults to `false`.
- Attempting to construct `CompactionCoordinator` with `automaticCompactionEnabled: true` and `operationalBaselineVerified !== true` throws `CompactionConfigurationError`.
- Constructor never triggers compaction on startup.
- `runAutomaticTick()` returns `AUTOMATIC_DISABLED` when disabled and enforces `minCompactionIntervalMs` (`RATE_LIMITED`).
- `runManualCompaction()` executes all safety invariants, snapshot verification, PostgreSQL durability checks, and cross-process locking without bypass.

---

## 7. Failure Recovery and Idempotency

- **Cross-Process Coordination:** Uses PostgreSQL session advisory locks (`pg_try_advisory_lock(hashtext('compaction:' || clusterId), hashtext(epochId))`) released in `finally`, avoiding holding `witness_raft_state` row locks during external etcd RPCs.
- **Uncertain Outcomes:** Timeouts (`ETCD_TIMEOUT`) and lost responses fail closed without advancing `lastSuccessfulCompactionRevision`. Subsequent runs reconcile against PostgreSQL, `SnapshotManager`, and etcd status; if etcd already compacted the revision, `ALREADY_COMPACTED` is handled idempotently.

---

## 8. Monitoring and Operational Safeguards

`getMetrics()` exposes a frozen `CompactionMetricsSnapshot`:
- `currentEtcdRevision`, `currentCompactedRevision`, `latestVerifiedSnapshotRevision`, `pgPersistedRevision`, `configuredSafetyBuffer`, `calculatedSafeBoundary`, `lastSuccessfulCompactionRevision`, `lastAttemptedCandidateRevision`, `lastCompactionError`, `automaticCompactionEnabled`, `operationalBaselineVerified`, `compactionLag`, and `warningTriggered`.
- No synthetic Prometheus baseline is claimed; `operationalBaselineVerified` remains `false` by default until a 24-hour production observation window of `etcd_debugging_mvcc_current_revision` and reconnect p99 is completed.

---

## 9. Test Commands and Actual Results

| Check | Command | Exit Code | Result | Scope |
| :--- | :--- | :---: | :--- | :--- |
| Step 6 Suite | `npx vitest run test/witness/compaction-coordinator.test.ts` | `0` | **6 passed (6)** | Unit + PostgreSQL 16.15 + Fault-Injected etcd + Real `etcd v3.5.18` |
| Witness Regressions (9 files) | `npx vitest run test/witness/snapshot-manager.test.ts test/witness/consensus-store.test.ts test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/migration-004.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts test/witness/migration-003.test.ts` | `0` | **187 passed (187)** | Unit + Live PostgreSQL 16.15 |
| TypeScript Build | `npm run build` (`tsc -p tsconfig.build.json`) | `0` | **0 errors** | Full `src/` compilation |

---

## 10. PostgreSQL and etcd Integration Evidence

- **PostgreSQL:** `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit` (isolated disposable DBs `web3user_test_comp_*` and `web3user_test_comp_real_*`).
- **etcd:** Pinned `etcd v3.5.18` (`.tmp/etcd-bin/v3.5.18/etcd.exe` via `RealEtcdProcess`) — verified real `Etcd3CompactionClient` compaction at `tipRev - 5n` and confirmed `EtcdCompactedError` on watch resumption at revision `1n`.

---

## 11. Remaining Risks and Limitations

- **24-Hour Telemetry Baseline:** Automatic compaction remains disabled until production Prometheus metrics (`etcd_debugging_mvcc_current_revision`, `witness_etcd_watch_reconnect_duration_seconds_bucket`) are calibrated over 24 hours.
- **No Durable Compaction History Table:** `lastSuccessfulCompactionRevision` is tracked in-memory on the coordinator instance and reconciled via `etcd` (`ALREADY_COMPACTED` / `getStatus()`) across restarts.

---

## 12. SHA-256 Hashes

| File Path | SHA-256 Checksum |
| :--- | :--- |
| `src/witness/compaction-coordinator.ts` | `40CCEA5C66D85C53BDD7B38B164EE459B6FD1E2373627B993BF1A0C252CA4224` |
| `test/witness/compaction-coordinator.test.ts` | `BF39D4C7E6EF4005933EB8395F75D8DC74D5C140C933890488DB6E182C1C04B7` |

---

## 13. Git Status and Governance Confirmation

- **Implemented, Unit-Tested, PostgreSQL-Tested & Real-etcd-Tested:** Pure eligibility math, dimensional buffer, disabled-by-default gating, advisory locking, fault-injected etcd error paths, and real `etcd v3.5.18` + PostgreSQL 16.15 + `SnapshotManager` compaction.
- **Governance:** Zero production compaction, zero staging/production DB access, zero git commits/pushes/merges, all pre-existing files preserved. Stopping here for independent acceptance audit.
