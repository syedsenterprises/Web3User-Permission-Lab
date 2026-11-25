# Web3User — Milestone 13-D / Stage 2-B.3
## Production Readiness Assessment (Read-Only)

**Document ID:** `docs/M13-D-STAGE-2B3-PRODUCTION-READINESS-ASSESSMENT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.3 (Production Readiness Assessment)  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Assessment Date:** November 25, 2026  
**Authorization Scope:** Read-only inspection and planning only  
**Accepted Development Baseline:** `docs/M13-D-STAGE-2B2-FORMAL-CLOSURE-RECORD.md` (SHA-256: `746479E4B3BF07F16E9A8EDD829484FFCEF57B70F274E92270A6449B00E75CD7`)  
**Production Deployment & Automatic Compaction Status:** **NOT AUTHORIZED (BLOCKED)**

---

## 1. Executive Assessment

Milestone 13-D **Stage 2-B.2 (Persistent State-Machine Integration)** achieved **implementation acceptance** across Steps 1–7 (`929/929` tests passing across `44/44` test files, `0` failed, `0` skipped, `0` TypeScript build errors). However, **implementation acceptance does not equal production readiness**.

This Stage 2-B.3 read-only assessment evaluates the operational, cloud-storage, distributed-cluster, database, observability, and deployment-governance gaps separating the accepted Stage 2-B.2 development baseline from safe production operation:

1. **Core Algorithms & Local Persistence:** The `TTCF-v1` / `Canon-v1` serializer, `ConsensusStateMachine` bounded retention (`INV-RET-01`), Migration 004 schema/rollback, `PostgresConsensusStore` two-phase publication (`INV-AUTH-01`), `SnapshotManager` crash-consistent lifecycle (`INV-SNAP-01`), and `CompactionCoordinator` safety invariant (`INV-COMP-01`) are **verified locally** against live `PostgreSQL 16.15`, local POSIX storage, and single-node `etcd v3.5.18`.
2. **Primary Production Blockers:**
   - **Cloud Object Storage (`S3SnapshotStorageBackend` / `GcsSnapshotStorageBackend`):** Verified only against in-memory test doubles; live AWS S3 and GCP GCS SDK adapters, IAM policies, retries, and lifecycle behavior are **NOT VERIFIED**.
   - **Multi-Node etcd Raft Cluster:** Verified only against single-node `etcd v3.5.18`; multi-node leader election/failover during `kv.compact()` and cluster-wide watch recovery are **NOT VERIFIED**.
   - **24-Hour Operational Baseline:** No live 24-hour Prometheus scrape of `etcd_debugging_mvcc_current_revision` has been collected; `operationalBaselineVerified` remains `false` and `automaticCompactionEnabled` remains **disabled (`false`)**.
   - **PostgreSQL Production Governance & Runbooks:** Least-privilege runtime role grants (`web3user_app`), production pool/timeout sizing, PITR alignment, and deployment/rollback runbooks are **BLOCKED** pending staging provisioning and ops sign-off.

**Bottom Line:** Production deployment and automatic etcd compaction **MUST remain NOT AUTHORIZED** until all P0 blockers in Section 6 are closed with auditable staging and telemetry evidence.

---

## 2. Detailed Readiness Matrix

| Domain / Requirement | Status | Local Test Evidence (Verified) | Live-Environment Evidence (Staging / Prod) | Gap / Blocker Summary |
| :--- | :---: | :--- | :--- | :--- |
| **Canonical Serialization (`TTCF-v1` & `Canon-v1`)** | `VERIFIED` | `canonical-ttcf.test.ts` (52 tests), `receipt-canonicalization.test.ts`; pure deterministic JS/TS | N/A (pure CPU/memory deterministic logic) | None. Byte-for-byte parity verified. |
| **State Machine Retention & Backpressure** | `VERIFIED` | `state-machine.test.ts`; `INV-RET-01` & `BackpressurePolicy` verified | N/A (pure reducer logic) | None. |
| **PostgreSQL Migration 004 DDL & Rollback** | `PARTIALLY VERIFIED` | `migration-004.test.ts` & `consensus-store.test.ts` on local `PostgreSQL 16.15` (forward, rollback, reapply, lock order) | Staging/prod DBA rehearsal, lock-wait impact on live traffic, and backup pre-check **not run** | Requires staging migration rehearsal with `web3user_migrator` role. |
| **`PostgresConsensusStore` Persistence & Replay** | `PARTIALLY VERIFIED` | `consensus-store.test.ts` (25 tests on local `PG 16.15`, `statementTimeoutMs`, FIFO mutex, `EPOCH_ADVANCE`, crash hooks) | Multi-process failover, prod pool sizing, and `web3user_app` least-privilege role **not verified** | Requires staging multi-process + least-privilege DB verification. |
| **`SnapshotManager` — POSIX Backend** | `PARTIALLY VERIFIED` | `snapshot-manager.test.ts` on local Windows/POSIX (6-step atomic write, `DELETING` recovery, leases) | Production host `rootDir` ownership/permissions and symlink isolation (`F-STEP5-03`) **not verified** | Hardening recommended if shared hosts are used. |
| **`SnapshotManager` — AWS S3 Backend** | `NOT VERIFIED` | In-memory `S3ObjectStorageAdapter` double (`If-None-Match: *`, `ChecksumSHA256`, `ContentMD5`, `412`) | Live AWS S3 SDK adapter, IAM least-privilege, KMS, retries, and lifecycle **not executed** | **P0 Blocker** if S3 backend is selected for prod. |
| **`SnapshotManager` — GCP GCS Backend** | `NOT VERIFIED` | In-memory `GcsObjectStorageAdapter` double (`ifGenerationMatch: 0`, `CRC32C`, `byteSize`) | Live GCP GCS SDK adapter, IAM least-privilege, retries, and lifecycle **not executed** | **P0 Blocker** if GCS backend is selected for prod. |
| **`CompactionCoordinator` — Single-Node & Invariant** | `PARTIALLY VERIFIED` | `compaction-coordinator.test.ts` (6 tests on real `etcd v3.5.18` + `PG 16.15` `pg_try_advisory_lock`) | Production advisory lock contention & multi-instance coordination **not observed** | Requires staging multi-instance soak. |
| **Multi-Node etcd Raft Failover & Compaction** | `NOT VERIFIED` | Simulated via fault-injected `EtcdCompactionClient` (`ETCD_TIMEOUT`, `ETCD_UNAVAILABLE`, `ALREADY_COMPACTED`) | Live 3-node/5-node etcd cluster leader change during `kv.compact()` **not executed** | **P0 Blocker** for production HA etcd clusters. |
| **24-Hour Prometheus Baseline & Auto-Compaction** | `BLOCKED` | `calculateDimensionalSafetyBuffer()` unit-tested; `operationalBaselineVerified` gate enforced | 24-hour `etcd_debugging_mvcc_current_revision` scrape **not collected** | **P0 Blocker**; `automaticCompactionEnabled` must stay `false`. |
| **PostgreSQL Backup / PITR & Runtime Roles** | `BLOCKED` | Migrations contain no hardcoded prod roles (`web3user_app` / `web3user_migrator` externalized) | Least-privilege SQL grants & PITR + snapshot alignment drill **not executed** | **P0 Blocker** before production deployment. |
| **Deployment Controls, Runbooks & Sign-Off** | `BLOCKED` | Read-only verification & formal closure complete | Pre-deploy checklist, incident runbooks, and founder/ops sign-off **not completed** | **P0 Blocker** before production deployment. |

---

## 3. Advisory Disposition Register (F-STEP5-01 through F-STEP6-02)

All six Low-severity advisory findings from Steps 5 and 6 are preserved below with full risk assessment and disposition:

| ID | Original Description | Impact | Likelihood | Current Mitigation | Residual Risk | Recommended Disposition | Required Evidence to Close |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **F-STEP5-01** | `verifyAndDeserializeSnapshot()` does not explicitly validate `m.epochState` enum or `Number.isSafeInteger(m.epochHeight)`. | Low (corrupt/forged payload rejected by hash; only affects malformed manifests if hash-matched) | Very Low | Outer `SHA-256` + canonical `integrityHash` bound to trusted PostgreSQL `witness_snapshots` row. | Very Low | **Harden in Stage 2-B.3** (optional low-effort guard) | Unit test rejecting invalid `epochState` / non-safe `epochHeight` with `SnapshotIntegrityError`. |
| **F-STEP5-02** | Retrying `createAndPublishSnapshot()` at exact `(cluster_id, epoch_id, snapshot_index)` after mid-staging crash hits `witness_snapshots_pkey` (`23505`) until `cleanupSnapshots()` purges expired `STAGED` row. | Low (temporary inability to re-snapshot that exact index until grace period expires) | Low | Fail-closed; subsequent indices succeed normally; `cleanupSnapshots()` purges expired `STAGED` rows after 1h grace. | Low | **Accept as Designed** (document in operator runbook) | Runbook entry documenting `STAGED` grace-period cleanup behavior. |
| **F-STEP5-03** | `PosixSnapshotStorageBackend.resolveSafePath()` uses lexical `path.resolve()` without `fs.realpathSync()` symlink resolution. | Medium on shared hosts; Low on dedicated service host | Low | `assertSafeIdentifier()` blocks `..`/`/`; safe when `rootDir` is owned exclusively by witness service user. | Low–Medium (env-dependent) | **Harden Before Shared-Host POSIX Prod**; otherwise **Accept with Host Control** | Either `fs.realpathSync()` containment patch + symlink test, or deployment verification of exclusive `rootDir` ownership (`0700`). |
| **F-STEP5-04** | `snapshot-manager.test.ts` lacks dedicated assertions for `storage.delete()` throwing non-`ENOENT` and `loadAndVerifyStrict()` rejecting a `STAGED` row. | Low (test coverage gap on secondary error branches) | Low | Covered indirectly by `DELETING` resume and `loadAndVerify` tests. | Low | **Close in Stage 2-B.3 Test Hardening** | Two targeted unit/integration tests in `test/witness/snapshot-manager.test.ts` passing. |
| **F-STEP6-01** | `SnapshotManager.cleanupSnapshots()` does not acquire the compaction advisory lock. | Low (theoretical race only if grace period + `last_snapshot_hash` were bypassed) | Very Low | 1-hour grace period + `witness_raft_state.last_snapshot_hash` protection + `INV-COMP-01` safety buffer. | Very Low | **Accept as Mitigated** (optional future lock alignment) | Confirm 1-hour grace >= max compaction cycle + runbook note. |
| **F-STEP6-02** | `Etcd3CompactionClient.getStatus()` leaves `compactedRevision` undefined across process restarts until compaction or `ALREADY_COMPACTED`. | Low (first post-restart compaction may receive `ALREADY_COMPACTED` and reconcile) | Medium (on restart) | `ALREADY_COMPACTED` reconciles idempotently against etcd and updates `lastSuccessfulCompactionRevision`. | Very Low | **Accept as Mitigated** (optional status bootstrap on startup) | Multi-node restart test confirming idempotent `ALREADY_COMPACTED` reconciliation. |

---

## 4. Validation Plans

### 4.1 Cloud Storage Validation Plan (AWS S3 & GCP GCS)

*Constraint: Do not connect to or modify live production cloud resources. Execute only in an isolated staging account/project.*

1. **Adapter Implementation & Transport Parity:**
   - Implement production `S3ObjectStorageAdapter` (`@aws-sdk/client-s3`) and `GcsObjectStorageAdapter` (`@google-cloud/storage`) conforming to `src/witness/snapshot-manager.ts` interfaces.
   - Verify exact URI layout (`s3://<bucket>/snapshots/<clusterId>/<epochId>/<snapshotId>.snap` and `gs://<bucket>/<clusterId>/<epochId>/<snapshotId>.snap`).
2. **Conditional Writes & Object Integrity:**
   - **AWS S3:** Verify `IfNoneMatch: "*"` returns HTTP `412` on duplicate key -> mapped to `SnapshotCollisionError`; verify `ChecksumSHA256` and `ContentMD5` headers are enforced by S3 and verified on response (`putAndVerify()`).
   - **GCP GCS:** Verify `ifGenerationMatch: 0` returns HTTP `412` on existing object -> mapped to `SnapshotCollisionError`; verify `crc32cBase64` and `byteSize` parity on upload and download.
3. **Authentication, IAM Least-Privilege & Encryption:**
   - Use workload identity / IAM role (IRSA / GKE Workload Identity), never static keys.
   - Scope IAM permissions strictly to the dedicated snapshot bucket/prefix: `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`, `s3:ListBucket` (S3) and `storage.objects.create`, `storage.objects.get`, `storage.objects.delete`, `storage.objects.list` (GCS).
   - Verify KMS / SSE encryption compatibility with `ChecksumSHA256` / `CRC32C`.
4. **Retries, Failure Recovery & Lifecycle Cleanup:**
   - Test transient `503` / `429` / network timeouts during `putObject`, `getObject`, and `deleteObject`.
   - Verify `cleanupSnapshots()` 1-hour grace period, `DELETING` two-phase deletion, and idempotent `deleteObject` when object is already absent (`404`/`NoSuchKey`).
   - Confirm bucket Object Versioning / Retention policies do not silently block `DELETING` cleanup or mask `If-None-Match: *`.

### 4.2 Multi-Node etcd Validation Plan

*Constraint: Do not run compaction against staging-live or production clusters. Execute only against an isolated ephemeral 3-node or 5-node `etcd v3.5.18` test cluster.*

1. **Cluster Topology:** Deploy a 3-node `etcd v3.5.18` cluster with mTLS/client-auth matching staging topology.
2. **Raft Leader Changes & Failover:**
   - Trigger `CompactionCoordinator.runCompactionOnce()` while killing or stepping down the Raft leader mid-`kv.compact()`.
   - Verify client reconnects to the new leader, retries boundedly up to `maxRetries`, and reconciles cleanly without advancing `lastSuccessfulCompactionRevision` on uncertain outcomes.
3. **Physical Compaction & Lost-Response Reconciliation:**
   - Inject network drop after `kv.compact()` reaches etcd but before the gRPC response returns; verify subsequent run receives `ALREADY_COMPACTED` and reconciles idempotently (`status: "ALREADY_COMPACTED"`).
   - Verify `EtcdCompactedError` on watch streams triggers snapshot + suffix catch-up via `PostgresConsensusStore.recover()` without event loss or duplication.
4. **Process & Node Restarts:**
   - Restart the witness process across compaction cycles (`F-STEP6-02`) and verify `ALREADY_COMPACTED` reconciliation and `pg_try_advisory_lock` release on connection drop.

### 4.3 PostgreSQL Operational Readiness

*Constraint: Do not access or modify staging/production databases during this assessment.*

1. **Runtime Roles & Least-Privilege Grants:**
   - **`web3user_app` (Runtime Service Role):**
     - `witness_consensus_log`: `SELECT, INSERT` (no `UPDATE`/`DELETE` — append-only).
     - `witness_raft_state`: `SELECT, INSERT, UPDATE`.
     - `witness_snapshots`: `SELECT, INSERT, UPDATE, DELETE` (required for `STAGED -> COMMITTED -> DELETING` and post-`DELETING` cleanup).
     - `witness_snapshot_leases`: `SELECT, INSERT, UPDATE, DELETE`.
     - No DDL (`CREATE`, `ALTER`, `DROP`), no `TRUNCATE`, no superuser.
   - **`web3user_migrator` (Migration Role):** Used strictly during maintenance/migration windows to execute `004_d3_consensus_persistence.sql` or `004_d3_consensus_persistence.rollback.sql`.
2. **Migration Ownership & Rollback Governance:**
   - Enforce pre-migration backup/snapshot and verify Migration 004 lock acquisition order (`witness_raft_state` `EXCLUSIVE` -> `witness_consensus_log` `SHARE ROW EXCLUSIVE`) during a low-traffic or maintenance window.
3. **Connection Pool & Timeout Requirements:**
   - Configure `statementTimeoutMs` (`SET LOCAL statement_timeout`) on both `PostgresConsensusStore` and `SnapshotManager` (e.g., `5000ms–15000ms` depending on batch/IO profile), plus `pg.Pool` `connectionTimeoutMillis`, `idleTimeoutMillis`, and bounded `max` pool size.
   - Ensure `CompactionCoordinator` holds the session advisory lock (`pg_try_advisory_lock(hashtext($1), hashtext($2))`) on a dedicated `PoolClient` that is always unlocked and released in `finally`.
4. **Backup & Recovery Alignment:**
   - Enable PostgreSQL continuous WAL archiving (PITR) and align snapshot object-store retention (`1h+` grace) so any PITR restore point has valid `COMMITTED` snapshots or contiguous `witness_consensus_log` entries.

### 4.4 Observability & 24-Hour Prometheus Operational Baseline

1. **Required Metrics (`CompactionMetricsSnapshot` + etcd + PostgreSQL):**
   - **CompactionCoordinator (`getMetrics()`):** `currentEtcdRevision`, `currentCompactedRevision`, `latestVerifiedSnapshotRevision`, `pgPersistedRevision`, `configuredSafetyBuffer`, `calculatedSafeBoundary`, `lastSuccessfulCompactionRevision`, `lastAttemptedCandidateRevision`, `lastCompactionError`, `automaticCompactionEnabled`, `operationalBaselineVerified`, `compactionLag`, `warningTriggered`.
   - **etcd Server Metrics:** `etcd_debugging_mvcc_current_revision`, `etcd_debugging_mvcc_db_total_size_in_bytes`, `etcd_debugging_mvcc_db_total_size_in_use_in_bytes`, `etcd_disk_backend_commit_duration_seconds`.
   - **PostgreSQL & Snapshot Metrics:** Transaction latency, `statement_timeout` cancellations, `40P01` deadlock count (expected `0`), pool wait count, snapshot creation/upload/cleanup latency and error counts.
2. **Required Dashboards & Alerts:**
   - **Alerts:** `compactionLag > lagWarningThreshold` (`warningTriggered == true`), `lastCompactionError != null` for >2 consecutive cycles, `etcd_debugging_mvcc_db_total_size_in_bytes > 75%` quota, PostgreSQL persistence lag exceeding `BackpressurePolicy` threshold, or snapshot `STAGED`/`DELETING` backlog growth.
3. **Requirements to Enable `operationalBaselineVerified: true`:**
   - Collect **>= 24 continuous hours** of production (or production-mirrored) Prometheus telemetry of `etcd_debugging_mvcc_current_revision` and watch reconnect duration.
   - Compute empirical `revisionRateP99PerSecond` and `reconnectP99Seconds`, calibrate `safetyBuffer` via `calculateDimensionalSafetyBuffer()`, attach the signed calibration report, and obtain explicit Founder + SRE sign-off before setting `operationalBaselineVerified: true` (which is enforced by `CompactionConfigurationError` if `automaticCompactionEnabled: true` is attempted without it).

---

## 5. Prioritized Remediation Roadmap & Dependencies

| Priority | Work Item | Dependencies | Target Phase |
| :---: | :--- | :--- | :--- |
| **P0** | Implement & stage-test live `S3ObjectStorageAdapter` / `GcsObjectStorageAdapter` (IAM, conditional PUT, checksums, retries) | Staging AWS/GCP bucket + Workload Identity | Stage 2-B.3 (Pre-Prod) |
| **P0** | Execute 3-node/5-node `etcd v3.5.18` Raft leader-failover & compaction reconciliation test suite | Isolated multi-node etcd testbed | Stage 2-B.3 (Pre-Prod) |
| **P0** | Provision & verify PostgreSQL `web3user_app` / `web3user_migrator` roles, pool/timeout config, and PITR + snapshot alignment | Staging PostgreSQL 16 instance | Stage 2-B.3 (Pre-Prod) |
| **P0** | Deploy with `automaticCompactionEnabled: false` to collect 24-hour Prometheus baseline & calibrate `safetyBuffer` | Observability stack + staging/shadow soak | Stage 2-B.4 (Baseline) |
| **P1** | Close `F-STEP5-04` (2 secondary test assertions) and `F-STEP5-01` (explicit enum/safe-integer check) | Authorized Stage 2-B.3 remediation | Stage 2-B.3 (Hardening) |
| **P1** | Close `F-STEP5-03` (`fs.realpathSync()` containment) if POSIX backend is used on shared hosts | Authorized Stage 2-B.3 remediation | Stage 2-B.3 (Hardening) |
| **P2** | Optional hardening for `F-STEP6-01` and `F-STEP6-02` | None | Post-GA / Backlog |

---

## 6. Explicit Production Blockers

Production deployment and automatic compaction are **BLOCKED** by the following four items:
1. **No live AWS S3 / GCP GCS adapter verification** (`S3SnapshotStorageBackend` / `GcsSnapshotStorageBackend` tested only with in-memory doubles).
2. **No live multi-node etcd Raft failover compaction verification** (tested only on single-node `etcd v3.5.18`).
3. **No 24-hour Prometheus `etcd_debugging_mvcc_current_revision` baseline** (`operationalBaselineVerified` is `false`; `automaticCompactionEnabled` is `false`).
4. **No verified production PostgreSQL runtime role grants, PITR alignment, or operational deployment/rollback runbooks.**

---

## 7. Production Deployment Controls & Evidence Required to Authorize Next Phase

### 7.1 Deployment Controls, Runbooks & Approval Gates
- **Pre-Deployment Checks:** Verify Migration 004 SHA-256 (`98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341`), take pre-migration PostgreSQL snapshot, verify `automaticCompactionEnabled: false`, and confirm `web3user_app` least-privilege grants.
- **Rollback Strategy:** Application binary rollback + `004_d3_consensus_persistence.rollback.sql` (`85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74`) only after verifying no active `STAGED`/`COMMITTED` snapshot dependencies require Migration 004 columns, or restore from pre-migration PITR point.
- **Operational Runbooks Required:** (1) `ETCD_COMPACTED` watch recovery; (2) stuck `STAGED` / `DELETING` snapshot cleanup (`F-STEP5-02`); (3) PostgreSQL lock-wait / `statement_timeout` triage; (4) emergency compaction disable (`automaticCompactionEnabled: false`).
- **Approval Gates:** Separate Founder authorizations required for (a) Stage 2-B.3 remediation/staging validation, (b) production deployment with automatic compaction **disabled**, and (c) enabling `operationalBaselineVerified: true` + `automaticCompactionEnabled: true` after the 24-hour baseline.

### 7.2 Evidence Required to Authorize the Next Phase
1. Passing live AWS S3 / GCP GCS staging integration test report (with IAM policy audit & conditional-write `412` proof).
2. Passing isolated 3-node `etcd v3.5.18` leader-failover compaction & watch-recovery report.
3. Staging PostgreSQL `web3user_app` least-privilege grant verification & PITR restore drill report.
4. Completed operational runbooks and deployment checklist.

---

## 8. Checksum & Git Governance

- **Governance:** Read-only assessment; zero source, test, migration, configuration, historical report, roadmap, or mindmap files modified; zero production/staging access; zero git commits, pushes, merges, deployments, or compaction activation.
- **Document SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-STAGE-2B3-PRODUCTION-READINESS-ASSESSMENT.md`.
