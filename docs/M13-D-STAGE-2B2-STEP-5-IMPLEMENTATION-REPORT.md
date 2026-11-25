# Web3User — Milestone 13-D / Stage 2-B.2 / Step 5
## Implementation Report: SnapshotManager

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-5-IMPLEMENTATION-REPORT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 5  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Date:** November 25, 2026  
**Status:** COMPLETE — AWAITING INDEPENDENT ACCEPTANCE AUDIT  

---

## 1. Architecture Decisions Followed

- **ADR-M13D-012 (Multi-Backend Snapshot Storage & 6-Step POSIX Protocol):** Separates local POSIX atomic rename + `fsync` + readback SHA-256 verification (`PosixSnapshotStorageBackend`) from object-storage conditional PUTs (`S3SnapshotStorageBackend` with `If-None-Match: *` + `ChecksumSHA256`/`ContentMD5`, `GcsSnapshotStorageBackend` with `ifGenerationMatch: 0` + `CRC32C`).
- **INV-SNAP-01 (Authoritative Snapshot Durability):** A snapshot is eligible for recovery if and only if its metadata row is durably `COMMITTED` in `witness_snapshots`.
- **Stage 2-B.2 Final Architecture Gate (3-State Lifecycle & Race-Safe Cleaner):** Enforces `STAGED -> COMMITTED -> DELETING` under Migration 004 trigger `trg_witness_snapshots_lifecycle`, active publication leases in `witness_snapshot_leases`, a 1-hour (`3600s`) grace period, and `SELECT ... FOR UPDATE` delayed-writer re-check prior to orphan deletion.
- **ADR-M13D-014 (TTCF-v1 / Canon-v1):** Snapshot manifests embed a canonical `integrityHash` computed via `computeCanonicalPayloadHash(manifest, canonicalizationVersion)` supporting both `1` and `2` (omitting `undefined` optional fields such as `PolicyRecord.definitionJson` for TTCF-v1 compliance).

---

## 2. Files Created and Modified

| File Path | Action | Purpose |
| :--- | :--- | :--- |
| `src/witness/snapshot-manager.ts` | **Created** | `SnapshotManager`, deterministic serialization/verification, `PosixSnapshotStorageBackend`, `S3SnapshotStorageBackend`, `GcsSnapshotStorageBackend`, lease management, and race-safe cleanup. |
| `test/witness/snapshot-manager.test.ts` | **Created** | 10 PostgreSQL 16 + POSIX FS + S3/GCS adapter integration tests covering creation, integrity, restoration, leases, triggers, and crash boundaries. |
| `docs/M13-D-STAGE-2B2-STEP-5-IMPLEMENTATION-REPORT.md` | **Created** | This Step 5 implementation report. |

Zero pre-existing source files, migrations, or accepted historical reports were modified.

---

## 3. Snapshot Creation Design

- `createAndPublishSnapshot(state, options)` rejects `INITIAL` / empty epochs (`EMPTY_EPOCH_SNAPSHOT_FORBIDDEN`), empty `epochId`, and uncommitted states (`lastAppliedAppIndex > lastConsecutivePersistedAppIndex`).
- `serializeApplicationStateSnapshot()` deterministically sorts maps/sets, converts `BigInt` fields to decimal strings, computes `integrityHash` (`computeCanonicalPayloadHash(manifest, canonVersion)`), and computes outer SHA-256 (`snapshotHash`) + `byteSize`.
- Because Migration 004's `trg_witness_snapshots_lifecycle` makes all metadata columns immutable upon `INSERT`, `snapshotHash`, `byteSize`, and `storageUri` are computed in memory before inserting the `STAGED` row.

---

## 4. Durable Publication Protocol

1. **Lease Acquisition:** `acquireLease()` inserts/reclaims an active lease in `witness_snapshot_leases` (`clock_timestamp() + ttl`).
2. **Staged Metadata (`STAGED`):** `insertStagedSnapshotRow()` locks `witness_raft_state` `FOR SHARE`, verifies `last_consecutive_persisted_index >= state.lastAppliedAppIndex`, and inserts `witness_snapshots` with `status = 'STAGED'`.
3. **Storage Upload & Verification:** `storage.putAndVerify()` writes and verifies the payload (POSIX 6-step rename + `fsync` + readback SHA-256; S3 conditional PUT + SHA-256; GCS `ifGenerationMatch: 0` + CRC32C).
4. **Atomic Commit (`COMMITTED`):** `commitStagedSnapshot()` locks `witness_raft_state` `FOR UPDATE`, verifies the active lease is still held, transitions `witness_snapshots` `STAGED -> COMMITTED`, advances `last_snapshot_index` / `last_snapshot_hash` monotonically, and deletes the lease in one ACID transaction. On failure in steps 2–4, best-effort `releaseLease()` runs and `STAGED` is never exposed to recovery.

---

## 5. Integrity and Verification Design

`verifyAndDeserializeSnapshot(bytes, expected)` checks:
- Exact `byteSize` and outer `SHA-256` (`expected.snapshotHash`).
- Valid JSON envelope, `formatVersion === 1`, `canonicalizationVersion IN (1, 2)` matching `expected.canonicalizationVersion`.
- Recomputed canonical `integrityHash` parity.
- Exact `clusterId`, `epochId`, `snapshotIndex`, `chainHeadHash`, and `lastPhysicalCursor` (`etcdRevision`, `subIndex`) parity against the trusted PostgreSQL `PersistedSnapshotRecord`.
- Rehydrates frozen `ReadonlyFrozenMap`, `ReadonlyFrozenSet`, and `BigInt` fields without silent repair.

---

## 6. Restoration and Recovery Integration

- `SnapshotManager` implements `ConsensusSnapshotLoader` (`loadAndVerify` + `loadAndVerifyStrict`) without duplicating `PostgresConsensusStore.recover()` logic.
- `loadAndVerifyStrict()` verifies `witness_snapshots.status === 'COMMITTED'`, fetches bytes from storage, and runs `verifyAndDeserializeSnapshot()`.
- `loadAndVerify()` returns `null` on missing/corrupt snapshots so `PostgresConsensusStore.recover()` falls back to an earlier `COMMITTED` snapshot or genesis, replays contiguous suffix entries from `witness_consensus_log`, and verifies `chainHeadHash` across epoch boundaries (`EPOCH_ADVANCE`).

---

## 7. Lease and Cleanup Design

- **Leases:** `acquireLease()`, `renewLease()`, and `releaseLease()` operate on `witness_snapshot_leases` using PostgreSQL `clock_timestamp()` so cross-process workers coordinate safely in PostgreSQL.
- **Cleanup (`cleanupSnapshots`):**
  1. Transitions eligible `STAGED` (expired/unleased past grace period) and superseded `COMMITTED` (beyond `retainCount`, past grace period, unreferenced by `witness_raft_state.last_snapshot_hash`, and unleased) rows to `DELETING` inside a PostgreSQL transaction (`witness_raft_state` locked `FOR SHARE` first, then `witness_snapshots` `FOR UPDATE`).
  2. Resumes any pre-existing `DELETING` rows from interrupted runs.
  3. Deletes the object from storage (`storage.delete()` is idempotent on `ENOENT`/404).
  4. Deletes the `witness_snapshots` row (`WHERE status = 'DELETING'`).
  5. Scans `storage.listObjects()` for orphan files older than `gracePeriodSeconds`, verifies no active lease and `SELECT 1 FROM witness_snapshots FOR UPDATE` returns 0 rows, then deletes the orphan.

---

## 8. Crash-Consistency Evidence

Verified in `test/witness/snapshot-manager.test.ts`:
- Crash after `STAGED` insert (`onAfterStagedInsert`): row stays `STAGED`; `recover()` ignores it and replays from log.
- Crash after `DELETING` transition (`onAfterDeletingTransition`): next `cleanupSnapshots()` run resumes `DELETING`, deletes storage file and DB row.
- Crash after storage delete (`onAfterStorageDelete`): next `cleanupSnapshots()` run idempotently deletes DB row.
- Concurrent cleanup workers (`Promise.all`): serialize safely without double-delete errors.

---

## 9. PostgreSQL Integration Evidence

- **Engine:** `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit` (isolated disposable DB `web3user_test_snap_*` with `schema.sql` + `004_d3_consensus_persistence.sql`).
- Verified live: `trg_witness_snapshots_lifecycle` immutability enforcement, invalid transition rejection (`COMMITTED -> STAGED`), direct `DELETE` rejection on non-`DELETING` rows, `witness_snapshot_leases` contention/renewal/expiry, and `PostgresConsensusStore.recover()` integration.

---

## 10. Test Commands, Counts, and Actual Results

| Check | Command | Exit Code | Result | Scope |
| :--- | :--- | :---: | :--- | :--- |
| Step 5 Suite | `npx vitest run test/witness/snapshot-manager.test.ts` | `0` | **10 passed (10)** | Live PostgreSQL 16.15 + real POSIX FS + mocked S3/GCS adapters |
| Step 4 Suite | `npx vitest run test/witness/consensus-store.test.ts` | `0` | **25 passed (25)** | Live PostgreSQL 16.15 |
| Witness Regressions (7 files) | `npx vitest run test/witness/state-machine.test.ts test/witness/canonical-ttcf.test.ts test/witness/migration-004.test.ts test/witness/receipt-canonicalization.test.ts test/witness/lock-order-compatibility.test.ts test/witness/disposal-and-recovery.test.ts test/witness/migration-003.test.ts` | `0` | **152 passed (152)** | Unit + live PostgreSQL 16.15 |
| TypeScript Build | `npm run build` (`tsc -p tsconfig.build.json`) | `0` | **0 errors** | Full `src/` compilation |

---

## 11. Security and Operational Review

- **SQL Parameterization:** All queries use `$1..$N` bind parameters; `statementTimeoutMs` is validated as a non-negative integer.
- **Path Traversal Prevention:** `assertSafeIdentifier()` rejects `..`, `/`, `\`, and null bytes; `PosixSnapshotStorageBackend.resolveSafePath()` enforces `rootDir` containment.
- **Zero Trust in External Objects:** `verifyAndDeserializeSnapshot()` never trusts external manifest fields without matching PostgreSQL `PersistedSnapshotRecord` + `SHA-256` + canonical `integrityHash`.

---

## 12. Remaining Limitations

- **Cloud Provider Live Integration:** `S3SnapshotStorageBackend` and `GcsSnapshotStorageBackend` are verified with deterministic in-memory `S3ObjectStorageAdapter` / `GcsObjectStorageAdapter` test doubles; live AWS S3 and GCP GCS bucket integration was not executed (no cloud credentials/buckets in local test scope).
- **Large Snapshot Memory:** Serialization buffers the snapshot JSON in memory (`Buffer`); streaming chunked snapshot encoding is not implemented.
- **Step 6 Scope:** `CompactionCoordinator` and etcd watch compaction gating remain deferred to Step 6.

---

## 13. SHA-256 Hashes

| File Path | SHA-256 Checksum |
| :--- | :--- |
| `src/witness/snapshot-manager.ts` | `C58F204033763A4368D7652DDF069E8D79CD6EAB2C476340F6C0713838E8BF4C` |
| `test/witness/snapshot-manager.test.ts` | `0DD052CF24A6F4FBB4706BFD9013962145FC2C25CF2DBE0BB5F3E2F906CF9288` |

---

## 14. Git Status and Governance Confirmation

- **Implemented & PostgreSQL/POSIX-Verified:** `SnapshotManager`, POSIX 6-step backend, leases, lifecycle triggers, cleanup/orphan handling, and `PostgresConsensusStore` restoration.
- **Adapter-Tested (Mocked Provider):** `S3SnapshotStorageBackend` and `GcsSnapshotStorageBackend`.
- **Governance:** Zero git commits, pushes, merges, or deployments; zero staging/production access; all pre-existing files preserved. Stopping here for independent acceptance audit prior to Step 6.
