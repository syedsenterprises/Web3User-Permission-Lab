# Web3User — Milestone 13-D / Stage 2-B.2 / Step 5
## Independent Acceptance Audit — SnapshotManager

**Document ID:** `docs/M13-D-STAGE-2B2-STEP-5-INDEPENDENT-AUDIT.md`  
**Milestone:** 13-D Distributed Consensus Engine — Stage 2-B.2 Step 5  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Audit Date:** November 25, 2026  
**Auditor:** Independent Distributed-Systems, PostgreSQL, Storage-Integrity & Security Auditor  
**Verdict:** **ACCEPTED**

---

## 1. Executive Verdict

**Verdict: ACCEPTED**

Independent inspection of `src/witness/snapshot-manager.ts`, `test/witness/snapshot-manager.test.ts`, Migration 004 triggers/constraints, and `PostgresConsensusStore` integration confirms that Step 5 (`SnapshotManager`) is architecturally compliant, crash-consistent, and fail-closed:

1. **Snapshot Serialization & Integrity:** Deterministic canonicalization supporting both Canon-v1 (`1`) and TTCF-v1 (`2`), outer `SHA-256` + `byteSize` + embedded canonical `integrityHash`, and strict metadata cross-verification against trusted PostgreSQL `PersistedSnapshotRecord` rows.
2. **Durable Publication & Crash Consistency (`STAGED -> COMMITTED -> DELETING`):** `STAGED` rows are never selected by `recover()`, `commitStagedSnapshot()` transitions `STAGED -> COMMITTED` atomically with `witness_raft_state` and lease release, and Migration 004's `trg_witness_snapshots_lifecycle` immutability trigger is respected.
3. **POSIX 6-Step Protocol & Object-Storage Adapters:** `PosixSnapshotStorageBackend` implements temp-file write, `fsync` file fd, atomic rename, parent-dir `fsync` (with Windows NTFS fallback), and readback SHA-256 verification. `S3SnapshotStorageBackend` and `GcsSnapshotStorageBackend` implement conditional preconditions (`If-None-Match: *`, `ifGenerationMatch: 0`) and transport checksums (`ChecksumSHA256`/`ContentMD5`, `CRC32C`), verified against deterministic in-memory adapters (live cloud provider integration not executed locally).
4. **Leases & Race-Safe Cleanup:** `witness_snapshot_leases` uses PostgreSQL `clock_timestamp()` for cross-process coordination; `cleanupSnapshots()` enforces the 1-hour grace period, active-lease checks, `witness_raft_state.last_snapshot_hash` protection, `DELETING` two-phase deletion, and `SELECT ... FOR UPDATE` delayed-writer re-checks.

Four **Low-severity** advisory findings (`F-STEP5-01` through `F-STEP5-04`) are documented for optional future hardening; none block Step 5 acceptance.

---

## 2. Files and Evidence Inspected

| Artifact | SHA-256 Checksum | Role |
| :--- | :--- | :--- |
| `src/witness/snapshot-manager.ts` | `C58F204033763A4368D7652DDF069E8D79CD6EAB2C476340F6C0713838E8BF4C` | Step 5 implementation under audit |
| `test/witness/snapshot-manager.test.ts` | `0DD052CF24A6F4FBB4706BFD9013962145FC2C25CF2DBE0BB5F3E2F906CF9288` | Step 5 PostgreSQL 16 + POSIX + S3/GCS suite (10 tests) |
| `docs/M13-D-STAGE-2B2-STEP-5-IMPLEMENTATION-REPORT.md` | `759A0137ADD8508FE8D565944BB41756EA34DD069B7F76DA38E3F700065C04BB` | Step 5 implementation report |
| `src/witness/consensus-store.ts` | `6262EB7C090C06ED000DF2E93AB2910828950A6AC6EFDCDFED32D116EE08F88F` | `ConsensusSnapshotLoader` consumer |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | `98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341` | `witness_snapshots`, `witness_snapshot_leases`, and lifecycle trigger |

**Observed Execution Evidence:**
- PostgreSQL server: `PostgreSQL 16.15, compiled by Visual C++ build 1944, 64-bit`.
- `npx vitest run test/witness/snapshot-manager.test.ts`: **10/10 passed** (exit code `0`).
- `npx vitest run test/witness/consensus-store.test.ts`: **25/25 passed** (exit code `0`).
- Witness regression suites (7 files): **152/152 passed** (exit code `0`).
- `npm run build` (`tsc -p tsconfig.build.json`): **0 errors** (exit code `0`).

---

## 3. Snapshot Integrity Assessment

- **Serialization (`src/witness/snapshot-manager.ts` lines 183–273):** Deterministically sorts all maps/sets, converts `BigInt` fields to decimal strings, omits `undefined` `PolicyRecord.definitionJson` (ensuring TTCF-v1 compliance), embeds canonical `integrityHash`, and computes outer `SHA-256` (`snapshotHash`) + `byteSize`.
- **Verification (`lines 279–469`):** Validates `byteSize`, outer `SHA-256`, JSON syntax, `formatVersion === 1`, `canonicalizationVersion IN (1, 2)`, canonical `integrityHash`, `clusterId`, `epochId`, `snapshotIndex`, `chainHeadHash`, and `lastPhysicalCursor` (`etcdRevision`, `subIndex`) against the trusted PostgreSQL `PersistedSnapshotRecord`. External object metadata cannot bypass PostgreSQL metadata parity.

---

## 4. Crash-Consistency Assessment

- **Empty / Uncommitted State Guard (`lines 972–986, 1087–1093`):** Rejects `INITIAL` / `lastAppliedAppIndex <= 0n` and verifies `witness_raft_state.last_consecutive_persisted_index >= state.lastAppliedAppIndex` before inserting `STAGED`.
- **Crash Boundaries:**
  - *After `STAGED` insert / failed upload:* `STAGED` row is ignored by `recover()` (`WHERE status = 'COMMITTED'`); best-effort `releaseLease()` frees the lease (`lines 1026–1033`).
  - *After `DELETING` transition / after storage delete:* `cleanupSnapshots()` resumes any `DELETING` rows (`line 1292`), performs idempotent `storage.delete()`, and completes `DELETE FROM witness_snapshots WHERE snapshot_id = $1 AND status = 'DELETING'`.

---

## 5. POSIX Backend Assessment

- `PosixSnapshotStorageBackend` (`lines 494–618`) enforces `assertSafeIdentifier()` (`lines 95–110`) and `resolveSafePath()` (`lines 512–521`), writes to `${snapPath}.tmp`, calls `fs.fsyncSync(fd)`, atomically renames to `snapPath`, flushes parent directory fd where supported by OS, and reads back `snapPath` to verify `SHA-256` and `byteSize`, unlinking on mismatch.
- `delete()` ignores `ENOENT` for idempotent crash recovery.

---

## 6. S3 and GCS Backend Assessment

- `S3SnapshotStorageBackend` (`lines 633–717`) enforces `If-None-Match: *`, `ChecksumSHA256`, `ContentMD5`, HTTP `412 -> SnapshotCollisionError`, and response checksum verification.
- `GcsSnapshotStorageBackend` (`lines 731–814`) enforces `ifGenerationMatch: 0`, computes `CRC32C` via `calculateCrc32c()`, and validates returned `crc32cBase64` and `byteSize`.
- **Scope Distinction:** Tested with deterministic in-memory `S3ObjectStorageAdapter` / `GcsObjectStorageAdapter` test doubles. Live AWS S3 / GCP GCS production validation requires staging/provider integration tests.

---

## 7. PostgreSQL Lifecycle and Lease Assessment

- **Trigger Compatibility:** `insertStagedSnapshotRow()` writes all immutable columns once; `commitStagedSnapshot()` and `transitionRowToDeletingIfEligible()` update only `status`; `cleanupSnapshots()` deletes only `WHERE status = 'DELETING'`.
- **Leases (`lines 893–962`):** `acquireLease`, `renewLease`, and `releaseLease` use PostgreSQL `clock_timestamp()`, preventing cross-process lease races.
- **Cleaner vs. Restore Safety:** `transitionRowToDeletingIfEligible()` (`lines 1362–1454`) locks `witness_raft_state` `FOR SHARE` then `witness_snapshots` `FOR UPDATE`, protecting `last_snapshot_hash`, active leases, and snapshots within `gracePeriodSeconds = 3600`. `verifyOrphanObjectSafeToDelete()` (`lines 1456–1503`) re-checks `witness_snapshots ... FOR UPDATE` immediately before orphan deletion.

---

## 8. Restoration and Recovery Assessment

- `SnapshotManager` implements `ConsensusSnapshotLoader` (`lines 1227–1255`) without duplicating `PostgresConsensusStore.recover()`.
- `loadAndVerifyStrict()` verifies `witness_snapshots.status === 'COMMITTED'` in PostgreSQL before reading storage; `loadAndVerify()` returns `null` on failure so `PostgresConsensusStore.recover()` falls back to an earlier `COMMITTED` snapshot or genesis, replays contiguous suffix entries, and preserves `EPOCH_ADVANCE` lineage and `chainHeadHash` parity.

---

## 9. Security and Operational Assessment

- **SQL Parameterization:** All queries use `$1..$N` bind parameters; `statementTimeoutMs` is validated as a non-negative integer.
- **Path Traversal & Key Safety:** `assertSafeIdentifier()` and `extractKey()`/`extractObjectName()`/`resolveSafePath()` reject `..`, `/`, `\`, and null bytes.
- **Memory & Streaming:** Snapshots are buffered in memory (`Buffer`) as JSON; acceptable for current state sizes, noted as a future scaling consideration for multi-hundred-MB states.

---

## 10. Test Adequacy

All 10 tests in `test/witness/snapshot-manager.test.ts` execute against live **PostgreSQL 16.15** and real POSIX filesystem operations (`os.tmpdir()`), plus deterministic S3/GCS adapters. Earlier test failures during development (`definitionJson: undefined` in TTCF-v1 and `orphanUri` mtime setup) were resolved and verified passing (**10/10**, alongside **25/25** `consensus-store`, **152/152** witness regressions, and **0** build errors).

---

## 11. Findings (Low Severity / Advisory)

- **F-STEP5-01 (Low — `src/witness/snapshot-manager.ts` lines 448–452):** `verifyAndDeserializeSnapshot()` does not explicitly validate `m.epochState` enum membership or `Number.isSafeInteger(m.epochHeight)` (mitigated by outer `SHA-256` + `integrityHash` bound to PostgreSQL).
- **F-STEP5-02 (Low — `src/witness/snapshot-manager.ts` lines 1095–1118):** Retrying `createAndPublishSnapshot()` at the *exact same* `(cluster_id, epoch_id, snapshot_index)` after a crash that left a `STAGED` row will fail closed on `witness_snapshots_pkey` until `cleanupSnapshots()` purges the expired `STAGED` row.
- **F-STEP5-03 (Low — `src/witness/snapshot-manager.ts` lines 512–521):** `PosixSnapshotStorageBackend.resolveSafePath()` performs lexical `path.resolve()` containment without `fs.realpathSync()` symlink resolution (low risk when `rootDir` is service-owned).
- **F-STEP5-04 (Low — `test/witness/snapshot-manager.test.ts`):** `storage.delete()` throwing a non-`ENOENT` error and `loadAndVerifyStrict()` rejecting a `STAGED` row are not directly asserted in dedicated tests.

---

## 12. Required Remediation

- **None required for Step 5 acceptance.** Findings `F-STEP5-01` through `F-STEP5-04` are Low-severity hardening items that may be addressed optionally or during staging hardening, alongside live S3/GCS bucket integration testing when cloud credentials are provisioned.

---

## 13. Final Acceptance Verdict

- **Verdict:** **ACCEPTED**
- **Governance:** Audit-only; zero source, test, or migration files modified; zero git commits/pushes; Step 6 (`CompactionCoordinator`) not started.
