# Web3User — PostgreSQL Test Teardown Race Remediation Report

**Document ID:** `docs/M13-D-POSTGRES-TEST-TEARDOWN-REMEDIATION-REPORT.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Baseline HEAD:** `fc446d96fa7965f6ac42ba7a1976e0a4f16edf10`  
**Authorization Scope:** Local remediation of the PostgreSQL test teardown race across the 5 witness test suites (`consensus-store.test.ts`, `snapshot-manager.test.ts`, `compaction-coordinator.test.ts`, `compaction-coordinator.real.test.ts`, `migration-003.test.ts`), targeted regression tests, and reporting only. Zero production source, CI, or commit/push changes.

---

## 1. Verified Root Cause

In `pg-pool@3.14.0` (`node_modules/pg-pool/index.js:133-143, 172-188, 270, 385`), every pooled client attaches `client.on("error", idleListener)`, forwarding errors to `pool.emit("error", err, client)`. When `pool.end()` runs, `_remove(item.client)` removes idle clients from `_clients` and resolves `await pool.end()` synchronously **before** `client.end()` finishes closing the underlying TCP sockets and **without** detaching `idleListener`.

Immediately after `await pool.end()`, all 5 witness test suites executed `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, causing PostgreSQL to emit `57P01: terminating connection due to administrator command` on closing sockets whose server-side disconnect had not yet completed. Because none of the disposable test pools or `adminPool` instances had a `"error"` listener attached, Node.js emitted an unhandled `'error'` EventEmitter exception, causing Vitest to fail the Node 26 CI job (`138790211244`) even after `45/45` files and `929/929` tests passed.

---

## 2. Five-Suite Audit & Affected Locations

| Suite | Affected Pool & Teardown Locations | Remediation Applied |
| :--- | :--- | :--- |
| `test/witness/consensus-store.test.ts` | `adminPool` (`line 101`), `afterAll` (`lines 110-125`), `createDisposableMigration004Db` (`line 134`), `destroyDisposableDb` (`lines 150-163`), `F-STEP3-01` pool (`line 174`) | Migrated to `createManagedTestPool`, `destroyDisposableTestDb`, and `closeAdminTestPool`. |
| `test/witness/snapshot-manager.test.ts` | `adminPool` (`line 81`), `pool` (`line 92`), `afterAll` (`lines 104-115`) | Migrated to `createManagedTestPool`, `destroyDisposableTestDb`, and `closeAdminTestPool`. |
| `test/witness/compaction-coordinator.test.ts` | `adminPool` (`line 199`), `pool` (`line 208`), `afterAll` (`lines 219-230`) | Migrated to `createManagedTestPool`, `destroyDisposableTestDb`, and `closeAdminTestPool`. |
| `test/witness/compaction-coordinator.real.test.ts` | `adminPool` (`line 86`), `pool` (`line 95`), `afterAll` (`lines 107-120`) | Migrated to `createManagedTestPool`, `destroyDisposableTestDb`, and `closeAdminTestPool`. |
| `test/witness/migration-003.test.ts` | `adminPool` (`line 41`), `afterAll` (`lines 50-64`), `createDisposableDb` (`line 70`), `destroyDisposableDb` (`lines 80-90`) | Migrated to `createManagedTestPool`, `destroyDisposableTestDb`, and `closeAdminTestPool`. |

---

## 3. Teardown Ownership & Error Classification Design (`test/witness/helpers/pg-test-teardown.ts`)

- **Single Listener per Pool (`WeakMap` Registry):** `registerManagedTestPool(pool)` attaches **exactly one** `"error"` listener per test-owned `pg.Pool`, preventing duplicate listeners.
- **Explicit State Machine (`ACTIVE | CLOSING | CLOSED`):**
  - `ACTIVE`: **All** pool errors (including `57P01`) are recorded in `unexpectedErrors` and fail the test via `assertNoUnexpectedPoolErrors()`.
  - `CLOSING` / `CLOSED`: **Only** `57P01` (`admin_shutdown`) is classified as an expected teardown event (`expectedShutdown57P01Count += 1`). Any non-`57P01` error (e.g., `ECONNRESET`, `08006`) is recorded in `unexpectedErrors` and fails teardown.
- **Listener Lifetime:** Kept attached through `CLOSING` and `CLOSED` to absorb late `pg-pool@3.14.0` socket `57P01` events without arbitrary sleeps or process-wide exception handlers.
- **Deterministic Teardown (`destroyDisposableTestDb`):** Idempotently ends `pool` via `endManagedTestPool` (`closePromise` deduplication), queries `pg_stat_activity` and invokes `pg_terminate_backend` **only if** lingering backends remain, drops the disposable DB, propagates any `pool.end()` rejection, and asserts zero unexpected errors.

---

## 4. Regression Tests & Verification Results

### 4.1 Dedicated Regression Suite (`test/witness/pg-test-teardown.test.ts`, 5 deterministic tests)
1. Absorbs expected `57P01` during intentional teardown (`CLOSING` & late `CLOSED`) with `0` unhandled Vitest errors.
2. Fails teardown on unexpected `57P01` during `ACTIVE` execution and non-`57P01` (`ECONNRESET`) during shutdown.
3. Handles late socket errors after shutdown and propagates `pool.end()` rejection while transitioning to `CLOSED`.
4. Prevents duplicate listener installation (`listenerCount("error") === 1`) and supports concurrent `endManagedTestPool()` calls (`endCalls === 1`).
5. Invokes `pg_terminate_backend` only when `pg_stat_activity` reports remaining PIDs.

### 4.2 Local Verification Results (`Node v26.11.1`)
| Check | Command | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| **Teardown Regression** | `npx vitest run test/witness/pg-test-teardown.test.ts` | `0` | **1 passed (1) file, 5 passed (5) tests** (`461ms`) |
| **ConsensusStore** | `npx vitest run test/witness/consensus-store.test.ts` | `0` | **1 passed (1) file, 25 passed (25) tests** (`5.37s`) |
| **SnapshotManager** | `npx vitest run test/witness/snapshot-manager.test.ts` | `0` | **1 passed (1) file, 10 passed (10) tests** (`3.13s`) |
| **CompactionCoordinator** | `npx vitest run test/witness/compaction-coordinator.test.ts` | `0` | **1 passed (1) file, 5 passed (5) tests** (`1.78s`) |
| **Compaction Real etcd** | `npx vitest run test/witness/compaction-coordinator.real.test.ts` | `0` | **1 passed (1) file, 1 passed (1) test** (`4.04s`) |
| **Migration 003** | `npx vitest run test/witness/migration-003.test.ts` | `0` | **1 passed (1) file, 12 passed (12) tests** (`12.09s`) |
| **Full Witness Regression** | `npx vitest run test/witness/` | `0` | **23 passed (23) files, 401 passed (401) tests** (`268.78s`, `0` unhandled errors) |
| **TypeScript & Build** | `npx tsc --noEmit` & `npm run build` | `0` | **0 errors** |
| **Gitleaks (`8.30.1`)** | `gitleaks detect --no-git --source <file> --config .gitleaks.toml` *(all 7 files)* | `0` | **0 leaks found** |

### 4.3 Node 22 / Node 24 / Node 26 Cross-Version Status
- **Node 26 (`v26.11.1`):** **VERIFIED LOCALLY** (`23/23` witness files, `401/401` tests, `0` unhandled errors).
- **Node 22 (`22.13.0`) & Node 24 (`24`):** **NOT VERIFIED LOCALLY** (only Node `v26.11.1` is installed on this Windows host; no `nvm`/`fnm`/`volta` is present). Cross-version execution across `Node 22.13.0`, `Node 24`, and `Node 26` on `ubuntu-24.04` requires GitHub Actions CI validation after separate push authorization.

---

## 5. Changed Files & SHA-256 Checksums

| File | Action | SHA-256 Checksum |
| :--- | :---: | :--- |
| `test/witness/helpers/pg-test-teardown.ts` | **Created** | `B82A4D440DBD8DC42D960029D1A26FBAAAB055AAF2C92B9F84FE4A5BCDFC64A8` |
| `test/witness/pg-test-teardown.test.ts` | **Created** | `DB53653838FA51DB222AA4648DB257F9E2DA990780660A04ED48BD718F2BA42A` |
| `test/witness/consensus-store.test.ts` | **Modified** | `FAABE4B2889EE016E0EBA07FBB299F5242AD0C1FFCFC34345A32253C034AEE99` |
| `test/witness/snapshot-manager.test.ts` | **Modified** | `B95D4F1C6B55BAA6BACC0C928938ABCC5301381F00E087397B399731889E3F7F` |
| `test/witness/compaction-coordinator.test.ts` | **Modified** | `EC74FC3DC66606B7D3D5B6F7525A74C7991D811D14E5A70C1A1718FB74DE15DA` |
| `test/witness/compaction-coordinator.real.test.ts` | **Modified** | `AF9E4980F73E15A24F9D6822F2A210F480E4EFD7C026B678DBF5A1AA0E80FE6D` |
| `test/witness/migration-003.test.ts` | **Modified** | `876E6DB4F315901AA0C65D1ECA57A820375B897CD97DB8F9FEA46AC0CAFEC42F` |

---

## 6. Governance & Report Checksum

- **Production Pool Lifecycle Code:** Untouched relative to the accepted remediation (`src/witness/pg-pool-lifecycle.ts`, `consensus-store.ts`, `postgres-store.ts`, `index.ts`).
- **Git Governance:** Zero staging, commits, pushes, PR updates, merges, or deployments performed.
- **Report SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-POSTGRES-TEST-TEARDOWN-REMEDIATION-REPORT.md`.
