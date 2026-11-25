# Web3User — PostgreSQL Pool Lifecycle Conditional-Acceptance Remediation Report

**Document ID:** `docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-REMEDIATION-REPORT.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Baseline HEAD:** `fc446d96fa7965f6ac42ba7a1976e0a4f16edf10`  
**Remediated Findings:** `F-POOL-01`, `F-POOL-02`, `F-POOL-03`, `F-POOL-04` (from `docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-INDEPENDENT-AUDIT.md`)  
**Authorization Scope:** Production pool lifecycle code, directly affected health reporting, targeted tests, and this remediation report only. Zero test-teardown edits, zero Git commits/pushes/merges, zero CI edits.

---

## 1. Finding-by-Finding Resolution Summary

### F-POOL-01 (Medium) — Recovery Semantics & Concurrency Guard
- **Resolution (`src/witness/pg-pool-lifecycle.ts`):**
  - Replaced the sticky `degraded` boolean with explicit `PoolLifecycleState = "HEALTHY" | "DEGRADED" | "CLOSING" | "CLOSED"` and a monotonic `errorEpoch` counter.
  - **State Transitions:**
    - `HEALTHY` -> `DEGRADED`: Any idle-client error while `!duringShutdown` increments `errorEpoch` and sets `state = "DEGRADED"`.
    - `DEGRADED` -> `HEALTHY`: Occurs **only** via `markVerifiedHealthy(observedErrorEpoch)` after a verified PostgreSQL query (`verifyConnectivity()` / `PostgresWitnessStore.getSyncStatus()`) succeeds **and** `this.errorEpoch === observedErrorEpoch` **and** `state === "DEGRADED"` (never resurrects `CLOSING` or `CLOSED`, and never overwrites a newer idle error that arrived mid-probe).
    - `HEALTHY | DEGRADED` -> `CLOSING` -> `CLOSED`: During `close()`.
  - **Diagnostics Preserved:** `totalPoolErrors` and `lastPoolError` are never cleared upon recovery.
  - **Explicit Guarantee Boundary:** A single verified query (`SELECT 1` or `getSyncStatus()`) proves **at least one** pooled connection is operational; it does **not** claim every other idle socket in the pool is healthy (any subsequent idle socket error increments `errorEpoch` and returns the pool to `DEGRADED`).

### F-POOL-02 (Low–Medium) — Shutdown Safety & `pg-pool@3.14.0` Lifecycle
- **Resolution (`src/witness/pg-pool-lifecycle.ts`, `src/witness/consensus-store.ts`, `src/witness/postgres-store.ts`):**
  - **Limitation of `pg-pool@3.14.0`:** `pool.end()` removes idle clients from `_clients` and resolves synchronously before `client.end()` finishes closing TCP sockets, and `_remove()` never removes `idleListener`. Thus, there is no deterministic synchronous point at which `pool.end()` guarantees zero late `57P01`/socket events.
  - **Safest Bounded Design:**
    1. Removed premature `detach()` after `await this.pool.end()`. For **component-owned pools (`ownPool === true`)**, the shutdown-safe `"error"` listener remains attached through `CLOSING` and `CLOSED` (since the owned pool is permanently disposed and never returned to external callers), ensuring late `57P01` or socket errors cannot become unhandled EventEmitter exceptions.
    2. Added `closePromise` deduplication on `PostgresConsensusStore.close()` and `PostgresWitnessStore.close()` so repeated or concurrent `close()` calls share one `pool.end()` invocation without triggering `pg-pool`'s `Called end on pool more than once` error, while propagating any `pool.end()` rejection and transitioning `state = "CLOSED"` in `finally`.
    3. Externally supplied pools (`ownPool === false`) never receive any listener (`listenerAttached === false`).

### F-POOL-03 (Low) — Store Health Integration
- **Resolution (`src/witness/postgres-store.ts`, `src/witness/consensus-store.ts`):**
  - `PostgresWitnessStore.getSyncStatus()` (`src/witness/postgres-store.ts:1404-1448`) captures `errorEpoch` before querying `witness_tickets`, invokes `markVerifiedHealthy(epochBefore)` on query success, includes `poolHealth: PoolHealthStatus` in its return value (backwards-compatible with `WitnessSyncStatus`), and returns `healthy: false` with `reason` when `closingOrClosed` is `true`.
  - Added `verifyPoolHealth(): Promise<PoolHealthStatus>` on both `PostgresConsensusStore` and `PostgresWitnessStore`.

### F-POOL-04 (Low) — Deterministic Regression Coverage
- **Resolution (`test/witness/pg-pool-lifecycle.test.ts` — 7 deterministic tests):**
  1. SQLSTATE/network error classification (`57P01`, `57P03`, `08*`, `ECONNRESET`, unexpected).
  2. Throwing `onPoolError` callback isolation (never escapes as uncaught exception).
  3. `pool.end()` rejection propagation + `CLOSED` transition + repeated/concurrent `close()` idempotency (`endCalls === 1`).
  4. Late `57P01` and `08006` during `CLOSING`/`CLOSED` handled without unhandled EventEmitter errors.
  5. `DEGRADED -> HEALTHY` recovery via `verifyConnectivity()` preserving `lastPoolError`/`totalPoolErrors`, plus mid-probe concurrent error race guard (`errorEpoch` mismatch blocks false recovery).
  6. `PostgresWitnessStore.getSyncStatus()` store-level recovery & `CLOSED` unhealthy reporting.
  7. Caller-owned pool isolation (`0` listeners, `0` `end()` calls) + multiple owned errors with `listenerCount("error") === 1`.

---

## 2. Changed Files & SHA-256 Checksums

| File | Changed Functions / Scope | SHA-256 Checksum |
| :--- | :--- | :--- |
| `src/witness/pg-pool-lifecycle.ts` | `PoolLifecycleState`, `ManagedPgPoolLifecycle` (`errorEpoch`, `markVerifiedHealthy`, `verifyConnectivity`, `markClosing`, `markClosed`, `getHealth`) | `63ABD475154C1C60638082D810C85B1D3F9A3702366830E656775BFCD4EB371F` |
| `src/witness/consensus-store.ts` | `PostgresConsensusStore` (`closePromise`, `verifyPoolHealth`, `close` using `markClosed`) | `F42CF339B054B8AF704BEA3A79BFA5134FC7C0521C7F8F3B074171F1162B950C` |
| `src/witness/postgres-store.ts` | `PostgresWitnessStore` (`closePromise`, `verifyPoolHealth`, `close` using `markClosed`, `getSyncStatus` integration) | `3C1CDE2B32781D26D5AFE58D1568C1BCFA3E3E50CD8802D53289D3A4B05DC790` |
| `src/witness/index.ts` | Unchanged from prior hardening (`export * from "./pg-pool-lifecycle.js"`) | `2AA5A5E24AA63F06E4E9B0AD0623753098B8A2B351C3ADBE992E39E0061C17FC` |
| `test/witness/pg-pool-lifecycle.test.ts` | 7 deterministic tests covering all F-POOL-04 scenarios | `03147B6445A76E14F2A1E6BA148EEE64B4216F65C44889BA5FEA274D1B4020B0` |

---

## 3. Verification Commands & Results

| Check | Command | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| **Targeted Lifecycle & Store Suites** | `npx vitest run test/witness/pg-pool-lifecycle.test.ts test/witness/consensus-store.test.ts test/witness/postgres-store.test.ts` | `0` | **3 passed (3) files, 62 passed (62) tests** (`90.52s`) |
| **Full Witness Regression** | `npx vitest run test/witness/` | `0` | **22 passed (22) files, 396 passed (396) tests** (`182.80s`, `0` failed, `0` skipped) |
| **TypeScript Typecheck** | `npx tsc --noEmit` | `0` | **0 errors** |
| **Production Build** | `npm run build` (`tsc -p tsconfig.build.json`) | `0` | **0 errors** |
| **Gitleaks (`8.30.1`)** | `gitleaks detect --no-git --source <file> --config .gitleaks.toml` *(all 4 modified/new code & test files)* | `0` | **0 leaks found** |

*(Note: GitHub Actions CI has **not** yet validated these local uncommitted changes.)*

---

## 4. Remaining Risks & Git Governance

- **Remaining Risks:**
  1. The 5 test suites with disposable test-only `pg.Pool` teardown (`consensus-store.test.ts`, `snapshot-manager.test.ts`, `compaction-coordinator.test.ts`, `compaction-coordinator.real.test.ts`, `migration-003.test.ts`) remain untouched per governance; Node 26 CI `57P01` test-teardown remediation requires separate authorization.
  2. Externally supplied pools (`options.pool`) remain the caller's responsibility for `"error"` listener attachment.
- **Governance:** Zero staging, commits, pushes, PR updates, merges, or deployments performed. Original reports (`M13-D-POSTGRES-POOL-ERROR-HANDLING-REPORT.md`, `M13-D-POSTGRES-POOL-ERROR-HANDLING-INDEPENDENT-AUDIT.md`) and Stage 2-B.2 closure records preserved unchanged.
- **Remediation Report SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-REMEDIATION-REPORT.md`.
