# Web3User — Independent Audit: PostgreSQL Pool Lifecycle Hardening

**Document ID:** `docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-INDEPENDENT-AUDIT.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus` (`fc446d96fa7965f6ac42ba7a1976e0a4f16edf10` + local uncommitted changes)  
**Authorization Scope:** Read-only independent audit. Zero source, test, config, or report edits to existing files; zero Git state changes.  
**Verdict:** **ACCEPTED WITH CONDITIONS**

---

## 1. Executive Verdict

**Verdict: ACCEPTED WITH CONDITIONS**

Independent inspection of `src/witness/pg-pool-lifecycle.ts`, `src/witness/consensus-store.ts`, `src/witness/postgres-store.ts`, `src/witness/index.ts`, `test/witness/pg-pool-lifecycle.test.ts`, and `pg-pool@3.14.0` confirms that the implementation eliminates unhandled `'error'` events on component-owned pools during normal operation, preserves caller ownership for externally supplied pools, classifies SQLSTATE/network errors without leaking credentials, and preserves all consensus, persistence, transaction, retry, and fail-closed invariants.

However, **four audit findings** (`1` Medium, `1` Low–Medium, `2` Low) prevent unconditional acceptance:
1. **F-POOL-01 (Medium):** `degraded` is a permanently sticky latch with no recovery path and conflicts with `PostgresWitnessStore.healthCheck()`.
2. **F-POOL-02 (Low–Medium):** `detach()` runs immediately after `await this.pool.end()`, which in `pg-pool@3.14.0` resolves before `client.end()` sockets finish closing—leaving a window for late `57P01`/socket errors to emit with `0` listeners.
3. **F-POOL-03 (Low):** `PostgresWitnessStore.healthCheck()` does not surface `getPoolHealth()` diagnostics.
4. **F-POOL-04 (Low):** Missing deterministic tests for throwing `onPoolError`, `pool.end()` rejection (`shouldRejectEnd`), repeated/concurrent `close()`, store-level shutdown `57P01`, and transient recovery.

---

## 2. Files & Functions Inspected

| File | Functions / Symbols Inspected | SHA-256 Checksum |
| :--- | :--- | :--- |
| `src/witness/pg-pool-lifecycle.ts` | `classifyPgPoolError()`, `ManagedPgPoolLifecycle` (`attachOnce`, `handlePoolError`, `markClosing`, `detach`, `getHealth`) | `8098C8C157ADA7DCF0A3955D9E6B00BE9F97DB68B083E0846C45A9875746CD69` |
| `src/witness/consensus-store.ts` | `PostgresConsensusStore` constructor (`lines 330-354`), `getPoolHealth()` (`lines 388-390`), `close()` (`lines 392-403`) | `20699E65CC7348A9B8C5285B736E65A01772D59313D78E2933288616D7FD0710` |
| `src/witness/postgres-store.ts` | `PostgresWitnessStore` constructor (`lines 234-264`), `getPoolHealth()` (`lines 470-472`), `close()` (`lines 474-483`), `healthCheck()` (`lines 1386-1396`) | `45A6B0819949CB5D1947B7F7AEA7FB9D331B8F1B15B410CE359B9D6113A5A732` |
| `src/witness/index.ts` | `export * from "./pg-pool-lifecycle.js"` (`line 7`) | `2AA5A5E24AA63F06E4E9B0AD0623753098B8A2B351C3ADBE992E39E0061C17FC` |
| `test/witness/pg-pool-lifecycle.test.ts` | All 5 tests (`lines 31-213`), `MockPgPool` (`lines 19-29`) | `89388CA596BC13456B8E1A8D881ED7CFE0D2FFF8E0A9FB57A4D0CC97B98E7791` |
| `docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-REPORT.md` | Inspected as implementation claims only | `42ABBC0C952931FCDB66405388AD0D65E1932EA1DDB6E074EF5A1A936A37D744` |

---

## 3. Audit Findings

### F-POOL-01 (Medium) — Sticky `degraded` State & Health-Model Mismatch
- **Location:** `src/witness/pg-pool-lifecycle.ts:100,151,188`; `src/witness/postgres-store.ts:1386-1392`.
- **Evidence:** `handlePoolError()` sets `this.degraded = true` (`line 151`) for any non-shutdown or non-`57P01` error, and `getHealth()` returns `healthy: !this.closingOrClosed && !this.degraded` (`line 188`). No method ever clears `this.degraded`.
- **Impact:** A single transient idle-client error (e.g., idle TCP keepalive drop or single backend restart in a 20-connection pool) permanently marks `getPoolHealth().healthy = false` for the process lifetime even after PostgreSQL recovers and subsequent queries succeed. Meanwhile, `PostgresWitnessStore.healthCheck()` queries PostgreSQL directly and returns `healthy: true`, creating a contradictory health signal.
- **Required Remediation:** Provide an explicit verified recovery transition (e.g., `markHealthy()` invoked on verified DB liveness/success such as `healthCheck()` / `recover()` / `applyEntry()` commit) or distinguish `poolDegradedSinceMs` / `lastPoolError` from active readiness.

### F-POOL-02 (Low–Medium) — Early `detach()` Race Against Closing `pg-pool` Clients
- **Location:** `src/witness/pg-pool-lifecycle.ts:177-183`; `src/witness/consensus-store.ts:397-401`; `src/witness/postgres-store.ts:477-481`; `node_modules/pg-pool/index.js:133-143,172-188`.
- **Evidence:** Both `close()` methods call `await this.pool.end()` and immediately `this.poolLifecycle.detach()` in `finally`. In `pg-pool@3.14.0`, `pool.end()` removes idle clients from `_clients` and resolves `_endCallback()` synchronously **before** `client.end()` finishes closing TCP sockets, and `_remove()` never detaches `idleListener`.
- **Impact:** If a late `57P01` or `ECONNRESET` arrives on a closing client after `detach()` removes the pool `"error"` listener, `idleListener` will emit `'error'` on a pool with `0` listeners.
- **Required Remediation:** Keep the shutdown `"error"` listener attached on owned pools after `markClosing()` (since the pool is being discarded anyway) or wait until all `remove` events fire before detaching.

### F-POOL-03 (Low) — `PostgresWitnessStore.healthCheck()` Does Not Surface `getPoolHealth()`
- **Location:** `src/witness/postgres-store.ts:1386-1392`.
- **Evidence:** `healthCheck()` returns `{ healthy: true, epochId, sequenceNumber, divergenceDetected, reason }` without referencing `getPoolHealth()`.

### F-POOL-04 (Low) — Missing Deterministic Regression Tests
- **Location:** `test/witness/pg-pool-lifecycle.test.ts:19-213`.
- **Gaps Identified:**
  1. No test verifies `onPoolError` throwing does not escape (`pg-pool-lifecycle.ts:165-169`).
  2. `MockPgPool.shouldRejectEnd` (`line 21`) is unused; no test verifies `pool.end()` rejection or repeated/concurrent `close()` / `detach()` calls.
  3. No test exercises `PostgresConsensusStore.close()` or `PostgresWitnessStore.close()` receiving `57P01` during `pool.end()`.
  4. No test verifies recovery after a transient connection failure (paired with `F-POOL-01`).

---

## 4. Verified Behavior vs. Assumptions & Guarantees

- **Verified:**
  - All production `new Pool(` sites in `src/` were audited (`consensus-store.ts`, `postgres-store.ts`; `SnapshotManager`, `CompactionCoordinator`, and `disposal-adapter.ts` are caller-owned).
  - `ownPool === true` attaches `1` `"error"` listener; `ownPool === false` attaches `0` listeners and `close()` never calls `pool.end()`.
  - `classifyPgPoolError()` handles `57P01`, `57P02`/`57P03`, `08*`, Node network codes, and unexpected errors without logging credentials or connection strings.
  - Zero changes to consensus state transitions, two-phase publication, transaction isolation, retry/idempotency, or fail-closed authorization.
- **Read-Only Commands Executed Independently:**
  - `npx vitest run test/witness/pg-pool-lifecycle.test.ts`: **1 passed (1) file, 5 passed (5) tests** (`1.32s`, exit `0`).
  - `npx tsc --noEmit`: exit `0` (`0` errors).
  - `git status --porcelain`: confirms zero test-teardown suites were modified and all untracked files remain preserved.

---

## 5. Audit Checksum & Governance

- **Audit Report SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-INDEPENDENT-AUDIT.md`.
- **Governance:** Read-only audit; zero existing files modified, staged, committed, pushed, merged, or deployed.
