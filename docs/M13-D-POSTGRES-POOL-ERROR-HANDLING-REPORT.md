# Web3User — Production PostgreSQL Pool Error-Handling Hardening
## Implementation & Verification Report

**Document ID:** `docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-REPORT.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus`  
**Baseline HEAD:** `fc446d96fa7965f6ac42ba7a1976e0a4f16edf10`  
**Authorization Scope:** Local production PostgreSQL pool error-handling hardening, targeted regression tests, TypeScript/build/Gitleaks verification, and reporting only. Zero test-only teardown edits, zero Git commits/pushes/merges, zero CI workflow edits.

---

## 1. Phase 1 Audit: Production PostgreSQL Pool Constructors & Ownership

A complete search of `src/*.ts` and `src/witness/*.ts` identified every `pg.Pool` reference in production source:

| Component | Source Location | Pool Ownership | Action Taken |
| :--- | :--- | :--- | :--- |
| **`PostgresConsensusStore`** | `src/witness/consensus-store.ts` (`lines 318-335`) | **Conditional:** `ownPool = true` when `options.pool` is omitted (`new Pool(config)`); `ownPool = false` when `options.pool` is supplied | **Hardened:** Attached `ManagedPgPoolLifecycle` (`ownPool === true` only); added `onPoolError` option and `getPoolHealth()`; `close()` calls `markClosing()` -> `pool.end()` -> `detach()`. |
| **`PostgresWitnessStore`** | `src/witness/postgres-store.ts` (`lines 234-251`) | **Conditional:** `ownPool = true` when `options.pool` is omitted (`new Pool(config)`); `ownPool = false` when `options.pool` is supplied | **Hardened:** Attached `ManagedPgPoolLifecycle` (`ownPool === true` only); added `onPoolError` option and `getPoolHealth()`; `close()` calls `markClosing()` -> `pool.end()` -> `detach()`. |
| **`SnapshotManager`** | `src/witness/snapshot-manager.ts` (`lines 865-866`) | **Always caller-owned** (`options.pool` required) | **Untouched** (caller retains pool lifecycle responsibility). |
| **`CompactionCoordinator`** | `src/witness/compaction-coordinator.ts` (`lines 398-403`) | **Always caller-owned** (`options.pool` required) | **Untouched** (caller retains pool lifecycle responsibility). |
| **`disposal-adapter.ts`** | `src/witness/disposal-adapter.ts` (`line 77`) | **Always caller-owned** (`pool.end().catch(() => {})` on supplied pool) | **Untouched.** |

---

## 2. Original Defect & Safe Error-Handling Semantics

### 2.1 Original Defect
In `pg-pool@3.14.0`, every pooled client attaches `client.on('error', idleListener)`, which forwards idle/closing client errors to `pool.emit('error', err, client)`. Neither `PostgresConsensusStore` nor `PostgresWitnessStore` attached a `pool.on("error", ...)` listener when `ownPool === true`. Consequently, an idle client receiving `57P01` (PostgreSQL administrative termination/restart/failover) or a network drop (`ECONNRESET`, `08006`) emitted an unhandled `'error'` event, crashing the Node.js process.

### 2.2 Implemented Design (`src/witness/pg-pool-lifecycle.ts`)
- **Single-Listener Ownership Guard:** `ManagedPgPoolLifecycle` attaches **exactly one** `"error"` listener only when `ownPool === true`; externally supplied pools (`ownPool === false`) are never mutated.
- **Error Classification (`classifyPgPoolError`):**
  - `57P01` -> `ADMIN_SHUTDOWN`
  - `57P02`, `57P03` -> `SERVER_UNAVAILABLE`
  - `08000`, `08001`, `08003`, `08004`, `08006`, `08007`, `08P01`, `ECONNRESET`, `ECONNREFUSED`, `ETIMEDOUT`, `EPIPE`, `ENOTFOUND`, `EHOSTUNREACH` -> `CONNECTION_ERROR`
  - All other errors -> `UNEXPECTED_POOL_ERROR`
- **Operational vs. Shutdown Semantics:**
  - During normal operation (`duringShutdown === false`), **any** idle pool error (including `57P01`) marks `getPoolHealth().healthy = false`, increments `totalPoolErrors`, records `lastPoolError`, emits structured JSON via `console.error` (no credentials, connection strings, or query params), and invokes optional `onPoolError`.
  - During intentional `close()` (`markClosing()` called before `await this.pool.end()`), expected `57P01` is recorded in `lastPoolError` with `duringShutdown: true` without noisy stderr, while any non-`57P01` error is still marked degraded and logged.
- **Clean Disposal:** `close()` removes the attached listener in `finally` (`pool.off("error", listener)`), preventing listener leaks or races.
- **No Silent Retries / No Process-Wide Handlers:** No arbitrary transaction retries or `process.on("uncaughtException")` workarounds were introduced; consensus, persistence, and fail-closed invariants remain unchanged.

---

## 3. Regression Tests & Verification Outcomes

### 3.1 Targeted Regression Suite (`test/witness/pg-pool-lifecycle.test.ts`, 5 deterministic tests)
1. Classifies `57P01`, `57P03`, `ECONNRESET`, and unexpected errors accurately.
2. Attaches exactly 1 `"error"` listener on owned pools, handles idle `57P01` without throwing, and marks `getPoolHealth().healthy === false` outside shutdown.
3. Records expected `57P01` during intentional shutdown without noisy error logs while keeping non-`57P01` (`08006`) errors logged and visible.
4. Confirms externally supplied pools (`options.pool`) receive `0` added listeners and are never ended by `close()`.
5. Confirms `PostgresConsensusStore` and `PostgresWitnessStore` (`ownPool === true`) install `1` listener, handle idle errors, and detach (`listenerCount("error") === 0`) on `close()`.

### 3.2 Executed Commands & Results
| Check | Command | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| **Targeted Pool & Store Suites** | `npx vitest run test/witness/pg-pool-lifecycle.test.ts test/witness/consensus-store.test.ts test/witness/postgres-store.test.ts` | `0` | **3 passed (3) files, 60 passed (60) tests** (`54.92s`) |
| **Full Witness Regression** | `npx vitest run test/witness/` | `0` | **22 passed (22) files, 394 passed (394) tests** (`156.60s`) |
| **TypeScript Typecheck** | `npx tsc --noEmit` | `0` | **0 errors** |
| **Production Build** | `npm run build` (`tsc -p tsconfig.build.json`) | `0` | **0 errors** |
| **Gitleaks Scan (`8.30.1`)** | `gitleaks detect --no-git --source <file> --config .gitleaks.toml` *(all 5 changed/new files)* | `0` | **0 leaks found** |

*(Note: GitHub Actions CI has **not** yet validated these local uncommitted changes.)*

---

## 4. Changed & Created Files (SHA-256)

| File | Action | SHA-256 Checksum |
| :--- | :---: | :--- |
| `src/witness/pg-pool-lifecycle.ts` | **Created** | `8098C8C157ADA7DCF0A3955D9E6B00BE9F97DB68B083E0846C45A9875746CD69` |
| `src/witness/consensus-store.ts` | **Modified** | `20699E65CC7348A9B8C5285B736E65A01772D59313D78E2933288616D7FD0710` |
| `src/witness/postgres-store.ts` | **Modified** | `45A6B0819949CB5D1947B7F7AEA7FB9D331B8F1B15B410CE359B9D6113A5A732` |
| `src/witness/index.ts` | **Modified** | `2AA5A5E24AA63F06E4E9B0AD0623753098B8A2B351C3ADBE992E39E0061C17FC` |
| `test/witness/pg-pool-lifecycle.test.ts` | **Created** | `89388CA596BC13456B8E1A8D881ED7CFE0D2FFF8E0A9FB57A4D0CC97B98E7791` |

---

## 5. Known Limitations & Remaining Scope
1. **Test-Only Teardown Suites Untouched:** By authorization boundary, the 5 test files that create their own disposable `pg.Pool` (`consensus-store.test.ts`, `snapshot-manager.test.ts`, `compaction-coordinator.test.ts`, `compaction-coordinator.real.test.ts`, `migration-003.test.ts`) were **not** modified; resolving the Node 26 CI `57P01` teardown race in those test files requires separate authorization.
2. **Externally Supplied Pools:** When callers pass `options.pool` (`ownPool === false`), attaching a `pool.on("error", ...)` listener remains the caller's responsibility.
3. **Health Surface:** `getPoolHealth()` exposes synchronous pool health/diagnostics on `PostgresConsensusStore` and `PostgresWitnessStore`; active DB liveness probing remains in `PostgresWitnessStore.healthCheck()`.
4. **Report SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-POSTGRES-POOL-ERROR-HANDLING-REPORT.md`.
