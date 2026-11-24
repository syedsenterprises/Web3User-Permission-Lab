# Web3User — Cross-Platform etcd Test Infrastructure
## Independent Verification Report

**Document ID:** `docs/M13-D-CROSS-PLATFORM-ETCD-INDEPENDENT-VERIFICATION.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus` (`f69da6b`)  
**Authorization Scope:** Read-only independent verification. Zero files modified, staged, committed, pushed, merged, or deployed.  
**Verdict:** **ACCEPTED WITH CONDITIONS**

---

## 1. Executive Verdict & Conditions

**Verdict: ACCEPTED WITH CONDITIONS**

Independent inspection and execution confirm that the cross-platform `etcd v3.5.18` test-infrastructure changes (`scripts/ensure-etcd.mjs`, `test/witness/helpers/real-etcd-process.ts`, `test/witness/compaction-coordinator.real.test.ts`, `test/witness/compaction-coordinator.test.ts`, `.github/workflows/ci.yml`) satisfy all Windows and architectural requirements with **zero** production source or database migration modifications:

1. **Accepted:** Pinning (`etcd v3.5.18`), upstream SHA-256 verification, OS-aware binary resolution, platform-aware termination (`taskkill` on Windows; `SIGTERM` -> `SIGKILL` on POSIX), bounded stdout/stderr failure diagnostics, non-skipping fail-closed behavior, and clean separation of `compaction-coordinator.real.test.ts` (`45/45` test files, `929/929` unique tests passing on Windows, `0` orphaned `etcd` processes, `0` Gitleaks findings).
2. **Condition 1 — Ubuntu 24.04 Execution (`NOT VERIFIED`):** No local Ubuntu 24.04 / Docker / WSL Ubuntu environment is available, and PR #1 (`refs/pull/1/head` = `f69da6b`) has not yet executed the updated `.github/workflows/ci.yml`. Ubuntu execution must be verified on GitHub Actions `ubuntu-24.04` after an authorized push.
3. **Condition 2 — Pre-Existing `tsc --noEmit` Failure:** `npx tsc --noEmit` (required by `.github/workflows/ci.yml` and `Dockerfile`) fails on pre-existing `TS7034` / `TS7005` in accepted `test/witness/canonical-ttcf.test.ts:327,329`. This predates the cross-platform changes and does not affect `npm run build`, but requires a separate 1-line authorized fix before CI passes `npx tsc --noEmit`.

---

## 2. Implementation & Baseline Integrity Inspection

- **Tracked Modified Files (`git diff --name-only`):** Only `.github/workflows/ci.yml` and `test/witness/helpers/real-etcd-process.ts`.
- **New Test-Infra Files:** `scripts/ensure-etcd.mjs`, `test/witness/compaction-coordinator.real.test.ts`.
- **Untouched Production & Migration Baseline:** Zero changes to `src/witness/` or `src/witness/migrations/`. All 8 accepted Stage 2-B.2 source/migration SHA-256 checksums match their closure baseline (`docs/M13-D-STAGE-2B2-FORMAL-CLOSURE-RECORD.md`).
- **Pinned `etcd v3.5.18` Checksums (`scripts/ensure-etcd.mjs`):**
  - `win32-x64`: `etcd-v3.5.18-windows-amd64.zip` (`c17126fe42852d2eef181f94b17af26b6289052de9d28f8fe5edb6783f461c59`)
  - `linux-x64`: `etcd-v3.5.18-linux-amd64.tar.gz` (`6ddde039a7a506badf34e7edfb38e1ea90e36f05c8cfceba602045df623d86fa`)
  - `linux-arm64`: `etcd-v3.5.18-linux-arm64.tar.gz` (`c2bcaf465537d6d47c8bb82a69e31f786f32257050e3bca445bc4e63479ec714`)
  - Verified before extraction; post-extract `etcd --version` must include `etcd Version: 3.5.18`.
- **No Silent Skips / No Orphaned Processes:** `RealEtcdProcess` throws immediately if `.tmp/etcd-bin/v3.5.18/etcd(.exe)` is missing or wrong version; `Get-Process -Name etcd` confirmed `0` orphaned processes after Windows real-etcd runs.

---

## 3. Exact Test Accounting (Zero Double-Counting)

`vitest.config.ts` sets `testTimeout: 20000`, `hookTimeout: 20000`, `fileParallelism: false`. The repository contains **45** `.test.ts` files (`21` in `test/witness/`, `24` outside `test/witness/`):

| Subset | Files | Tests | Result | Overlap? |
| :--- | :---: | :---: | :---: | :--- |
| **Real `etcd v3.5.18` Suites** (`etcd-client-adapter.real.test.ts` [26] + `compaction-coordinator.real.test.ts` [1]) | `2` | `27` | **27/27 passed** | Subset of `test/witness/` |
| **Witness Unit / PG 16 / Fault-Injected Suites** (including `compaction-coordinator.test.ts` [5]) | `19` | `362` | **362/362 passed** | Subset of `test/witness/` |
| **Full Witness Suite** (`npx vitest run test/witness/`) | **21** | **389** | **389/389 passed** | `362 + 27 = 389` |
| **Non-Witness Project Suite** (`npx vitest run --exclude "test/witness/**"`) | **24** | **540** | **540/540 passed** | Disjoint from `test/witness/` |
| **Actual Unique Repository Total** | **45** | **929** | **929/929 passed** | **0 excluded, 0 duplicated** |

*(The 27 real etcd tests **are** included in the 389 witness tests and 929 total tests; they were also executed standalone to verify isolated real-etcd pass/cleanup.)*

---

## 4. CI Workflow & Dockerfile Assessment

- **`.github/workflows/ci.yml` (`ubuntu-24.04`):**
  - Matrix Node `["22.13.0", "24", "26"]` with `postgres:16-alpine` service (`pg_isready` healthcheck).
  - Runs `npm ci`, `npm run build`, `node scripts/ensure-etcd.mjs`, `npx tsc --noEmit`, `npx vitest run` (executes all `45` files / `929` tests including both `*.real.test.ts` suites), `examples/basic-authorization.ts`, `npm run demo:persistent-replay -- --verify`, `npm pack --dry-run --json`, and `if: failure()` log output for `.tmp/logs/*.log`.
  - Standard exit-code propagation applies to each step.
- **`Dockerfile`:** Retains `npx vitest run --exclude "**/*.real.test.ts"` so offline container builds do not fetch external binaries. With `compaction-coordinator.real.test.ts` split out, both real-etcd suites are cleanly excluded from the offline container job while remaining active in the `ubuntu-24.04` `test` job.

---

## 5. TypeScript Discrepancy Investigation (`TS7034` / `TS7005`)

- **Root Cause:** `tsconfig.json` includes both `src/**/*.ts` and `test/**/*.ts` with `"strict": true`. In `test/witness/canonical-ttcf.test.ts` lines `327–329` (authored in Stage 2-B.2 Step 1.1, predating these cross-platform changes), `const sparseTrailing = [];` has no explicit type annotation, causing `TS7034` and `TS7005` under `npx tsc --noEmit`.
- **Impact on Production Build:** **None.** `tsconfig.build.json` (`npm run build`) includes only `src/**/*.ts` and exits `0` (`0` errors).
- **CI Impact:** **Blocking for CI.** Both `.github/workflows/ci.yml` and `Dockerfile` run `npx tsc --noEmit` as a required gate.
- **Safest Remediation:** Under a separate founder authorization, change line `327` of `test/witness/canonical-ttcf.test.ts` to `const sparseTrailing: unknown[] = [];` and update its Stage 2-B.2 test checksum record.

---

## 6. Ubuntu 24.04 Evidence Status

- **Status:** **NOT VERIFIED**
- **Basis:** PR #1 (`refs/pull/1/head` = `f69da6b`) predates these uncommitted changes, and no Ubuntu 24.04 environment (Docker or WSL Ubuntu) is available locally. Windows verification does not prove Linux runtime behavior.

---

## 7. Checksum & Git Governance

- **Verification Report SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-CROSS-PLATFORM-ETCD-INDEPENDENT-VERIFICATION.md`.
- **Governance:** Read-only verification; zero existing files modified, staged, committed, pushed, merged, or deployed.
