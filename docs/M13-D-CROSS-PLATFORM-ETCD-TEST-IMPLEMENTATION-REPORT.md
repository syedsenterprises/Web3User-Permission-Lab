# Web3User — M13-D Cross-Platform etcd Test Infrastructure
## Implementation & Verification Report

**Document ID:** `docs/M13-D-CROSS-PLATFORM-ETCD-TEST-IMPLEMENTATION-REPORT.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus` (`f69da6b`)  
**Authorization Scope:** Test infrastructure, test organization, and minimal CI workflow changes only. Zero production source, migration, or accepted Stage 2-B.2 implementation/report edits.

---

## 1. Files Changed & Reasons

| File | Action | Reason | SHA-256 Checksum |
| :--- | :---: | :--- | :--- |
| `scripts/ensure-etcd.mjs` | **Created** | Cross-platform pinned `etcd v3.5.18` provisioning script with official SHA-256 archive verification and `--version` check into `.tmp/etcd-bin/v3.5.18/`. | `645E94F1ED1A5A12A6AAFE8FE3C22124D95FA8D418FC2293945BDA78087472E9` |
| `test/witness/helpers/real-etcd-process.ts` | **Modified** | Removed hardcoded `etcd.exe`/`etcdctl.exe` and Windows-only `taskkill` assumptions; added OS-aware executable resolution, `v3.5.18` version enforcement, `SIGTERM` -> `SIGKILL` POSIX shutdown, and bounded stdout/stderr tail diagnostics on startup/readiness failures. | `3B3A261060D4E938F48C57F28CE078CC56F42F5F6419C7D5F130A10E3E5F834E` |
| `test/witness/compaction-coordinator.real.test.ts` | **Created** | Extracted Section 3 (`Real etcd v3.5.18 + PostgreSQL 16.15 Integration`) into a dedicated `*.real.test.ts` suite preserving all assertions verbatim. | `43CE24632D2DDA8D8DDA10E37DF0189FB621BB04E547A534587DE105B22A60DC` |
| `test/witness/compaction-coordinator.test.ts` | **Modified** | Retained all 5 unit + PostgreSQL 16 fault-injected compaction tests; removed `RealEtcdProcess` dependency so offline container verification (`--exclude "**/*.real.test.ts"`) runs cleanly. | `7BB7314D920256C212281D5DC6E1682375E0B54BA053E58CAB3BBF553720FFC4` |
| `.github/workflows/ci.yml` | **Modified** | Added `node scripts/ensure-etcd.mjs` provisioning step on `ubuntu-24.04`, changed test command to `npx vitest run` (executing both ordinary and `*.real.test.ts` suites with zero duplicates), and added `if: failure()` log output for `.tmp/logs/*.log`. | `08E4C7E596803F93E9464FAD652D8F0354833FC93CEA2ED9293AF39C889DC34A` |

*(Note: `Dockerfile` retains `npx vitest run --exclude "**/*.real.test.ts"` intentionally so offline container builds do not download external binaries; now that `compaction-coordinator.real.test.ts` follows the `*.real.test.ts` naming convention, `Dockerfile`'s exclusion is accurate and consistent.)*

---

## 2. Cross-Platform Design & Pinned Provisioning

### 2.1 `RealEtcdProcess` (`test/witness/helpers/real-etcd-process.ts`)
- **OS-Aware Executables:** Resolves `etcd.exe`/`etcdctl.exe` on `win32` and `etcd`/`etcdctl` on POSIX (`linux`/`darwin`) inside `ETCD_BIN_DIR` or `.tmp/etcd-bin/v3.5.18/`.
- **Strict Version Pinning:** Executes `etcd --version` in the constructor and throws an actionable error if the binary is missing or does not report `etcd Version: 3.5.18` (never silently falls back to a system-installed binary or skips tests).
- **Platform-Aware Shutdown:** Uses `taskkill /F /T /PID` (with `SIGKILL` fallback) on `win32`, and `SIGTERM` (1500ms grace) followed by `SIGKILL` on POSIX.
- **Diagnostics:** Captures bounded 8 KB `stdout`/`stderr` tails in memory alongside `.tmp/logs/<name>.log` and includes exit code/signal and output tails in startup/readiness timeout errors.

### 2.2 Pinned Provisioning (`scripts/ensure-etcd.mjs`)
- Pins `ETCD_VERSION = "3.5.18"` and verifies archive SHA-256 against official upstream `etcd-io/etcd` `v3.5.18` `SHA256SUMS` before extraction:
  - `win32-x64`: `etcd-v3.5.18-windows-amd64.zip` (`c17126fe42852d2eef181f94b17af26b6289052de9d28f8fe5edb6783f461c59`)
  - `linux-x64`: `etcd-v3.5.18-linux-amd64.tar.gz` (`6ddde039a7a506badf34e7edfb38e1ea90e36f05c8cfceba602045df623d86fa`)
  - `linux-arm64`: `etcd-v3.5.18-linux-arm64.tar.gz` (`c2bcaf465537d6d47c8bb82a69e31f786f32257050e3bca445bc4e63479ec714`)
- Short-circuits (`exit 0`) when `.tmp/etcd-bin/v3.5.18/` already contains a verified `etcd v3.5.18` binary.
- Setup procedure for developers or CI: run `node scripts/ensure-etcd.mjs`.

---

## 3. Verification Results

### 3.1 Windows Verification (Executed Locally)
- **Environment:** Windows 11 Pro AMD64 (`win32-x64`), Node.js `v26.11.1`, `PostgreSQL 16.15`, `etcd v3.5.18`.
- **Provisioning Check (`node scripts/ensure-etcd.mjs`):** Exit `0` (`Pinned etcd v3.5.18 already present and verified at C:\Users\syeds\Projects\Web3User\.tmp\etcd-bin\v3.5.18`).
- **Real etcd Suites (`npx vitest run test/witness/compaction-coordinator.real.test.ts test/witness/etcd-client-adapter.real.test.ts`):** **2 passed (2) files, 27 passed (27) tests** (`26` adapter + `1` compaction), `0` failed, `0` skipped (`20.02s`). **0** orphaned `etcd` processes afterward.
- **Full Witness Suite (`npx vitest run test/witness/`):** **21 passed (21) files, 389 passed (389) tests**, `0` failed, `0` skipped (`156.05s`).
- **Non-Witness Project Suite (`npx vitest run --exclude "test/witness/**"`):** **24 passed (24) files, 540 passed (540) tests**, `0` failed, `0` skipped (`122.67s`).
- **Combined Total:** **45 passed (45) files, 929 passed (929) tests**, `0` failed, `0` skipped.

### 3.2 Ubuntu 24.04 Verification Status
- **Status:** **NOT VERIFIED LOCALLY** (Docker Desktop daemon is not running on this Windows host, and no Ubuntu WSL distro is installed).
- **Required CI Validation:** Push `feature/m13-d-consensus` (once authorized) and observe the GitHub Actions `ubuntu-24.04` `test` job in `.github/workflows/ci.yml` executing `node scripts/ensure-etcd.mjs` and `npx vitest run` against `postgres:16-alpine`.

### 3.3 Build & Gitleaks Results
- **TypeScript Production Build (`npm run build` / `tsc -p tsconfig.build.json`):** Exit `0`, **0 errors**.
- **Full Typecheck (`npx tsc --noEmit`):** Reported pre-existing `TS7034` / `TS7005` on `sparseTrailing` in accepted `test/witness/canonical-ttcf.test.ts` lines `327, 329` (outside this task's scope; note that `.github/workflows/ci.yml` runs `npx tsc --noEmit`, so that pre-existing TS error in `canonical-ttcf.test.ts` will also need founder-authorized attention before CI passes `npx tsc --noEmit`).
- **Gitleaks (`Gitleaks 8.30.1` with `.gitleaks.toml`):** Exit `0` (**0 leaks**) on all 5 changed/new files (`scripts/ensure-etcd.mjs`, `test/witness/helpers/real-etcd-process.ts`, `test/witness/compaction-coordinator.test.ts`, `test/witness/compaction-coordinator.real.test.ts`, `.github/workflows/ci.yml`).

---

## 4. Accepted Stage 2-B.2 Baseline Integrity & Git Governance

All 8 accepted Stage 2-B.2 source and migration deliverables remain **100% unmodified** with exact matching SHA-256 checksums:
- `src/witness/canonical-serializer.ts`: `DF8EA55DD5B0666BD4714E63C09A5D6AF1445BFFA6FCB21EF64D80746077D3F5`
- `src/witness/state-machine-types.ts`: `DD006076305D262D28CF1BA57C9FF762C516C916264AD04FD923726A8A3EC620`
- `src/witness/state-machine.ts`: `C2CB8BFAF70D0F4D568DFB5CC23F8892FFB4E6869BAFEBB7850B9E949A1A9335`
- `src/witness/migrations/004_d3_consensus_persistence.sql`: `98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341`
- `src/witness/migrations/004_d3_consensus_persistence.rollback.sql`: `85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74`
- `src/witness/consensus-store.ts`: `6262EB7C090C06ED000DF2E93AB2910828950A6AC6EFDCDFED32D116EE08F88F`
- `src/witness/snapshot-manager.ts`: `C58F204033763A4368D7652DDF069E8D79CD6EAB2C476340F6C0713838E8BF4C`
- `src/witness/compaction-coordinator.ts`: `40CCEA5C66D85C53BDD7B38B164EE459B6FD1E2373627B993BF1A0C252CA4224`

**Git Governance:** Zero commits, pushes, merges, rebases, or branch changes were performed. All pre-existing untracked files remain preserved.
