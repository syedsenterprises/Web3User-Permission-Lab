# Web3User — M13-D Git Integration Preflight Closure Report

**Document ID:** `docs/M13-D-GIT-INTEGRATION-PREFLIGHT-REPORT.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User`  
**Branch:** `feature/m13-d-consensus` (`f69da6b`)  
**Authorization Scope:** Read-only preflight verification only. Zero files staged, committed, pushed, merged, rebased, or modified.  
**Final Verdict:** **CONDITIONAL GO** *(GO for committing Groups A–E on `feature/m13-d-consensus`; HOLD on merging PR #1 to `main` until Linux CI `RealEtcdProcess` compatibility is resolved)*

---

## 1. Executive Verdict & Blocking Summary

| Concern | Preflight Result | Blocks Commit on `feature/m13-d-consensus`? | Blocks Merge of PR #1 to `main`? |
| :--- | :--- | :---: | :---: |
| **1. Gitleaks Reconciliation** | All 13 findings (`12` in `ef21964`, `1` in `M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md:155`) are **false positives** matching the AWS KMS enum identifier `ECC_NIST_EDWARDS25519`. Zero leaks in Stage 2-B.0/2-B.1/2-B.2 source, migration, and test files. | **No** *(note: `docs/` line 155 false positive documented)* | **No** *(CI does not run Gitleaks, though `.gitleaks.toml` / doc wording can be cleaned in an authorized follow-up)* |
| **2. Linux CI Compatibility** | `compaction-coordinator.test.ts` uses `RealEtcdProcess`, which hardcodes `.tmp/etcd-bin/v3.5.18/etcd.exe` and `taskkill`, and is **NOT** excluded by `--exclude "**/*.real.test.ts"` in `.github/workflows/ci.yml` or `Dockerfile`. | **No** | **YES — Linux CI (`ubuntu-24.04`) will fail** on `compaction-coordinator.test.ts` until addressed. |
| **3. Git & PR Synchronization** | `feature/m13-d-consensus` (`f69da6b`) == `origin/feature/m13-d-consensus` == `refs/pull/1/head`. Remote `origin/main` is at `650427d` (ahead of local `main` `0fa8d15` and stale tracking `c43f5be`). | **No** | **Sync check required** (`git fetch origin` before PR #1 merge). |

---

## 2. Gitleaks Reconciliation (`Gitleaks 8.30.1`)

### 2.1 Exact Commands & Exit Codes
| Command | Scope | Exit Code | Result |
| :--- | :--- | :---: | :--- |
| `gitleaks git --config .gitleaks.toml --log-opts="main..HEAD"` | 10 commits on `feature/m13-d-consensus` (`834.97 KB`) | `1` | `12` false-positive findings (all in commit `ef21964`) |
| `gitleaks detect --no-git --source src/witness --config .gitleaks.toml` | All `src/witness/` files (`491.49 KB`) | `0` | **0 leaks found** |
| `gitleaks detect --no-git --source test/witness/<file> --config .gitleaks.toml` *(run on each of the 6 Stage 2-B.2 test files)* | `canonical-ttcf.test.ts`, `state-machine.test.ts`, `migration-004.test.ts`, `consensus-store.test.ts`, `snapshot-manager.test.ts`, `compaction-coordinator.test.ts` | `0` *(all 6)* | **0 leaks found** |
| `gitleaks detect --no-git --source docs --config .gitleaks.toml` | All `docs/` files (`895.58 KB`) | `1` | `1` false-positive finding (`M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md:155`) |
| `gitleaks detect --no-git --source funding --config .gitleaks.toml` | All `funding/` files (`101.89 KB`) | `0` | **0 leaks found** |

### 2.2 Complete Finding Inventory
All **13** findings match Gitleaks rule `generic-api-key` on the public AWS KMS key-specification enum constant `ECC_NIST_EDWARDS25519` (false positive, not a secret or credential):
1. **12 findings in already-committed `ef21964` (`FN-SEC-01`, outside proposed commit groups):**
   - `test/witness/grpc-kms-integration.test.ts`: line `275`
   - `test/witness/cloud-kms-signer.test.ts`: lines `374`, `432`, `477`, `517`, `549`
   - `test/witness/cloud-kms-e2e-pipeline.test.ts`: lines `178`, `424`, `524`, `679`, `919`, `996`
2. **1 finding in proposed Commit Group E:**
   - `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md`: line `155` (quoted the literal `ECC_NIST_EDWARDS25519` match string from the `ef21964` test files).
3. **Configuration Assessment (`.gitleaks.toml`):** `.gitleaks.toml` currently allowlists only `idempotencyKey` test fixtures in `test/durable-witness.test.ts` and `test/monotonic-witness.test.ts`. It does not allowlist `ECC_NIST_EDWARDS25519` in `test/witness/` or `docs/`. No changes were made to `.gitleaks.toml`.

---

## 3. Linux CI Compatibility (`compaction-coordinator.test.ts` & `RealEtcdProcess`)

### 3.1 Root Cause Inspection
- **`test/witness/helpers/real-etcd-process.ts`:**
  - Line `71`: `this.etcdBinary = path.resolve(process.cwd(), ".tmp/etcd-bin/v3.5.18/etcd.exe");`
  - Line `72`: `this.etcdctlBinary = path.resolve(process.cwd(), ".tmp/etcd-bin/v3.5.18/etcdctl.exe");`
  - Line `74-76`: Throws `Error("etcd binary not found at ...")` if missing.
  - Line `183`: `execSync(\`taskkill /F /PID ${pid}\`, { stdio: "ignore" });` (Windows-only command).
- **`test/witness/compaction-coordinator.test.ts`:**
  - Line `32`: Imports `RealEtcdProcess`.
  - Line `457`: `describe("3. Real etcd v3.5.18 + PostgreSQL 16.15 Integration", ...)` instantiates `RealEtcdProcess`.
- **`.github/workflows/ci.yml` (line `64`) & `Dockerfile` (line `34`):**
  - Both execute `npx vitest run --exclude "**/*.real.test.ts"` on `ubuntu-24.04` / `node:26.11.1-bookworm-slim`.
  - Because `compaction-coordinator.test.ts` is **not** named `*.real.test.ts`, it is **not excluded** and will fail in Linux CI when `.tmp/etcd-bin/v3.5.18/etcd.exe` is absent.

### 3.2 Reproducible Linux CI Compatibility Options (Not Implemented)
1. **Option A (Minimal / Consistent with Stage 2-A.2):** Split Section 3 (`describe("3. Real etcd v3.5.18...")`) into `test/witness/compaction-coordinator.real.test.ts` so `--exclude "**/*.real.test.ts"` in `ci.yml` and `Dockerfile` excludes it cleanly while keeping all unit + PG 16 fault-injected compaction tests active in Linux CI.
2. **Option B (Full Linux Real-etcd Execution):** Update `RealEtcdProcess` to resolve `etcd` / `etcdctl` without `.exe` and use `process.kill(pid, "SIGKILL")` on non-`win32` platforms, and add a CI step to download and SHA-256-verify `etcd-v3.5.18-linux-amd64.tar.gz` into `.tmp/etcd-bin/v3.5.18/`.

---

## 4. Git & PR Synchronization (Read-Only Remote Inspection)

- **`git show-ref` (Local):**
  - `refs/heads/feature/m13-d-consensus`: `f69da6b16c86a4ddc713ea0312a8c618ee5a9090`
  - `refs/remotes/origin/feature/m13-d-consensus`: `f69da6b16c86a4ddc713ea0312a8c618ee5a9090`
  - `refs/heads/main`: `0fa8d1537658eed43af2c5b75547f6f5727e063a`
  - `refs/remotes/origin/main`: `c43f5be3cc1302e73dd429d5134672d88bd913b9`
- **`git ls-remote origin` (Live Remote):**
  - `refs/heads/feature/m13-d-consensus`: `f69da6b16c86a4ddc713ea0312a8c618ee5a9090`
  - `refs/heads/main`: `650427d3530d543f5642b94e46fdfae5130fc840` *(live `origin/main` is ahead of local tracking `c43f5be`)*
  - `refs/pull/1/head`: `f69da6b16c86a4ddc713ea0312a8c618ee5a9090` *(PR #1 is open)*
  - `refs/pull/1/merge`: `673aff7ba49ac431b6c91fa806b8a03af34aa97e` *(GitHub computed clean merge ref)*
- **Ancestry & Overlap:** `git merge-base main HEAD` = `0fa8d15`. `main..HEAD` = `10` commits ahead, `0` behind. `main..origin/main` (`c43f5be`) touches only `.github/FUNDING.yml` and `README.md` (zero overlap with Stage 2-B.0/2-B.1/2-B.2).

---

## 5. Commit Plan Reconciliation

All 5 proposed commit groups from `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md` were re-verified:
- **Exact File Lists & Dependencies:** Group A (`13` Stage 2-B.0/2-B.1 docs) -> Group B (`5` Stage 2-B.2 plan/gate docs) -> Group C (`14` Stage 2-B.2 source/migration/test files, atomic) -> Group D (`20` Stage 2-B.2 Step 1–7 reports, audits & closure) -> Group E (`4` readiness, progress, integration plan & this preflight report).
- **Exclusions Verified:** `funding/application/` (`20` files), `.demo-data/`, `.tmp/`, `.wrangler/`, `dist/`, `node_modules/`, `test/policy.test.ts.bak` remain excluded.
- **Checksums & Secrets:** All `14` Group C deliverables match accepted SHA-256 checksums; zero real secrets or generated artifacts in any proposed commit group.

---

## 6. Exact Remaining Actions & Verdict

- **Verdict:** **CONDITIONAL GO**
  1. **Authorized Next (upon Founder Approval):** Commit Groups A–E onto `feature/m13-d-consensus` (keeping `funding/` untracked).
  2. **Required Before Merging PR #1 to `main`:** Resolve the Linux CI `compaction-coordinator.test.ts` / `RealEtcdProcess` issue (Option A or B above), run `git fetch origin`, and verify PR #1 checks pass on `ubuntu-24.04` + `docker compose`.
- **Report SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-GIT-INTEGRATION-PREFLIGHT-REPORT.md`.
