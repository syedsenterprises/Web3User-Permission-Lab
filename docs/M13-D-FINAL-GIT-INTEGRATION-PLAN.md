# Web3User — M13-D Final Git Integration Plan (Reconciled)

**Document ID:** `docs/M13-D-FINAL-GIT-INTEGRATION-PLAN.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User` (`origin`: `https://github.com/syedsenterprises/Web3User-Permission-Lab.git`)  
**Current Branch:** `feature/m13-d-consensus` (`f69da6b`)  
**Supersedes:** `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md` *(preserved unchanged for audit trail)*  
**Authorization Scope:** Read-only planning only. **Zero files staged, committed, pushed, merged, rebased, or deployed.**

---

## 1. Reconciled Repository State (`git status --porcelain -uall`)

- **Active Branch & HEAD:** `feature/m13-d-consensus` at `f69da6b` (in sync with `origin/feature/m13-d-consensus`; `PR #1` open against `main`).
- **`main` vs `origin/main`:** Local `main` is at `0fa8d15`; live `origin/main` is at `650427d` (`git ls-remote origin`).
- **Tracked Modified Files (`2`):**
  - `M .github/workflows/ci.yml`
  - `M test/witness/helpers/real-etcd-process.ts`
- **Untracked Candidate Files (`61` + this plan = `62`):**
  - `src/witness/` (`8` files: Stage 2-B.2 production & Migration 004 deliverables)
  - `test/witness/` (`7` files: Stage 2-B.2 test suites + `compaction-coordinator.real.test.ts`)
  - `scripts/ensure-etcd.mjs` (`1` file)
  - `docs/` (`45` files including this plan)
- **Explicitly Excluded (`20` untracked + gitignored transient artifacts):**
  - `funding/application/**` (`20` unrelated files)
  - `.demo-data/*.sqlite`, `.tmp/` (contains `etcd.exe`), `.wrangler/`, `dist/`, `node_modules/`, `test/policy.test.ts.bak`

---

## 2. Reconciled Six-Commit Staging Plan

Reconciles the original 5 commit groups (`docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md`) with the subsequently accepted cross-platform `etcd v3.5.18` infrastructure and `canonical-ttcf.test.ts` TypeScript fix:

### Commit 1 (Group A — `13` files): Stage 2-B.0 & 2-B.1 Architecture & ADR Closure
- **Message:** `docs(m13-d): archive Stage 2-B.0 and 2-B.1 consensus architecture and ADR closure`
- **Files:**
  - `docs/M13-D-PHASE-D3-ARCHITECTURE-CHALLENGE.md`
  - `docs/M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT.md`
  - `docs/M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md`
  - `docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md`
  - `docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md`
  - `docs/M13-D-STAGE-2B1-IMPLEMENTATION-REPORT.md`
  - `docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md`
  - `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md`
  - `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md`
  - `docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md`
  - `docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md`

### Commit 2 (Group B — `5` files): Stage 2-B.2 Planning & Pre-Implementation Gates
- **Message:** `docs(m13-d): add Stage 2-B.2 implementation plan and pre-implementation gates`
- **Files:**
  - `docs/M13-D-STAGE-2B2-INDEPENDENT-TECHNICAL-CHALLENGE.md`
  - `docs/M13-D-STAGE-2B2-RECONCILIATION-REPORT.md`
  - `docs/M13-D-STAGE-2B2-IMPLEMENTATION-PLAN.md`
  - `docs/M13-D-STAGE-2B2-PREIMPLEMENTATION-VERIFICATION.md`
  - `docs/M13-D-STAGE-2B2-FINAL-ARCHITECTURE-GATE.md`

### Commit 3 (Group C1 — `3` files): Cross-Platform etcd v3.5.18 & CI Infrastructure
*(Committed separately before Group C2 so `RealEtcdProcess` and `ci.yml` support `compaction-coordinator.real.test.ts` on both Windows and Ubuntu 24.04 at every commit boundary.)*
- **Message:** `ci(witness): add cross-platform etcd v3.5.18 provisioning and real-etcd CI execution`
- **Files:**
  - `scripts/ensure-etcd.mjs` (`645E94F1ED1A5A12A6AAFE8FE3C22124D95FA8D418FC2293945BDA78087472E9`)
  - `test/witness/helpers/real-etcd-process.ts` (`3B3A261060D4E938F48C57F28CE078CC56F42F5F6419C7D5F130A10E3E5F834E`)
  - `.github/workflows/ci.yml` (`08E4C7E596803F93E9464FAD652D8F0354833FC93CEA2ED9293AF39C889DC34A`)

### Commit 4 (Group C2 — `15` files): Accepted Stage 2-B.2 Implementation & Test Suites
- **Message:** `feat(witness): implement Stage 2-B.2 consensus state machine, Migration 004, SnapshotManager, and CompactionCoordinator`
- **Files & Verified SHA-256 Checksums:**
  - `src/witness/canonical-serializer.ts` (`DF8EA55DD5B0666BD4714E63C09A5D6AF1445BFFA6FCB21EF64D80746077D3F5`)
  - `src/witness/state-machine-types.ts` (`DD006076305D262D28CF1BA57C9FF762C516C916264AD04FD923726A8A3EC620`)
  - `src/witness/state-machine.ts` (`C2CB8BFAF70D0F4D568DFB5CC23F8892FFB4E6869BAFEBB7850B9E949A1A9335`)
  - `src/witness/migrations/004_d3_consensus_persistence.sql` (`98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341`)
  - `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` (`85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74`)
  - `src/witness/consensus-store.ts` (`6262EB7C090C06ED000DF2E93AB2910828950A6AC6EFDCDFED32D116EE08F88F`)
  - `src/witness/snapshot-manager.ts` (`C58F204033763A4368D7652DDF069E8D79CD6EAB2C476340F6C0713838E8BF4C`)
  - `src/witness/compaction-coordinator.ts` (`40CCEA5C66D85C53BDD7B38B164EE459B6FD1E2373627B993BF1A0C252CA4224`)
  - `test/witness/canonical-ttcf.test.ts`:
    - *Historical Step 1.1 accepted SHA-256:* `C49DA311AA71C103564857B49CFD1DD813169789CFDCCAAC2A7CC8E143D00549`
    - *Current post-TS-fix accepted SHA-256:* `6216A36741068F2B4788919E4096079634AF25794224478CF73A703D4753A933`
  - `test/witness/state-machine.test.ts` (`3BF0051891E0A58DBA10727F005C8B1E33F64E7F58B19C5F95F9E90A139C73E8`)
  - `test/witness/migration-004.test.ts` (`521E9315BCF8DFB09051C70783E46A6A7F72F1C362FAE7E4FC87D8B83FA6FD01`)
  - `test/witness/consensus-store.test.ts` (`3D879DD1B848E219F82622C9783F91AD2F3A702522903C0A6BA00FC6C61C2D6B`)
  - `test/witness/snapshot-manager.test.ts` (`0DD052CF24A6F4FBB4706BFD9013962145FC2C25CF2DBE0BB5F3E2F906CF9288`)
  - `test/witness/compaction-coordinator.test.ts` (`7BB7314D920256C212281D5DC6E1682375E0B54BA053E58CAB3BBF553720FFC4`)
  - `test/witness/compaction-coordinator.real.test.ts` (`43CE24632D2DDA8D8DDA10E37DF0189FB621BB04E547A534587DE105B22A60DC`)

### Commit 5 (Group D — `20` files): Stage 2-B.2 Step Reports, Audits & Formal Closure
- **Message:** `docs(m13-d): record Stage 2-B.2 step reports, independent audits, and formal closure`
- **Files:** All 18 Step 1–6 implementation/remediation/audit reports + `docs/M13-D-STAGE-2B2-STEP-7-FINAL-VERIFICATION-REPORT.md` + `docs/M13-D-STAGE-2B2-FORMAL-CLOSURE-RECORD.md`.

### Commit 6 (Group E — `9` files): Readiness, Progress, Cross-Platform & TS-Fix Verification Docs
- **Message:** `docs(m13-d): add Stage 2-B.3 readiness, full progress baseline, CI/TS verification, and final integration plan`
- **Files:**
  - `docs/M13-D-STAGE-2B3-PRODUCTION-READINESS-ASSESSMENT.md`
  - `docs/WEB3USER-FULL-PRODUCTION-PROGRESS.md`
  - `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md`
  - `docs/M13-D-GIT-INTEGRATION-PREFLIGHT-REPORT.md`
  - `docs/M13-D-CROSS-PLATFORM-ETCD-TEST-IMPLEMENTATION-REPORT.md`
  - `docs/M13-D-CROSS-PLATFORM-ETCD-INDEPENDENT-VERIFICATION.md`
  - `docs/M13-D-TYPESCRIPT-TEST-FIX-VERIFICATION.md`
  - `docs/M13-D-TYPESCRIPT-TEST-FIX-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-FINAL-GIT-INTEGRATION-PLAN.md`

---

## 3. Secret-Scanning, CI & Dockerfile Verification

- **Gitleaks (`Gitleaks 8.30.1`, `.gitleaks.toml`):**
  - `src/witness/`, `scripts/ensure-etcd.mjs`, `.github/workflows/ci.yml`, `test/witness/helpers/real-etcd-process.ts`, and all 7 Stage 2-B.2 test suites returned **exit `0` (`0` leaks)**.
  - `docs/` returned exit `1` solely on the pre-existing false-positive match at `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md:155` (quoting the AWS KMS `ECC_NIST_EDWARDS25519` enum string). Zero real secrets exist in any proposed commit.
- **CI & Dockerfile Test Selection:**
  - `.github/workflows/ci.yml` (`ubuntu-24.04`) runs `node scripts/ensure-etcd.mjs`, `npx tsc --noEmit`, `npm run build`, and `npx vitest run` (all `45` files / `929` tests including both `*.real.test.ts` suites).
  - `Dockerfile` runs `npx vitest run --exclude "**/*.real.test.ts"`, cleanly excluding `etcd-client-adapter.real.test.ts` and `compaction-coordinator.real.test.ts` for offline container builds.

---

## 4. Risks & Required Post-Push Validation

1. **Ubuntu 24.04 Live CI Execution (Required Post-Push):** After founder-authorized `git push origin feature/m13-d-consensus`, verify the GitHub Actions `ubuntu-24.04` job (`Node 22.13.0`, `24`, `26`) passes `ensure-etcd.mjs`, `npx tsc --noEmit`, `npx vitest run` (`929/929`), and `docker compose` (`container-verify`) on PR #1.
2. **Remote `origin/main` Sync:** Fetch `origin/main` (`650427d`) and confirm clean mergeability on PR #1 before merging.
3. **Final Plan SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-FINAL-GIT-INTEGRATION-PLAN.md`.
