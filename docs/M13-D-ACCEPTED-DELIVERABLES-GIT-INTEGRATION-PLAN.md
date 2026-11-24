# Web3User — M13-D Accepted Deliverables Git Integration Plan

**Document ID:** `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md`  
**Date:** November 25, 2026  
**Repository:** `C:/Users/syeds/Projects/Web3User` (`origin`: `https://github.com/syedsenterprises/Web3User-Permission-Lab.git`)  
**Current Branch:** `feature/m13-d-consensus` (`f69da6b`)  
**Authorization Scope:** Read-only inspection and Git integration planning only. **No files staged, committed, pushed, merged, rebased, or modified.**

---

## 1. Repository Baseline

| Item | Observed State |
| :--- | :--- |
| **Active Branch & HEAD** | `feature/m13-d-consensus` at `f69da6b` (`feat(website): synchronize live production release assets and SEO metadata`) |
| **Remote Tracking (`origin/feature/m13-d-consensus`)** | `f69da6b` (in sync with local `feature/m13-d-consensus`) |
| **Local `main`** | `0fa8d15` (`feat(security): integrate durable witness lifecycle and remediate startup synchronization vulnerabilities (milestone 13-C & 13-C.1)`) |
| **Remote `origin/main`** | `c43f5be` — local `main` is **behind `origin/main` by 2 commits** (`2c3a7da Configure funding sources in FUNDING.yml`, `c43f5be Add Support this project section to README`) |
| **Branch Divergence (`main..HEAD`)** | `feature/m13-d-consensus` has **10 commits** ahead of `0fa8d15`: `5f620e2` -> `d0960c9` -> `25bfe62` -> `123adb8` -> `ec76386` -> `e81517c` -> `dd5cfff` -> `ef21964` -> `694a951` -> `f69da6b` |
| **Pull Request State** | `gh` CLI is not installed locally; remote PR state must be verified in GitHub UI before merging. |
| **Working Tree (`git status --porcelain -uall`)** | **0 modified (`M`), 0 deleted (`D`), 0 staged** tracked files; **72 untracked files (`??`)** across `docs/` (38), `src/witness/` (8), `test/witness/` (6), and `funding/application/` (20). *(Plus `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md` added by this task.)* |

---

## 2. Complete Candidate File Inventory & Classification

### Category 1 — Accepted Stage 2-B.0 Deliverables (5 files, `??` untracked)
| Path | Purpose & Acceptance Evidence | Recommended Treatment |
| :--- | :--- | :--- |
| `docs/M13-D-PHASE-D3-ARCHITECTURE-CHALLENGE.md` | Phase D3 architecture challenge | **Stage & Commit (Group A)** |
| `docs/M13-D-PHASE-D3-RAFT-READINESS-ASSESSMENT.md` | Phase D3 Raft readiness assessment | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B0-CONSENSUS-STATE-AND-FENCING-DESIGN.md` | Stage 2-B.0 consensus state & fencing design | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B0.1-ARCHITECTURE-DECISION-CLOSURE.md` | Stage 2-B.0.1 architecture decision closure | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B0.2-FINAL-ARCHITECTURE-VERIFICATION.md` | Stage 2-B.0.2 final architecture verification | **Stage & Commit (Group A)** |

### Category 2 — Accepted Stage 2-B.1 Deliverables (8 files, `??` untracked)
| Path | Purpose & Acceptance Evidence | Recommended Treatment |
| :--- | :--- | :--- |
| `docs/M13-D-STAGE-2B1-IMPLEMENTATION-REPORT.md` | Stage 2-B.1 pure state-machine implementation report | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-INDEPENDENT-AUDIT.md` | Stage 2-B.1 independent audit | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-1-CORRECTNESS-CLOSURE.md` | Stage 2-B.1.1 correctness closure | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-1-INDEPENDENT-AUDIT.md` | Stage 2-B.1.1 independent audit | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-2-HISTORICAL-RETENTION-SNAPSHOT-DECISIONS.md` | ADR-010..014 historical retention & snapshot decisions | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-2-1-ADR-PRECISION-AMENDMENT.md` | ADR precision amendment | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-2-2-INDEPENDENT-ADR-AUDIT.md` | Independent ADR audit | **Stage & Commit (Group A)** |
| `docs/M13-D-STAGE-2B1-2-3-FINAL-ADR-CLOSURE.md` | Final ADR-010..014 closure | **Stage & Commit (Group A)** |

### Category 3 — Accepted Stage 2-B.2 Implementation & Test Files (14 files, `??` untracked)
| Path | Purpose & Acceptance Evidence | Recommended Treatment |
| :--- | :--- | :--- |
| `src/witness/canonical-serializer.ts` | Step 1/1.1 `TTCF-v1` & `Canon-v1` serializer (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/state-machine-types.ts` | Step 2 state-machine types & retention interfaces (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/state-machine.ts` | Step 2 pure reducer, retention floor & backpressure (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | Step 3 Migration 004 forward DDL (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | Step 3 Migration 004 rollback DDL (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/consensus-store.ts` | Step 4 `PostgresConsensusStore` (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/snapshot-manager.ts` | Step 5 `SnapshotManager` (Accepted) | **Stage & Commit (Group C)** |
| `src/witness/compaction-coordinator.ts` | Step 6 `CompactionCoordinator` (Accepted) | **Stage & Commit (Group C)** |
| `test/witness/canonical-ttcf.test.ts` | Step 1/1.1 52 tests (Accepted) | **Stage & Commit (Group C)** |
| `test/witness/state-machine.test.ts` | Step 2 state-machine & retention tests (Accepted) | **Stage & Commit (Group C)** |
| `test/witness/migration-004.test.ts` | Step 3 Migration 004 tests (Accepted) | **Stage & Commit (Group C)** |
| `test/witness/consensus-store.test.ts` | Step 4 25 live PG 16 tests (Accepted) | **Stage & Commit (Group C)** |
| `test/witness/snapshot-manager.test.ts` | Step 5 10 PG 16 + POSIX + S3/GCS tests (Accepted) | **Stage & Commit (Group C)** |
| `test/witness/compaction-coordinator.test.ts` | Step 6 6 real `etcd v3.5.18` + PG 16 tests (Accepted) | **Stage & Commit (Group C)** |

### Category 4 & 5 — Stage 2-B.2 Planning, Independent Audits & Remediation Reports (20 files, `??` untracked)
- **Planning & Architecture Gates (5 files -> Group B):**
  - `docs/M13-D-STAGE-2B2-INDEPENDENT-TECHNICAL-CHALLENGE.md`
  - `docs/M13-D-STAGE-2B2-RECONCILIATION-REPORT.md`
  - `docs/M13-D-STAGE-2B2-IMPLEMENTATION-PLAN.md`
  - `docs/M13-D-STAGE-2B2-PREIMPLEMENTATION-VERIFICATION.md`
  - `docs/M13-D-STAGE-2B2-FINAL-ARCHITECTURE-GATE.md`
- **Step 1–6 Implementation, Remediation & Independent Audit Reports (15 files -> Group D):**
  - `docs/M13-D-STAGE-2B2-STEP-1-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-1-INDEPENDENT-AUDIT.md` *(superseded by Step 1.1; preserve for audit trail)*
  - `docs/M13-D-STAGE-2B2-STEP-1-1-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-1-1-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B2-STEP-2-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-2-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B2-STEP-3-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-3-INDEPENDENT-AUDIT.md` *(superseded by Step 3 Remediation; preserve for audit trail)*
  - `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-3-REMEDIATION-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B2-STEP-4-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-4-INDEPENDENT-AUDIT.md` *(superseded by Step 4 Remediation; preserve for audit trail)*
  - `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-4-REMEDIATION-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B2-STEP-5-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-5-INDEPENDENT-AUDIT.md`
  - `docs/M13-D-STAGE-2B2-STEP-6-IMPLEMENTATION-REPORT.md`, `docs/M13-D-STAGE-2B2-STEP-6-INDEPENDENT-AUDIT.md`

### Category 6 — Acceptance and Closure Records (2 files, `??` untracked -> Group D)
- `docs/M13-D-STAGE-2B2-STEP-7-FINAL-VERIFICATION-REPORT.md` (SHA-256: `1A53BE552C4EE3200EB2F6EA2F701BD25AA67FD690A37CA6D141100B634978D1`)
- `docs/M13-D-STAGE-2B2-FORMAL-CLOSURE-RECORD.md` (SHA-256: `746479E4B3BF07F16E9A8EDD829484FFCEF57B70F274E92270A6449B00E75CD7`)

### Category 7 — Production-Readiness & Planning Documentation (3 files, `??` untracked -> Group E)
- `docs/M13-D-STAGE-2B3-PRODUCTION-READINESS-ASSESSMENT.md` (SHA-256: `A887C38C1D40F2C4AB78D4A28708385307C20EB4A0B0C339BD231D1F39E97038`)
- `docs/WEB3USER-FULL-PRODUCTION-PROGRESS.md` (SHA-256: `4AB9094C8976248D1569E824D3794D77C5A5C6BF496992634588DD2858C8E575`)
- `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md` *(this document)*

### Category 8 — Pre-Existing Unrelated / Non-Milestone Files (20 files, `??` untracked -> **EXCLUDE**)
- `funding/application/*` (20 files: `build_deck.py`, `Web3User-TECH-Funding-Pitch-Deck.pdf`, `Web3User-TECH-Funding-Pitch-Deck.pptx`, `Web3User-Application-Content.md`, `Web3User-Market-Research-Sources.md`, `Web3User-Pitch-Deck-Speaker-Notes.md`, `Web3User-Video-Narration-Script.md`, `assets/screenshot-playground.png`, `preview_slides/slide_01.png..slide_12.png`).
- **Treatment:** **Explicitly EXCLUDED** from M13-D staging/commits. Leave untracked or handle in a separate non-engineering commit if desired by the founder.

### Category 9 & 10 — Generated Artifacts, Temp Files & Secrets (Gitignored -> **EXCLUDE**)
- `.demo-data/authorization-replay.sqlite`, `.demo-data/bound-authorization-replay.sqlite`, `.tmp/` (contains `etcd.exe`), `.wrangler/`, `dist/`, `node_modules/`, `test/policy.test.ts.bak` — all properly ignored by `.gitignore`.
- No `.env`, `.env.*`, `*.pem`, `*.key`, `*.pfx`, or `*.p12` files exist in the workspace.

---

## 3. Proposed Exact Staging Groups & Commit Boundaries

To preserve clean Git history and ensure `tsc` + `vitest` pass at every code commit boundary:

1. **Commit 1 (Group A — Stage 2-B.0 & 2-B.1 Architecture & ADR Closure):**
   - Message: `docs(m13-d): archive Stage 2-B.0 and 2-B.1 consensus architecture and ADR closure`
   - Files: 13 files (Category 1 + Category 2).
2. **Commit 2 (Group B — Stage 2-B.2 Planning & Pre-Implementation Gates):**
   - Message: `docs(m13-d): add Stage 2-B.2 implementation plan and pre-implementation gates`
   - Files: 5 planning/gate docs.
3. **Commit 3 (Group C — Stage 2-B.2 Implementation & Test Suites):**
   - Message: `feat(witness): implement Stage 2-B.2 consensus state machine, Migration 004, SnapshotManager, and CompactionCoordinator`
   - Files: All 14 files in Category 3 (`8` source/migration + `6` test files). *Keeping all 14 together guarantees TypeScript compilation and full regression pass at the exact commit.*
4. **Commit 4 (Group D — Stage 2-B.2 Step Reports, Audits & Formal Closure):**
   - Message: `docs(m13-d): record Stage 2-B.2 step reports, independent audits, and formal closure`
   - Files: 18 Step 1–6 reports/audits + 2 Step 7/Closure docs = 20 files.
5. **Commit 5 (Group E — Stage 2-B.3 Readiness & Whole-Platform Progress Baseline):**
   - Message: `docs(m13-d): add Stage 2-B.3 production readiness and whole-platform progress baseline`
   - Files: `docs/M13-D-STAGE-2B3-PRODUCTION-READINESS-ASSESSMENT.md`, `docs/WEB3USER-FULL-PRODUCTION-PROGRESS.md`, `docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md`.

---

## 4. Checksum Verification Results

All 8 source/migration files and 6 test files match their accepted Steps 1–7 SHA-256 baselines **100%** with zero missing or modified deliverables:

| File | Verified SHA-256 | Baseline Match |
| :--- | :--- | :---: |
| `src/witness/canonical-serializer.ts` | `DF8EA55DD5B0666BD4714E63C09A5D6AF1445BFFA6FCB21EF64D80746077D3F5` | Exact Match (Step 1.1) |
| `src/witness/state-machine-types.ts` | `DD006076305D262D28CF1BA57C9FF762C516C916264AD04FD923726A8A3EC620` | Exact Match (Step 2) |
| `src/witness/state-machine.ts` | `C2CB8BFAF70D0F4D568DFB5CC23F8892FFB4E6869BAFEBB7850B9E949A1A9335` | Exact Match (Step 2) |
| `src/witness/migrations/004_d3_consensus_persistence.sql` | `98D4D5E56287220E264685F51CD7FC88D658A902A7CB44C70E415CB691945341` | Exact Match (Step 3 Rem.) |
| `src/witness/migrations/004_d3_consensus_persistence.rollback.sql` | `85B431C2E2D54EE3686EC4EAD3A52003AB90CA679ACEB9C124D58531D59ABF74` | Exact Match (Step 3 Rem.) |
| `src/witness/consensus-store.ts` | `6262EB7C090C06ED000DF2E93AB2910828950A6AC6EFDCDFED32D116EE08F88F` | Exact Match (Step 4 Rem.) |
| `src/witness/snapshot-manager.ts` | `C58F204033763A4368D7652DDF069E8D79CD6EAB2C476340F6C0713838E8BF4C` | Exact Match (Step 5) |
| `src/witness/compaction-coordinator.ts` | `40CCEA5C66D85C53BDD7B38B164EE459B6FD1E2373627B993BF1A0C252CA4224` | Exact Match (Step 6) |
| `test/witness/canonical-ttcf.test.ts` | `C49DA311AA71C103564857B49CFD1DD813169789CFDCCAAC2A7CC8E143D00549` | Exact Match (Step 1.1) |
| `test/witness/state-machine.test.ts` | `3BF0051891E0A58DBA10727F005C8B1E33F64E7F58B19C5F95F9E90A139C73E8` | Exact Match (Step 2) |
| `test/witness/migration-004.test.ts` | `521E9315BCF8DFB09051C70783E46A6A7F72F1C362FAE7E4FC87D8B83FA6FD01` | Exact Match (Step 3 Rem.) |
| `test/witness/consensus-store.test.ts` | `3D879DD1B848E219F82622C9783F91AD2F3A702522903C0A6BA00FC6C61C2D6B` | Verified Step 4 Rem. |
| `test/witness/snapshot-manager.test.ts` | `0DD052CF24A6F4FBB4706BFD9013962145FC2C25CF2DBE0BB5F3E2F906CF9288` | Exact Match (Step 5) |
| `test/witness/compaction-coordinator.test.ts` | `BF39D4C7E6EF4005933EB8395F75D8DC74D5C140C933890488DB6E182C1C04B7` | Exact Match (Step 6) |

---

## 5. Secret-Scanning Results (`Gitleaks 8.30.1`)

| Target Scanned | Command | Result | Notes |
| :--- | :--- | :---: | :--- |
| `docs/` | `gitleaks detect --no-git --source docs --config .gitleaks.toml` | **0 leaks** | Clean (`879.14 KB`) |
| `src/witness/` | `gitleaks detect --no-git --source src/witness --config .gitleaks.toml` | **0 leaks** | Clean (`491.49 KB`) |
| `funding/` | `gitleaks detect --no-git --source funding --config .gitleaks.toml` | **0 leaks** | Clean (`101.89 KB`) |
| `test/witness/` | `gitleaks detect --no-git --source test/witness --config .gitleaks.toml` | **12 false positives** | All 12 matches are `KeySpec: "ECC_NIST_EDWARDS25519"` (AWS KMS enum string) in already-committed `FN-SEC-01` tests (`grpc-kms-integration.test.ts`, `cloud-kms-signer.test.ts`, `cloud-kms-e2e-pipeline.test.ts`). **0 leaks** in all 6 Stage 2-B.2 test files. |

---

## 6. CI Validation Plan & PR Integration Risks

1. **CI Workflow Scope (`.github/workflows/ci.yml`):**
   - Triggers only on `main` (`push` / `pull_request` to `main`).
   - Runs `npm run build`, `npx tsc --noEmit`, `npx vitest run --exclude "**/*.real.test.ts"` (against `postgres:16-alpine`), `npx tsx examples/basic-authorization.ts`, `npm run demo:persistent-replay -- --verify`, `npm pack --dry-run --json`, and `docker compose` (`DR-2B`).
   - **Important:** `compaction-coordinator.test.ts` uses `RealEtcdProcess` (`.tmp/etcd-bin/v3.5.18/etcd.exe` on Windows); Linux CI does not include `.tmp/` so `compaction-coordinator.test.ts` may fail in Linux CI unless `etcd` is installed in the runner or the real-etcd test is gated/named `*.real.test.ts` or provided an etcd binary. **Verify this in a separate PR/CI check before merging to `main`.**
2. **`origin/main` Divergence:** Local `main` (`0fa8d15`) is behind `origin/main` (`c43f5be`) by 2 commits (`2c3a7da`, `c43f5be`). Merging `feature/m13-d-consensus` into `main` via PR will include `5f620e2..f69da6b` plus Commits 1–5 above; no file conflicts are expected with `2c3a7da`/`c43f5be` (`FUNDING.yml` / `README.md`), but PR diff should be reviewed in GitHub before merge.

---

## 7. Recommended Execution Sequence & Founder Authorizations Required

1. **Founder Authorization #1 (Commit on `feature/m13-d-consensus`):** Authorize executing Commits 1–5 in order on `feature/m13-d-consensus`, leaving `funding/` untracked, then running `npm run build`, `npx tsc --noEmit`, and `npx vitest run`.
2. **Founder Authorization #2 (Push & PR Validation):** Authorize `git push origin feature/m13-d-consensus` and opening/updating the PR against `origin/main` (`c43f5be`) to observe GitHub Actions `ci.yml` results (specifically checking `compaction-coordinator.test.ts` behavior on `ubuntu-24.04` without `.tmp/`).
3. **Founder Authorization #3 (Merge to `main`):** Only after CI passes cleanly on the PR.

---

## 8. Checksum & Git Governance

- **Governance:** Read-only planning; zero files staged, committed, pushed, merged, rebased, or modified.
- **Plan SHA-256:** Verified externally via `Get-FileHash -Algorithm SHA256 docs/M13-D-ACCEPTED-DELIVERABLES-GIT-INTEGRATION-PLAN.md`.
