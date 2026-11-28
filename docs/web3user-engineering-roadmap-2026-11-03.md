# Web3User Permission Lab — Engineering Status & Roadmap

**Snapshot date:** 28 November 2026 (Updated from 23 November 2026 baseline)  
**Development branch:** `feature/m13-d-stage-2b3-multinode`  
**`main` HEAD:** `a37518c05050acd08074948147d591b6ca0c7cb3` (`b0c6bf5` merged PR #2 Stage 2-B.2; `cc452fa`..`a37518c` Hallmark website polish)  
**Public release tag:** `v0.1.0-rc.1` (historical; not the current development branch head)  

## Current state

The project has progressed beyond the M6-era status currently published on the website. The repository history contains milestones through M13-C.1 on `main`, with the M13-D durable-witness / consensus foundation committed on the development branch. The DR-2B Linux container verification harness has been accepted, Phase 1-A source protection has been pushed, public repository secret scanning and Git hygiene hardening have been pushed (`ec76386`), M13-D Stage 2-A.2 single-node real-etcd integration has been formally accepted, and **FN-SEC-01 (Production Readiness: Cloud KMS/HSM Signing Adapter — Steps 1–4)** has been formally accepted, committed, and pushed to `origin/feature/m13-d-consensus` (`ef21964`).

### Latest verified evidence

- **Full repository regression suite (HEAD `ef21964`):** **37 test files passed; 760 tests passed; 0 failures; 0 pending; 0 todo** in Vitest v5.0.5 (`step4-full-suite-run.json`).
- **FN-SEC-01 Hermetic PostgreSQL E2E suite:** **1 test file; 9 tests passed; 0 failures** in `test/witness/cloud-kms-e2e-pipeline.test.ts` (verifying Path B1 replay idempotency, Path B2 engine crash reconciliation, single-key trust-anchor enforcement, key rotation, and adversarial error mappings against genuine local PostgreSQL 16 on `127.0.0.1:5432`).
- **Cloud KMS signer unit & integration test suites:**
  - `test/witness/cloud-kms-signer.test.ts`: 38 tests passed (AWS/GCP signer retry budgets, CRC32C, state machine).
  - `test/witness/signer-factory.test.ts`: 17 tests passed (production guardrails, mandatory fingerprints).
  - `test/witness/grpc-kms-integration.test.ts`: 11 tests passed (gRPC server KMS integration and startup failure boundaries).
  - `test/witness/unit-d2.test.ts`: 24 tests passed (mTLS transport, semver validator, and receipt signing).
- **Docker Compose Linux verification (DR-2B):** **32 test files passed; 655 tests passed; 0 failures** (historical container baseline excluding native Windows tests).
- **Native Windows real-etcd validation (Stage 2-A.2 on commit `5f620e2` / HEAD `ec76386`):** **1 test file; 26 tests passed; 0 failures; 0 skipped; 12.61s duration; exit code 0; 0 orphaned processes**.
- **Official pinned etcd binary:** `etcd-v3.5.18-windows-amd64.zip` (SHA-256: `c17126fe42852d2eef181f94b17af26b6289052de9d28f8fe5edb6783f461c59`).
- **Security audit & Git hygiene:** Gitleaks 8.30.1 clean across all Git commits on `feature/m13-d-consensus`.
- Basic authorization example, persistent replay demo, and npm package dry-run passed.
- The PostgreSQL test service uses dedicated test database `web3user_witness_test` with dynamic epoch allocation and accumulator truncation for inter-test isolation. Zero production databases or external cloud APIs are accessed.
- The public `v0.1.0-rc.1` tag remains a historical release-candidate tag. No stable production release is claimed.

### FN-SEC-01 Formal Acceptance Record (Cloud KMS/HSM Signing Adapter — Steps 1–4)

- **Workstream:** `FN-SEC-01` (Production Readiness — Security)
- **Status:** **ACCEPTED, COMMITTED, AND PUSHED**
- **Commit SHA:** `ef219646ce8dbcfb3f6e9120fb2c365a4119f119`
- **Parent Commit:** `dd5cfff8b0d986d2aa118023b5dc8508dd20cf0c`
- **Active Branch:** `feature/m13-d-consensus` (Synchronized with `origin/feature/m13-d-consensus`)
- **Governing Specification:** `FN-SEC-01-STEP-4-PLANNING-PROPOSAL.md` (Revision 4.14)
- **Independent Acceptance Audit:** `FN-SEC-01-STEP-4-INDEPENDENT-ACCEPTANCE-AUDIT.md` (Verdict: `ACCEPT — PASS`)
- **Total Deliverables:** Exactly 18 files (+5,801 / -124 lines):
  - *Step 1:* `package.json`, `package-lock.json`, `scripts/validate-dependency-pins.mjs`, `src/witness/dependency-validator.ts`
  - *Step 2A:* `src/witness/cloud-kms-signer.ts`, `src/witness/aws-kms-signer.ts`, `src/witness/gcp-kms-signer.ts`, `test/witness/cloud-kms-signer.test.ts`
  - *Step 2B:* `src/witness/signing.ts`, `src/witness/grpc-service.ts`, `src/witness/index.ts`
  - *Step 3:* `src/witness/signer-factory.ts`, `src/witness/grpc-server.ts`, `test/witness/signer-factory.test.ts`, `test/witness/grpc-kms-integration.test.ts`, `test/witness/unit-d2.test.ts`
  - *Step 4:* `test/witness/cloud-kms-e2e-pipeline.test.ts`, `docs/OPERATIONS.md` (Section 6 appended)
- **Full Suite Regression:** 37 files / 760 tests passed, 0 failures, 0 pending, 0 todo.

### Stage 2-A.2 Formal Acceptance Record (Single-Node Real-etcd Integration)

- **Status:** **ACCEPTED**
- **Implementation Commit:** `5f620e2`
- **Fresh Validation HEAD:** `ec763861db1fe3d75350149f68dc24c05a3a78fa`
- **Native Windows Environment:** Windows 11 Pro AMD64 (`win32-x64`)
- **etcd Version:** Official v3.5.18 (`windows/amd64`, Git SHA: `5bca08e`, Go: `go1.22.11`)
- **Binary Archive SHA-256:** `c17126fe42852d2eef181f94b17af26b6289052de9d28f8fe5edb6783f461c59`
- **Real-etcd Test Suite:** `test/witness/etcd-client-adapter.real.test.ts`
- **Execution Results:** **26/26 passed** in **12.61 seconds** (Exit code: 0, Failed: 0, Skipped: 0)
- **Orphaned etcd Processes:** Exactly 0 (verified via `Get-Process -Name 'etcd'`)
- **Working Tree State After Validation:** Clean (`git status --porcelain` empty)

> [!IMPORTANT]
> **Stage 2-A.2 Scope Limitation (Mandatory):**
> Stage 2-A.2 validates strictly:
> 1. Single-node etcd integration and wire protocols (`@grpc/grpc-js` and `etcd3@1.1.2`).
> 2. Linearizable reads and range queries.
> 3. Compare-and-swap (CAS) transactions and branches.
> 4. bbolt B+tree disk storage, Raft WAL persistence, and ungraceful restart recovery.
> 5. Watch creation, reconnection catch-up, and physical compaction error handling.
> 6. Client mTLS authentication (valid, missing, untrusted, and corrupt certificates).
>
> It does **NOT** validate three-node Raft quorum, leader election, split-brain prevention, network partition healing, or distributed failover. Those remain future Stage 2-B / Stage 3 work and are not authorized by this acceptance.

## Roadmap

| Milestone / Workstream | Current status |
|---|---|
| M0–M8 — core evaluator, signing, persistence, budgets, and hardening | Implemented |
| M9–M10 — adversarial and disaster-recovery hardening | Implemented in milestone history |
| M11 — monotonic witness adapter and fail-closed recovery | Committed |
| M12 / M13-B — durable monotonic witness and bounded reconciliation | Committed |
| M13-C / 13-C.1 — durable witness lifecycle integration and startup synchronization remediation | Committed on `main` |
| M13-D — durable witness / consensus foundation | Committed on `feature/m13-d-consensus` (HEAD: `ef21964`) |
| M13-D real-etcd integration harness (Stage 2-A.2) | **Accepted (Single-Node Scope)**; 26/26 tests passed natively |
| DR-2B — non-root Docker + isolated Compose verification | Accepted; 655/655 Linux-compatible tests |
| Phase 1-A — protect deployment/verification source files | Complete; commit pushed (`25bfe62`) |
| Security Audit & Git Hygiene — secret scanning & ignore hardening | Complete; commit pushed (`ec76386`) |
| **FN-SEC-01 — Cloud KMS/HSM signing adapter & verification (Steps 1–4)** | **Complete & Accepted; committed and pushed (`ef21964`); 760/760 tests passed** |
| Stage 2-B / Stage 3 — consensus state machine & multi-node Raft cluster | Strictly unauthorized and unstarted |
| Production readiness | Partially unlocked (KMS adapters & receipt preimages completed; blocked by open revocation, backup, and recovery gates) |
| Stable public release | Not released |

## Production blockers

1. **Revocation freshness:** Needs reliable background synchronization; the current 30-second fail-closed gate remains a production blocker.
2. ~~**Receipt preimage compatibility:**~~ **RESOLVED by FN-SEC-01 Step 2B.** PureEd25519 canonical signing preimage format unified and validated between Engine and gRPC witness service.
3. ~~**Hardware-backed signing:**~~ **RESOLVED by FN-SEC-01 Steps 1–4.** AWS KMS (`ECC_NIST_EDWARDS25519`) and GCP Cloud KMS (`EC_SIGN_ED25519`) signing adapters authored, verified, hardened with CRC32C descriptor validation, signer factory production guardrails, fail-closed error mappings, and hermetic PostgreSQL E2E pipeline (`test/witness/cloud-kms-e2e-pipeline.test.ts`).
4. **Air-gapped backup encryption key ceremony:** Key generation, offline custody, and physical Safes A/B provisioning are not complete.
5. **Cross-store recovery:** PostgreSQL, etcd, and SQLite cross-store backup/restore reconciliation drills remain outstanding.
6. **Authority and availability:** PostgreSQL remains the live authority / single point of failure; do not describe etcd as the live authorization path yet.
7. **RPO / RTO targets:** Have not been demonstrated by measured, repeatable restore drills.
8. **Independent security review:** Formal external commercial security audit has not been completed.

## Next sequence

1. Address the open production blockers in Section 5:
   - Implement revocation freshness background worker.
   - Complete air-gapped backup key ceremony and offline custody protocol.
   - Execute PostgreSQL / etcd / SQLite cross-store disaster recovery drills.
   - Measure RPO/RTO with repeatable failure-and-restore drills.
   - Obtain formal independent commercial security audit before any production deployment.
2. Plan Stage 2-B / Stage 3 multi-node Raft cluster validation (when authorized).

**Scope warning:** The Cloudflare site is a static project-information preview. It does not mean the authorization engine, PostgreSQL witness service, or consensus path is deployed as a hosted production backend.

---

## Verified Synchronization & Blocker Ledger (28 November 2026)

- **Active Branch:** `feature/m13-d-stage-2b3-multinode` (synchronized with `origin/feature/m13-d-stage-2b3-multinode` and merged with `origin/main` at `a37518c`).
- **Latest Verified Full Suite (`npx vitest run` on `feature/m13-d-stage-2b3-multinode`):** **54 test files passed; 984 tests passed; 6 skipped** (env-gated live AWS S3 tests in `test/witness/aws-s3-adapter.real.test.ts`); **0 failures**; `npx tsc --noEmit`, `npm run build`, and `node scripts/validate-dependency-pins.mjs` exited 0.
- **GitHub Actions (`main`):** `CI` (`46075135593`) and `CodeQL Advanced` (`46075135555`) both `completed / success` on `a37518c`. Workflows trigger on `main` pushes/PRs.
- **Cloudflare Deployment:** Worker `super-tree-7537` deployed (`be61dd25-32a9-4980-bfdd-7fc8b08e5130`) serving `https://web3user.tech` and `https://docs.web3user.tech`.
- **Stage 2-B.2 & 2-B.3 Status:** Stage 2-B.2 merged on `main` (PR #2, `b0c6bf5`); Stage 2-B.3 multi-node etcd cluster harness (`test/witness/helpers/real-etcd-cluster.ts`, `loopback-fault-proxy.ts`, `raft-compaction-reconciliation.real.test.ts`) and AWS S3 adapter (`src/witness/aws-s3-adapter.ts`) committed on `feature/m13-d-stage-2b3-multinode`.

### 12 Production Blockers (`BLK-01`..`BLK-12`)

| ID | Blocker | Status |
|---|---|---|
| `BLK-01` | Uncommitted Stage 2-B.2 / diverged `main` | **Closed** (PR #2 merged on `main` at `b0c6bf5`) |
| `BLK-02` | Revocation 30s freshness, no background sync | **Open** |
| `BLK-03` | Live AWS/GCP KMS validation | **Open** |
| `BLK-04` | Air-gapped backup key ceremony, Safes A/B | **Open** |
| `BLK-05` | Cross-store DR drills, measured RPO/RTO | **Open** |
| `BLK-06` | Postgres HA, SSL/TLS, least-privilege roles, PITR | **Open** |
| `BLK-07` | Live S3/GCS snapshot backend validation | **Open** |
| `BLK-08` | Multi-node etcd Raft production cluster (Stage 3) | **Open** |
| `BLK-09` | Observability (Prometheus/OTel), 24h compaction baseline | **Open** |
| `BLK-10` | Independent external security audit | **Open** |
| `BLK-11` | Public SDK / hosted API | **Open** |
| `BLK-12` | Six low advisories (Stage 2-B.2 `F-STEP5-01..04`, `F-STEP6-01..02`) | **Open** |
