# Web3User Permission Lab — System Mindmap & Engineering Roadmap

**Status snapshot:** 23 November 2026 (Updated from 3 November 2026 baseline)  
**Repository:** `syedsenterprises/Web3User-Permission-Lab`  
**Development branch:** `feature/m13-d-consensus`  
**Development HEAD:** `ef219646ce8dbcfb3f6e9120fb2c365a4119f119`  
**Public release tag:** `v0.1.0-rc.1` (historical release-candidate tag; not the current development HEAD)  
**Status:** M0–M13-C.1 implementation history; M13-D foundation committed; DR-2B container verification accepted; Phase 1-A source-protection commit pushed; security hygiene commit pushed (`ec76386`); M13-D Stage 2-A.2 single-node real-etcd integration accepted; **FN-SEC-01 (Production Readiness: Cloud KMS/HSM Signing Adapter — Steps 1–4) accepted, committed, and pushed (`ef21964`)**.  
**Important:** This is a development-stage, off-chain authorization SDK. It is not a production wallet, hosted authorization API, transaction broadcaster, custody system, or independently audited security product.  

---

## 1. Product vision and scope

- Explicit, deterministic, testable off-chain policy decisions for proposed Web3 actions.
- Decision model: **ALLOW / DENY / UNKNOWN**.
- Wallets, smart accounts, dApps, relayers, bundlers, and autonomous agents are potential integration points.
- The SDK does not custody user assets, sign EVM transactions, broadcast transactions, or provide a universal wallet enforcement layer.
- No token launch, custody, or unverified mainnet deployment is in scope.

## 2. Policy and authorization foundation — implemented

- ERC-20 `transfer(address,uint256)` evaluator and strict calldata validation.
- Canonical transaction/policy binding digests.
- Ed25519 V3 signed authorization artifacts and length-prefixed canonical serialization.
- SQLite WAL persistence for authorization lifecycle, key governance, policy revisions, and replay protection.
- Single-use authorization consumption and fail-closed validation.
- Cumulative budget enforcement and hardened transaction boundaries.
- Monotonic clock protections, contention handling, safe TTL arithmetic, adversarial tests, and process-crash recovery validation.

## 3. Witness and consensus evolution

- **Milestone 10:** disaster-recovery, lock-hold optimization, and adversarial concurrency hardening — represented by the committed milestone history.
- **Milestone 11:** monotonic witness adapter and fail-closed recovery — committed.
- **Milestones 12 / 13-B:** durable monotonic witness and bounded reconciliation pipeline — committed.
- **Milestones 13-C / 13-C.1:** durable witness lifecycle integration and startup synchronization vulnerability remediation — committed on `main`.
- **Milestone 13-D:** durable witness / consensus foundation — committed on development branch `feature/m13-d-consensus` (HEAD: `ef21964`).
- **M13-D real-etcd integration (Stage 2-A.2):** single-node real-etcd integration harness is **ACCEPTED** (26/26 tests passed in 12.61s natively on Windows 11 AMD64 against official etcd v3.5.18 on HEAD `ec76386`). Multi-node Raft clustering, quorum partitions, and leader elections remain future Stage 2-B / Stage 3 work and are not authorized by this acceptance.
- **FN-SEC-01 Cloud KMS/HSM signing adapter (Steps 1–4):** **ACCEPTED, COMMITTED, AND PUSHED (`ef21964`)**. PureEd25519 canonical signing preimage format unified, AWS KMS and GCP Cloud KMS adapters authored with CRC32C descriptor verification and canonical raw-key SHA-256 fingerprint validation, production guardrails enforced (prohibiting local signers in production), and hermetic PostgreSQL E2E pipeline validated across recovery paths (760/760 tests passing).

## 4. Disaster recovery and reproducible verification

### Accepted verification

- Phase 0-F.2.5: non-root Dockerfile hardening.
- Phase 0-F.2.6: isolated Docker Compose validation accepted.
- **Test Baselines:**
  - **Full repository regression suite (HEAD `ef21964`):** **37 test files, 760 tests passed, 0 failures, 0 pending, 0 todo** in Vitest v5.0.5 (`step4-full-suite-run.json`).
  - **FN-SEC-01 Hermetic PostgreSQL E2E suite:** **1 test file, 9 tests passed, 0 failures** in `test/witness/cloud-kms-e2e-pipeline.test.ts`.
  - **Linux container baseline (DR-2B):** **32 test files, 655 tests passed, 0 failures**. (Excluded native Windows `*.real.test.ts` suites).
  - **Native Windows real-etcd validation (Stage 2-A.2 on commit `5f620e2` / HEAD `ec76386`):** **1 test file, 26 tests passed, 0 failures, 0 skipped** in 12.61s with exit code 0.
- Basic authorization example, persistent replay demo, and npm package dry-run passed.
- PostgreSQL test service uses dedicated test database `web3user_witness_test` with dynamic epoch allocation and accumulator truncation for inter-test isolation. Zero production databases or external cloud APIs are accessed.
- Cleanup removed only the validation project's containers and network. Existing host PostgreSQL and other Docker resources were preserved.

### Source protection & security hardening

- **Phase 1-A:** exactly five approved files committed and pushed (`25bfe62fbb1542e2f8512f522f9c8e4892b4ad97`).
- **Security Audit & Git Hygiene:** commit `ec763861db1fe3d75350149f68dc24c05a3a78fa` pushed; Gitleaks clean across all Git commits.
- **FN-SEC-01 Workstream Closure:** commit `ef219646ce8dbcfb3f6e9120fb2c365a4119f119` pushed; 18 approved deliverable files committed atomically; independent acceptance audit verdict `ACCEPT — PASS`.
- Development branch is fully synchronized with `origin/feature/m13-d-consensus` after all pushes.
- These source-protection and hygiene milestones are not a production deployment.

## 5. Current production-readiness blockers

These are open engineering requirements, not completed features:

1. **Revocation freshness:** the 30-second fail-closed freshness gate still needs a reliable background refresh / synchronization mechanism and integration validation.
2. ~~**Receipt preimage compatibility:**~~ **RESOLVED & ACCEPTED** by FN-SEC-01 Step 2B. Unified PureEd25519 canonical hashing across Engine and gRPC service.
3. ~~**Hardware-backed signing:**~~ **RESOLVED & ACCEPTED** by FN-SEC-01 Steps 1–4. AWS KMS and GCP Cloud KMS signing adapters implemented, verified, hardened, and operationalized.
4. **Air-gapped recovery key ceremony:** backup encryption key generation, offline custody, and physical Safes A/B provisioning are not complete.
5. **Cross-store recovery:** PostgreSQL, etcd, and SQLite backup/reconciliation procedures require end-to-end restore validation.
6. **Authority and availability:** PostgreSQL remains the live authority / single point of failure; etcd is not yet confirmed as the live authorization path.
7. **RPO / RTO:** recovery objectives have not been demonstrated by measured restore exercises.
8. **Independent security review:** formal independent commercial security audit has not been completed.

## 6. Roadmap status

| Workstream | Status | Evidence / exit condition |
|---|---|---|
| M0–M8: evaluator, signing, persistence, budgets, hardening | Implemented | Repository milestone history and automated tests |
| M9–M10: adversarial and disaster-recovery hardening | Implemented in milestone history | Commits for budget hardening and DR/concurrency work |
| M11: monotonic witness adapter | Committed | Milestone 11 commit |
| M12 / M13-B: witness and reconciliation pipeline | Committed | Milestone 12 / 13-B commit |
| M13-C / 13-C.1: durable witness lifecycle integration | Committed on main | Main-branch commit `0fa8d15` |
| M13-D: durable witness / consensus foundation | Committed on development branch | Commit `5f620e2` in `feature/m13-d-consensus` (HEAD: `ef21964`) |
| M13-D real-etcd integration validation (Stage 2-A.2) | **Accepted (Single-Node Scope)** | Fresh native Windows validation (26/26 passed in 12.61s on `ec76386`); commit `5f620e2` |
| DR-2B: reproducible Linux Compose harness | Accepted | 655/655 Linux-compatible tests; 26 Windows real-etcd tests excluded |
| Phase 1-A: source protection | Complete | Commit `25bfe62` pushed; local and remote branch synchronized |
| Security audit & Git hygiene | Complete | Commit `ec76386` pushed; Gitleaks clean across all Git commits |
| **FN-SEC-01: Cloud KMS/HSM signing adapter & verification (Steps 1–4)** | **Accepted & Pushed (`ef21964`)** | 18 deliverable files; 760/760 tests passed; independent acceptance audit PASS |
| Stage 2-B / Stage 3: multi-node Raft cluster | Strictly unauthorized | Blocked by production readiness sequencing |
| Production readiness | Partially unlocked | KMS adapters & receipt preimages completed; blocked by open revocation, backup, and recovery gates |
| Public stable release | Not released | Requires release criteria, CI evidence, and security review |

## 7. Next recommended sequence

1. Address the open production blockers in Section 5:
   - Implement revocation freshness background worker.
   - Complete offline backup-key ceremony and cross-store restore/reconciliation exercises.
   - Measure RPO/RTO with repeatable failure-and-restore drills.
   - Commission an independent commercial security review before any production use or stable release.
2. Plan Stage 2-B / Stage 3 multi-node Raft cluster validation (when authorized).

---

## Mindmap tree

```text
Web3User Permission Lab
|
+-- Product boundary
|   +-- Off-chain policy decision SDK
|   +-- ALLOW / DENY / UNKNOWN
|   +-- No custody / no EVM signing / no broadcast
|
+-- Authorization foundation [IMPLEMENTED]
|   +-- ERC-20 transfer evaluator
|   +-- Canonical transaction binding
|   +-- Ed25519 V3 authorization artifacts
|   +-- SQLite WAL lifecycle and replay protection
|   +-- Policy/key governance and cumulative budgets
|   +-- Clock, contention, TTL, adversarial hardening
|
+-- Witness / consensus [IN PROGRESS]
|   +-- M11 monotonic witness adapter [COMMITTED]
|   +-- M12 / M13-B reconciliation pipeline [COMMITTED]
|   +-- M13-C / C.1 durable witness integration [MAIN]
|   +-- M13-D consensus foundation [DEV BRANCH — HEAD: ef21964]
|   +-- Real-etcd integration harness (Stage 2-A.2) [ACCEPTED — SINGLE-NODE ONLY]
|   +-- FN-SEC-01 Cloud KMS/HSM signing adapter (Steps 1-4) [ACCEPTED & PUSHED]
|   +-- Stage 2-B / Stage 3 multi-node Raft cluster [UNSTARTED — UNAUTHORIZED]
|
+-- Verification and source protection
|   +-- Docker non-root verification image [ACCEPTED]
|   +-- Isolated Compose PostgreSQL harness [ACCEPTED]
|   +-- 655 Linux-compatible tests [PASSED]
|   +-- 26 Windows real-etcd tests [PASSED NATIVELY — STAGE 2-A.2 ACCEPTED]
|   +-- 760 full-suite regression tests [PASSED ON HEAD ef21964]
|   +-- Phase 1-A five-file source commit [PUSHED]
|   +-- Security audit & Git hygiene [PUSHED]
|   +-- FN-SEC-01 18-file deliverable commit [PUSHED]
|
+-- Production readiness [PARTIALLY UNLOCKED]
    +-- Canonical receipt preimage compatibility [RESOLVED — FN-SEC-01 STEP 2B]
    +-- AWS/GCP KMS signer adapter & verification [RESOLVED — FN-SEC-01 STEPS 1-4]
    +-- Revocation freshness worker [OPEN]
    +-- Air-gapped backup key ceremony [OPEN]
    +-- PostgreSQL / etcd / SQLite recovery reconciliation [OPEN]
    +-- RPO / RTO restore drills [OPEN]
    +-- Independent commercial security audit [OPEN]
```

**Status discipline:** “Committed” means present in Git history; “accepted” means the specified validation evidence was reviewed; “production-ready” requires all production blockers and operational gates to be closed. These labels are not interchangeable.
