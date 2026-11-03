# Web3User Permission Lab — Engineering Status & Roadmap

**Snapshot date:** 3 November 2026
**Development branch:** `feature/m13-d-consensus`
**Development HEAD:** `ec763861db1fe3d75350149f68dc24c05a3a78fa`
**Public release tag:** `v0.1.0-rc.1` (historical; not the current development branch head)

## Current state

The project has progressed beyond the M6-era status currently published on the website. The repository history contains milestones through M13-C.1 on `main`, with the M13-D durable-witness / consensus foundation committed on the development branch. The DR-2B Linux container verification harness has been accepted, Phase 1-A source protection has been pushed, public repository secret scanning and Git hygiene hardening have been pushed (`ec76386`), and M13-D Stage 2-A.2 single-node real-etcd integration has been formally accepted.

### Latest verified evidence

- **Docker Compose Linux verification (DR-2B):** **32 test files passed; 655 tests passed; 0 failures**. (Excluded native Windows `*.real.test.ts` suites).
- **Historical native Windows full suite:** **33 test files passed; 681 tests passed; 0 failures** in 154.5s (historical milestone evidence during Stage 2-A.2 development; not a fresh full-suite run on current HEAD).
- **Fresh native Windows real-etcd validation (Stage 2-A.2 on HEAD `ec76386`):** **1 test file; 26 tests passed; 0 failures; 0 skipped; 12.61s duration; exit code 0; 0 orphaned processes**.
- **Official pinned etcd binary:** `etcd-v3.5.18-windows-amd64.zip` (SHA-256: `c17126fe42852d2eef181f94b17af26b6289052de9d28f8fe5edb6783f461c59`).
- **Security audit & Git hygiene:** Gitleaks 8.30.1 clean across all 33 Git commits and working tree on commit `ec76386`.
- Basic authorization example, persistent replay demo, and npm package dry-run passed.
- The PostgreSQL test service used ephemeral tmpfs storage and no published host ports. Its Docker bridge network still permits outbound connectivity; it is not an air-gapped environment.
- The public `v0.1.0-rc.1` tag remains a historical release-candidate tag. No stable production release is claimed.

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
| M13-D — durable witness / consensus foundation | Committed on `feature/m13-d-consensus` |
| M13-D real-etcd integration harness (Stage 2-A.2) | **Accepted (Single-Node Scope)**; 26/26 tests passed natively on HEAD `ec76386` |
| DR-2B — non-root Docker + isolated Compose verification | Accepted; 655/655 Linux-compatible tests |
| Phase 1-A — protect deployment/verification source files | Complete; commit pushed (`25bfe62`) |
| Security Audit & Git Hygiene — secret scanning & ignore hardening | Complete; commit pushed (`ec76386`) |
| Stage 2-B / Stage 3 — consensus state machine & multi-node Raft cluster | Strictly unauthorized and unstarted |
| Production readiness | Blocked by open security, KMS, backup, and recovery work |
| Stable public release | Not released |

## Production blockers

1. Revocation freshness needs reliable background synchronization; the current 30-second fail-closed gate remains a production blocker.
2. Receipt signing preimage formats between gRPC and Engine must be unified and integration-tested.
3. AWS KMS Witness Signer adapter and algorithm/encoding contract tests remain outstanding.
4. Air-gapped backup encryption key ceremony and offline custody are not complete.
5. PostgreSQL / etcd / SQLite cross-store backup and restore reconciliation is not proven end-to-end.
6. PostgreSQL remains the live authority / single point of failure; do not describe etcd as the live authorization path yet.
7. RPO / RTO targets have not been measured in repeatable restore drills.
8. Independent commercial security audit has not been completed.

## Next sequence

1. Address the open production blockers in Section 5:
   - Fix revocation freshness and receipt-preimage compatibility.
   - Implement and contract-test KMS signing.
   - Complete offline key custody and cross-store restore exercises.
   - Measure RPO/RTO with repeatable failure-and-restore drills.
   - Obtain independent security review before production use.
2. Plan Stage 2-B / Stage 3 multi-node Raft cluster validation (when authorized).

**Scope warning:** The Cloudflare site is a static project-information preview. It does not mean the authorization engine, PostgreSQL witness service, or consensus path is deployed as a hosted production backend.
