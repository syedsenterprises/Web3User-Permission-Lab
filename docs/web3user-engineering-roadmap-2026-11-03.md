# Web3User Permission Lab — Engineering Status & Roadmap

**Snapshot date:** 3 November 2026
**Development branch:** `feature/m13-d-consensus`
**Development HEAD:** `25bfe62fbb1542e2f8512f522f9c8e4892b4ad97`
**Public release tag:** `v0.1.0-rc.1` (historical; not the current development branch head)

## Current state

The project has progressed beyond the M6-era status currently published on the website. The repository history contains milestones through M13-C.1 on `main`, with the M13-D durable-witness / consensus foundation committed on the development branch. The DR-2B Linux container verification harness has been accepted, and Phase 1-A source protection has been pushed.

### Latest verified evidence

- Docker Compose Linux verification: **32 test files passed; 655 tests passed; 0 failures**.
- 26 Windows real-etcd tests were excluded from that Linux run and require separate native Windows validation.
- Basic authorization example, persistent replay demo, and npm package dry-run passed.
- The PostgreSQL test service used ephemeral tmpfs storage and no published host ports. Its Docker bridge network still permits outbound connectivity; it is not an air-gapped environment.
- Phase 1-A commit: `25bfe62fbb1542e2f8512f522f9c8e4892b4ad97`, containing exactly five approved files.
- The public `v0.1.0-rc.1` tag remains a historical release-candidate tag. No stable production release is claimed.

## Roadmap

| Milestone / Workstream | Current status |
|---|---|
| M0–M8 — core evaluator, signing, persistence, budgets, and hardening | Implemented |
| M9–M10 — adversarial and disaster-recovery hardening | Implemented in milestone history |
| M11 — monotonic witness adapter and fail-closed recovery | Committed |
| M12 / M13-B — durable monotonic witness and bounded reconciliation | Committed |
| M13-C / 13-C.1 — durable witness lifecycle integration and startup synchronization remediation | Committed on `main` |
| M13-D — durable witness / consensus foundation | Committed on `feature/m13-d-consensus` |
| M13-D real-etcd integration harness | Pending report review and acceptance |
| DR-2B — non-root Docker + isolated Compose verification | Accepted; 655/655 Linux-compatible tests |
| Phase 1-A — protect deployment/verification source files | Complete; commit pushed |
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

1. Review the dedicated M13-D real-etcd harness report; do not mark it complete before acceptance.
2. Run the 26 Windows real-etcd tests natively.
3. Fix revocation freshness and receipt-preimage compatibility.
4. Implement and contract-test KMS signing.
5. Complete offline key custody and cross-store restore exercises.
6. Measure RPO/RTO.
7. Obtain independent security review before production use.

**Scope warning:** The Cloudflare site is a static project-information preview. It does not mean the authorization engine, PostgreSQL witness service, or consensus path is deployed as a hosted production backend.
