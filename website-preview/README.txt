Web3User Permission Lab — Cloudflare Static Information Preview
Status snapshot: 03 November 2026

This directory is the static public information site deployed through the Cloudflare Worker super-tree-7537 on web3user.tech and docs.web3user.tech. It is not the hosted authorization engine, PostgreSQL witness service, or production consensus path.

Current documents:
- assets/web3user-engineering-roadmap-2026-11-03.pdf
- assets/web3user-project-mindmap-2026-11-03.pdf
- Historical reference: assets/web3user-whitepaper-v0.3.0.pdf and assets/web3user-project-mindmap-v0.3.0.pdf

Current development branch: feature/m13-d-consensus
Development HEAD: 25bfe62fbb1542e2f8512f522f9c8e4892b4ad97
Public release tag: v0.1.0-rc.1 (historical; not the current development HEAD)

Latest accepted verification: Docker Compose Linux-compatible test run, 32 files / 655 tests passed. The 26 Windows real-etcd tests were excluded and require separate native validation. Phase 1-A source-protection commit 25bfe62 was pushed with exactly five approved files.

Production blockers remain: revocation freshness synchronization, receipt preimage compatibility, AWS KMS Witness Signer adapter, air-gapped backup-key ceremony, cross-store recovery validation, measured RPO/RTO, and independent security audit.

The Compose test network has no published PostgreSQL host port, but outbound network access remains enabled; it is not air-gapped. Do not describe this harness as production isolation.

No secrets, .tmp/ binaries/fixtures, or .demo-data/ SQLite files are part of this website bundle.