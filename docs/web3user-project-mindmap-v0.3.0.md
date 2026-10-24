# Web3User Permission Lab — Project Mindmap
## Built System Architecture vs. Planned Roadmap
**Version 0.3.0 — Milestone 6.4 Checkpoint (Locally Validated · Unpublished) — 23 October 2026**

- **Repository**: `https://github.com/syedsenterprises/Web3User-Permission-Lab`
- **Branch**: `main`
- **Baseline Git Commit**: `f1bed7f51e6a3ccb024b17a86993faf07bc48349`
- **Current Test Verification**: 238 passed (14 test files) · TypeScript typecheck clean
- **Planned Domain**: `web3user.tech` (DNS unconfigured, preview-first policy)
- **Status Summary**: M0–M6.3 Complete · Milestone 6.4 Locally Validated (Working Tree Verified, Unpublished) · M7–M9 Planned

---

```
WEB3USER PERMISSION LAB (Milestone 6.4)
│
├── 1. PRODUCT SCOPE & FOUNDATION
│   ├── Goal: Understandable, testable, auditable permissions for Web3 transactions
│   ├── Target Users: Wallets, account abstraction bundlers, dApps, autonomous AI agents
│   ├── Decision Triad:
│   │   ├── ALLOW: Action satisfies all allowlists, boundaries, and validity rules
│   │   ├── DENY: Explicit policy violation (unauthorized target/recipient, amount exceeded)
│   │   └── UNKNOWN: Missing, malformed, or unsupported transaction payload
│   └── Non-Goals / Hard Exclusions:
│       ├── Zero token launch / No speculative assets
│       ├── Zero real-money custody / No private key custody
│       └── Zero unverified mainnet deployment
│
├── 2. CORE EVALUATION ENGINE [BUILT]
│   ├── Source: src/policy.ts (deterministic TypeScript, zero external dependencies)
│   ├── Target Standard: ERC-20 transfer(address,uint256) [selector: 0xa9059cbb]
│   ├── Calldata Parser:
│   │   ├── Exact 68-byte validation (4-byte selector + two 32-byte words)
│   │   ├── Strict ABI padding check (12 leading zero bytes for addresses)
│   │   └── Direct calldata extraction for recipient and transfer amount
│   ├── Lossless Arithmetic: uint256 BigInt parsing; avoids 64-bit float precision loss
│   ├── Policy Rules:
│   │   ├── Allowed target token contract (case-insensitive)
│   │   ├── Allowed recipient address (case-insensitive)
│   │   ├── Per-action maximum amount limit
│   │   └── Policy time window [validFrom <= nowSeconds < expiresAt) & revocation
│   └── Engine Invariant: Evaluator outputs decisions; does NOT submit or block transactions
│
├── 3. CRYPTOGRAPHIC BINDING & SIGNING [BUILT]
│   ├── Binding Digest (V1):
│   │   ├── SHA-256 over canonical length-prefixed request & policy parameters
│   │   └── Eliminates TOCTOU parameter substitution between check and use
│   ├── Ed25519 Asymmetric Signatures (V2/V3):
│   │   ├── Engine: node:crypto Ed25519 digital signatures
│   │   ├── V3 Artifact: version (3), authId, keyId, issuedAt, expiresAt, policyId, revision, digest, sig
│   │   └── Canonical Encoding: web3user-signed-authorization-v3\n with name:length:value\n
│   ├── Cryptographic Boundary:
│   │   ├── Authorization Artifact Signing: Attests policy approval (off-chain)
│   │   └── Ethereum Transaction Signing: User/wallet signs EVM transaction (on-chain)
│   └── Verification Invariant: Signature verified BEFORE storage writes; forged artifacts fail closed
│
├── 4. PERSISTENT STORAGE & GOVERNANCE [BUILT]
│   ├── Database Engine: SQLite via node:sqlite (WAL mode, busy_timeout = 5000)
│   ├── Two-Phase Replay Protection:
│   │   ├── Table: consumed_authorization_ids
│   │   ├── Atomic state transition: issued -> consumed via atomic UPDATE
│   │   ├── Cross-Version Isolation: artifact_version column discriminates V1, V2, and V3
│   │   └── Single-Use Guarantee: Exactly one consumption succeeds; duplicates return DENY
│   ├── Key Registry Governance:
│   │   ├── Table: issuer_keys with statuses: active, retired, revoked
│   │   ├── Timestamp Ordering: validFromSeconds <= retiredAtSeconds <= revokedAtSeconds
│   │   └── Post-Retirement Verifiability: Retired keys verify pre-retirement issues; revoked keys block all
│   ├── Authoritative Policy Store:
│   │   ├── Tables: policies & policy_revisions
│   │   └── Monotonic Evolution: Incremental revisions (new_revision > current_revision)
│   └── Clock Rollback Detection:
│       ├── Table: system_clock_state with high_water_seconds
│       └── Invariant: nowSeconds >= highWaterSeconds checked inside BEGIN IMMEDIATE;
│
├── 5. CONCURRENCY, CONTENTION & CRASH RESILIENCE [BUILT]
│   ├── Bounded Contention Retries:
│   │   ├── Deterministic budget: 5 attempts / 250ms total budget
│   │   ├── Exponential backoff with pseudo-random jitter
│   │   └── Non-Spinning Sleep: Synchronous Atomics.wait on SharedArrayBuffer (sleepSync)
│   ├── Safe TTL Arithmetic:
│   │   ├── Subtraction-First Calculation: remaining = deadline - nowSeconds
│   │   ├── Clamping: If ttlSeconds >= remaining, clamp to deadline
│   │   └── Zero Overflow: Prevents intermediate addition exceeding Number.MAX_SAFE_INTEGER
│   ├── Concurrency Verification:
│   │   ├── 4-process IPC rendezvous barrier synchronizing simultaneous consumption attempts
│   │   └── Result: Exactly 1 ALLOW and 3 domain-level DENYs; zero SQLite busy leaks
│   └── Process-Crash Durability:
│       ├── Subprocess crash injection: Worker killed (SIGKILL / exit(1)) mid-transaction
│       ├── SQLite WAL Recovery: Automatic rollback of uncommitted writes upon reopen
│       └── Qualification: Verifies process-crash recovery; physical power loss durability depends on OS/hardware
│
├── 6. STATIC WEBSITE PREVIEW & HOSTING [BUILT]
│   ├── Bundle Directory: website-preview/
│   │   ├── Landing Page: index.html (responsive dark mode, verified stats, roadmap)
│   │   ├── Assets: web3user-whitepaper-v0.3.0.pdf & web3user-project-mindmap-v0.3.0.pdf
│   │   └── Documentation: README.txt explaining preview nature and deployment rules
│   ├── Hosting Candidates: Cloudflare Pages or GitHub Pages (static preview URL)
│   └── Domain Strategy: web3user.tech unconfigured; zero DNS modification until approval
│
├── 7. TOOLS & TESTING HARNESS [BUILT]
│   ├── TypeScript Compiler (tsc): Static type enforcement (npx tsc --noEmit)
│   ├── Vitest Test Runner: 238 tests passing across 14 test suites
│   ├── Isolated Replay Demo: npm run demo:persistent-replay -- --verify
│   ├── npm Audit: Clean dependency audit status
│   └── Git Version Control: Baseline commit f1bed7f51e6a3ccb024b17a86993faf07bc48349
│
└── 8. DEVELOPMENT ROADMAP
    ├── Milestone 0–3: Core Foundation, Evaluator & Baseline Tests [COMPLETE]
    ├── Milestone 4–5: Exact Transaction Binding & SQLite Persistence [COMPLETE]
    ├── Milestone 6.1–6.2: Ed25519 Signatures & In-Database Governance [COMPLETE]
    ├── Milestone 6.3: Concurrency Hardening & Monotonic Clock [COMPLETE]
    ├── Milestone 6.4: Security Hardening, TTL Safety & Crash Recovery [LOCALLY VALIDATED · UNPUBLISHED]
    ├── Milestone 7: Cumulative Spending Budgets Across Time Windows [PLANNED]
    ├── Milestone 8: Adversarial Corpus, Fuzzing & Property Testing [PLANNED]
    └── Milestone 9: Independent Security Review & Public Demo Readiness [PLANNED]
```

---

## Mindmap Legend & Architectural Notes

- **Milestone Status Hierarchy**: Milestones M0–M6.3 are complete in Git history; Milestone 6.4 is locally validated in the working tree subject to documented verification evidence (238 passing tests, clean TypeScript compilation, and verified crash recovery); Milestones M7–M9 are planned.
- **Working Tree vs. Committed HEAD**: Baseline commit `f1bed7f51e6a3ccb024b17a86993faf07bc48349` is the committed HEAD. Milestone 6.4 validation includes uncommitted and untracked changes in the local working tree (unpublished).
- **Built Prototype Scope**: Currently supports ERC-20 `transfer(address,uint256)` evaluation, V3 Ed25519 artifact signing, SQLite WAL persistence, monotonic timekeeping, bounded contention retries, safe TTL arithmetic, and process crash recovery.
- **Planned Work**: Multi-transaction cumulative spending budgets, arbitrary contract ABI decoders, on-chain Solidity validator contracts, and formal third-party audits.
- **Security & Durability Boundaries**: The evaluator issues off-chain signed authorization artifacts; it does not custody private keys, sign EVM transactions, or submit to blockchain networks. Process-crash recovery (SQLite WAL rollback) is verified, but physical power-loss durability is not claimed. Zero custom domain DNS activation in the current development preview.
- **Visual PDF vs. Markdown**: The companion PDF (`website-preview/assets/web3user-project-mindmap-v0.3.0.pdf`) provides a condensed two-page visual architecture map; the complete narrative legend is maintained here in Markdown.
