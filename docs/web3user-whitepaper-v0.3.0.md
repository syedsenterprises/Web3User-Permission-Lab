# Web3User Permission Lab
## Project White Paper, System Mindmap, Technology Stack & Deployment Roadmap
**Version 0.3.0 — Milestone 6.4 Validation Draft — 23 October 2026**

- **Repository**: `https://github.com/syedsenterprises/Web3User-Permission-Lab`
- **Branch**: `main`
- **Baseline Git Commit**: `f1bed7f51e6a3ccb024b17a86993faf07bc48349` (`fix: harden authorization lifecycle concurrency and governance`)
- **Parent Commit**: `763d3b8561c37c340cbdabd39615eece1e4fe8ed` (origin/main)
- **Planned Public Domain**: `web3user.tech`
- **Current Development Status**: M0–M6.3 Complete; Milestone 6.4 Locally Validated (Working Tree Verified at Commit `f1bed7f51e6a3ccb024b17a86993faf07bc48349`, Unpublished); M7–M9 Planned
- **Automated Test Suite**: 238 passing tests across 14 test files (`vitest run`); TypeScript static analysis clean (`npx tsc --noEmit`)

---

## Document Map & Status Guide

This document is a technical and project white paper detailing the implemented architecture, formal security model, technology stack, and future development roadmap for Web3User Permission Lab. It explicitly delineates what has been built and tested in code from planned future work and candidate options.

### Status Taxonomy
- **BUILT**: Implemented, integrated, and verified by automated tests in the current local repository working tree.
- **PLANNED**: Architected milestone scheduled for subsequent development phases.
- **OPTION**: Evaluated design pattern or technology candidate not yet adopted or configured.
- **NOT IN SCOPE**: Explicitly excluded from the initial prototype and MVP boundary.

> **Development-Stage Notice**: Web3User Permission Lab is an experimental prototype and has not undergone independent third-party security audits. Passing automated unit, integration, and recovery tests is an engineering baseline, not formal verification or proof of production security. The prototype does not custody digital assets, sign blockchain transactions, or submit transactions to live networks.

---

## 1. Executive Summary

Web3User Permission Lab is an off-chain transaction authorization and policy evaluation engine designed to make Web3 permissions explicit, testable, and auditable. Rather than forcing wallet users or autonomous agents to blindly approve opaque transaction payloads, the engine validates proposed blockchain actions against declarative, fine-grained policies before an action can proceed.

The initial implementation targets ERC-20 transfer actions (`transfer(address,uint256)`, selector `0xa9059cbb`). The engine enforces strict calldata layout validation (68 bytes), extracts transaction arguments from calldata rather than untrusted user assertions, checks allowlisted token target contracts and recipients, enforces per-action amount caps using lossless 256-bit integer arithmetic, and verifies time-bounded policy validity.

Beyond simple boolean evaluation, Milestone 6 provides an end-to-end cryptographic and transactional authorization lifecycle:
1. **Asymmetric Digital Signatures (Ed25519)**: Version 3 signed authorization artifacts bind transaction parameters and policy constraints to an authoritative issuer key using deterministic length-prefixed canonical serialization.
2. **Persistent Two-Phase Replay Protection**: Backed by SQLite in Write-Ahead Logging (WAL) mode, authorizations undergo an atomic state transition from `issued` to `consumed`. Unconsumed authorizations cannot be reused, and duplicate consumption attempts are strictly rejected.
3. **Transactional Monotonic Timekeeping**: A persisted system clock high-water mark enclosed in atomic `BEGIN IMMEDIATE;` write transactions detects and rejects wall-clock rollbacks and NTP regressions.
4. **Non-Spinning Contention Management**: Concurrent write contention is resolved through bounded retry budgets and synchronous exponential backoff via `Atomics.wait`, eliminating CPU starvation.
5. **Safe TTL Arithmetic**: Subtraction-first validity calculations eliminate integer overflow risks when processing expiration intervals up to `Number.MAX_SAFE_INTEGER`.
6. **Process-Crash Recovery**: Atomicity and crash rollback invariants are verified through multi-process crash injection tests.

---

## 2. Vision, Problem Statement, and Intended Users

### The Problem
Interacting with decentralized applications today frequently requires users to sign hexadecimal calldata and broad token allowances without clear insight into what the transaction actually executes. Users face severe security challenges:
- **Calldata Blindness**: Hexadecimal payloads obscure recipient addresses and transferred amounts.
- **Unlimited Approvals**: Broad ERC-20 approvals expose wallets to catastrophic draining if a spender contract is exploited or malicious.
- **Phishing and Address Poisoning**: Deceptive look-alike addresses trick users into authorizing unauthorized transfers.
- **Time-of-Check to Time-of-Use (TOCTOU) Exploits**: Transaction parameters can be altered between user review and final broadcast.
- **Lack of Persistent Replay Controls**: Authorization decisions held only in memory are forgotten on restart, exposing systems to replay attacks.

### Proposed Vision
Web3User Permission Lab establishes an off-chain verification layer where every sensitive action must satisfy explicit, verifiable rules. Policies are machine-readable, deterministic, and auditable. Authorization decisions are issued as tamper-evident, time-bounded cryptographic capabilities that can be verified and persistently retired upon single use.

### Intended Users and Integrators
1. **Smart Contract Wallets & Account Abstraction (ERC-4337)**: Bundlers and paymasters validating user operations against spending policies.
2. **Autonomous Agent & AI Execution Frameworks**: Autonomous agents executing on-chain actions within strictly bounded financial and temporal constraints.
3. **DeFi Treasury & Multi-Sig Operations**: Automated guardians enforcing dual-control spending rules before multi-sig execution.
4. **Security Researchers & Protocol Engineers**: A reference implementation for studying formal authorization boundaries, monotonic timekeeping, and crash recovery.

---

## 3. Product Scope: Implemented Reality vs. Future Roadmap

| Capability / Component | Status | Implementation Details |
| :--- | :--- | :--- |
| **ERC-20 Calldata Evaluator** | **BUILT** | Strict 68-byte validation, ABI padding verification, BigInt amount decoding. |
| **Per-Action Spending Caps** | **BUILT** | Exact ceiling enforcement against decoded calldata amounts. |
| **Address Allowlists** | **BUILT** | Case-insensitive token target and recipient verification. |
| **Canonical Binding Digest** | **BUILT** | SHA-256 hash over length-prefixed representation of request and policy. |
| **Ed25519 Artifact Signing (V3)** | **BUILT** | Asymmetric Ed25519 signing (`node:crypto`) with length-prefixed canonical encoding. |
| **SQLite WAL Persistent Store** | **BUILT** | Two-phase state machine (`issued` → `consumed`), version discriminator column. |
| **Persistent Monotonic Clock** | **BUILT** | Transaction-locked high-water mark with rollback detection. |
| **Contention Retries & Backoff** | **BUILT** | 5-attempt / 250ms budget, non-spinning backoff via `Atomics.wait`. |
| **Safe TTL Arithmetic** | **BUILT** | Subtraction-first safe-integer calculations up to `Number.MAX_SAFE_INTEGER`. |
| **Process-Crash Recovery** | **BUILT** | Verified WAL journal rollback on unexpected process termination. |
| **Cumulative Time-Window Budgets**| **PLANNED** | Multi-transaction aggregate limits (daily, weekly, monthly budgets). |
| **Arbitrary Function Decoders** | **PLANNED** | Support for Uniswap, Aave, and arbitrary complex smart contract calldata. |
| **On-Chain Validator Contracts** | **PLANNED** | Solidity verification contracts validating Ed25519/Secp256k1 authorization proofs. |
| **Production Wallet RPC Proxy** | **PLANNED** | Transparent EIP-1193 / JSON-RPC middleware proxy intercepting transactions. |
| **Independent Security Audit** | **PLANNED** | Formal external review by reputable smart contract security auditing firms. |

---

## 4. Core Policy Evaluator Engine

The core evaluator (`src/policy.ts`) is a zero-dependency, deterministic TypeScript library. It receives a policy configuration, a proposed transaction action, and a trusted timestamp, returning one of three explicit decisions:

- **`ALLOW`**: The action strictly complies with all allowlists, boundaries, and timestamps.
- **`DENY`**: An explicit policy restriction was violated (e.g., recipient not allowlisted, amount exceeded, policy revoked).
- **`UNKNOWN`**: Input data was missing, malformed, unsupported, or inconsistent.

### Evaluation Workflow
1. **Input Structural Validation**: Confirms all required fields exist and conform to schema types.
2. **Trusted Timestamp Invariants**: Verifies `context.nowSeconds` is a non-negative safe integer. Caller must provide authoritative time; timestamps are never extracted from untrusted transaction inputs.
3. **Policy Validity & Revocation**: Confirms `nowSeconds >= policy.validFrom` and `nowSeconds < policy.expiresAt`. If `policy.revoked === true`, evaluation fails closed immediately with `DENY`.
4. **Function Selector Dispatch**: Validates the 4-byte selector against `0xa9059cbb`. Any alternative selector returns `UNKNOWN`.
5. **Calldata Length & ABI Padding**: Requires exactly 68 bytes (4-byte selector + 32-byte recipient word + 32-byte amount word). Address words must contain 12 leading zero bytes.
6. **Calldata Extraction**: Extracts recipient address and amount directly from the validated binary words.
7. **Cross-Field Reconciliation**: If an unauthoritative compatibility amount field is provided in the action, it must match the decoded calldata amount exactly.
8. **Policy Rule Enforcement**:
   - `action.target.toLowerCase() === policy.allowedTarget.toLowerCase()`
   - `decodedRecipient.toLowerCase() === policy.allowedRecipient.toLowerCase()`
   - `decodedAmount <= BigInt(policy.maxAmount)`

---

## 5. Threat Model and Security Architecture

The Web3User security architecture is built on defensive, fail-closed principles:

### Handled Threats
- **Calldata Tampering**: Validating extracted values against policy rules prevents bypasses where user-asserted metadata contradicts the executed bytecode.
- **Off-by-One Expiry Attacks**: Policies and authorizations enforce strict half-open time boundaries ($[\text{validFrom}, \text{expiresAt})$). An authorization checked at the exact expiration second is rejected.
- **Integer Precision Loss**: JavaScript 64-bit floats lose precision beyond $2^{53}-1$. Calldata amounts are handled exclusively with `BigInt`, while timestamps and TTLs use checked safe integers (`Number.isSafeInteger`).
- **Signature Forgery**: Ed25519 digital signatures guarantee that only recognized private keys in the active key registry can authorize transactions.
- **Double Consumption / Replay**: Persistent SQLite primary key constraints and atomic `UPDATE ... WHERE state = 'issued'` queries ensure an authorization can only transition to `consumed` once.
- **Clock Rollback & NTP Glitches**: Persistent high-water clock tracking prevents backward time manipulation from resurrecting expired permissions.
- **Transient Contention Failure**: Bounded retry loops with exponential backoff prevent false-negative rejections during concurrent database access.

### Critical Cryptographic Distinction: Off-Chain vs. On-Chain Signing
It is essential to distinguish the cryptographic operations performed by Web3User Permission Lab from Ethereum transaction execution:
- **Authorization Artifact Signing (Off-Chain)**: Web3User uses Ed25519 keys (`node:crypto`) to attest that a transaction was reviewed and permitted by policy.
- **Ethereum Transaction Signing (On-Chain/Wallet)**: The user or smart wallet retains custody of their Secp256k1 private key. Web3User does NOT hold user private keys, sign raw EVM transactions, or broadcast transactions.
- **Enforcement Layer Responsibility**: An integrating wallet or node must verify the signed authorization artifact before signing the blockchain transaction.

---

## 6. Versioned Authorization Artifacts & Cryptographic Binding

To prevent time-of-check to time-of-use (TOCTOU) substitution, evaluation decisions are bound into tamper-evident artifacts.

```
+-----------------------------------------------------------------------------------------+
|                                    TRANSACTION REQUEST                                  |
|   (chainId, sender, target, calldata, value)                                            |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                                  AUTHORITATIVE POLICY                                   |
|   (policyId, revision, allowedTarget, allowedRecipient, maxAmount, validFrom, expiresAt)|
+-----------------------------------------------------------------------------------------+
                                             |
                                             v
+-----------------------------------------------------------------------------------------+
|                 LENGTH-PREFIXED DETERMINISTIC SERIALIZATION                             |
|                 Header: web3user-bound-authorization-v1\n                               |
|                 Format: name:length:value\n                                             |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v  SHA-256
+-----------------------------------------------------------------------------------------+
|                                  BINDING DIGEST                                         |
|                 sha256:<64 lowercase hexadecimal characters>                            |
+-----------------------------------------------------------------------------------------+
                                             |
                                             v  + Issuer Key, Timestamps, Policy Revision
+-----------------------------------------------------------------------------------------+
|                     CANONICAL SIGNED PAYLOAD V3 (Ed25519)                               |
|                 Header: web3user-signed-authorization-v3\n                              |
|                 Format: name:length:value\n                                             |
+-----------------------------------------------------------------------------------------+
```

### Artifact Schema Evolution

#### V1 Unkeyed Binding Artifact (Milestone 5B)
Bound normalized transaction parameters and policy constraints into a canonical SHA-256 digest. While establishing strict data integrity, V1 did not authenticate the identity of the issuer.

#### V2 Signed Authorization Artifact (Milestone 6.1)
Introduced asymmetric Ed25519 digital signatures, binding `version = 2`, `authorizationId`, `keyId`, and `bindingDigest`.

#### V3 Signed Authorization Artifact (Milestone 6.2–6.4)
Comprehensive authorization capability binding:
- `version`: literal integer `3`.
- `authorizationId`: unique identifier.
- `keyId`: identifier of signing key in key registry.
- `issuedAtSeconds`: creation Unix timestamp.
- `expiresAtSeconds`: explicit expiration timestamp.
- `policyId`: identifier of evaluated policy.
- `policyRevision`: monotonically incremented policy revision number.
- `bindingDigest`: SHA-256 digest over transaction and policy parameters.
- `signature`: 128-character hex Ed25519 signature.

---

## 7. Persistent Replay Protection, SQLite WAL Storage, and Concurrency Governance

Authorization state is maintained in SQLite with Write-Ahead Logging (`PRAGMA journal_mode = WAL;`) and immediate transaction isolation (`BEGIN IMMEDIATE;`).

### Additive Schema Architecture
- `consumed_authorization_ids`:
  - `authorization_id TEXT PRIMARY KEY`: Unique identifier.
  - `binding_digest TEXT`: Cryptographic hash of bound parameters.
  - `state TEXT NOT NULL CHECK (state IN ('issued', 'consumed'))`: Two-phase lifecycle state.
  - `consumed_at TEXT`: Timestamp recorded at consumption.
  - `artifact_version INTEGER NOT NULL DEFAULT 1`: Cross-version discriminator column.
- `issuer_keys`: In-database key registry tracking `key_id`, `public_key_pem`, `status` (`active`, `retired`, `revoked`), and validity timestamps.
- `policies` & `policy_revisions`: Authoritative policy store enforcing monotonic revisions (`revision > current_revision`).
- `system_clock_state`: Persisted monotonic clock high-water tracking.

### Two-Phase Replay Prevention Invariant
```sql
UPDATE consumed_authorization_ids
SET state = 'consumed', consumed_at = CURRENT_TIMESTAMP
WHERE authorization_id = ?
  AND binding_digest = ?
  AND state = 'issued'
  AND artifact_version = 3;
```
If an authorization ID does not exist, has already been consumed, or presents an incorrect binding digest or artifact version, exactly 0 rows are updated. The operation aborts and returns `DENY`.

---

## 8. Transactional Monotonic Clock, Bounded Retries, and Process-Crash Recovery

### Monotonic Clock High-Water State
Distributed systems and multi-process workers are vulnerable to system clock skews and NTP backwards adjustments. The store records the highest timestamp observed in `system_clock_state`:
- Within an immediate transaction, the store verifies:
  $$\text{trustedNowSeconds} \ge \text{highWaterSeconds}$$
- If the clock has regressed, the transaction aborts immediately with an error.
- When valid, the high-water mark advances atomically with the authorization state.

### Bounded Retries with Non-Spinning Backoff
Concurrent SQLite write operations under WAL mode can encounter transient `SQLITE_BUSY` errors when multiple processes attempt `BEGIN IMMEDIATE;`.
- Operations employ a bounded retry loop (5 attempts, 250ms total budget).
- Delays use exponential backoff with pseudo-random jitter.
- Delays are executed synchronously via `Atomics.wait` on a `SharedArrayBuffer` (`sleepSync`), yielding the CPU thread without busy-wait spinning.
- If contention exceeds the retry budget, the transaction fails closed, preventing lock exhaustion and livelocks.

### Process-Crash Recovery vs. Physical Power-Loss Durability
Milestone 6.4 includes automated test coverage verifying database behavior following abrupt worker termination:
- **Crash Recovery Invariant**: When child processes are abruptly terminated (`SIGKILL` or `process.exit(1)`) midway through uncommitted write transactions, reopening the database triggers automatic SQLite WAL recovery. All uncommitted writes and intermediate clock updates are rolled back cleanly, leaving zero orphaned records.
- **Important Qualification**: This test verifies **process-crash recovery**. It does **not** claim or prove **physical power-loss durability**, which depends on underlying operating system kernel caches, storage controller write buffers, and physical drive flush policies.

---

## 9. Safe TTL Arithmetic and Integer Overflow Hardening

In JavaScript runtimes, integer arithmetic exceeding `Number.MAX_SAFE_INTEGER` ($2^{53}-1 = 9,007,199,254,740,991$) causes precision loss and incorrect comparisons.

### Subtraction-First Expiration Calculation
When calculating an authorization's expiration from `effectiveNowSeconds` and `ttlSeconds`:
1. Directly computing `effectiveNowSeconds + ttlSeconds` overflows if `ttlSeconds` is near `Number.MAX_SAFE_INTEGER`.
2. The hardened issuance algorithm calculates the ceiling deadline (`maxAllowedExpiresAt`) as the minimum of:
   - `authoritativePolicy.expiresAt` (if defined)
   - `keyRow.expires_at_seconds` (if defined)
   - `Number.MAX_SAFE_INTEGER`
3. If `maxAllowedExpiresAt <= effectiveNowSeconds`, the validity interval is empty and issuance is denied.
4. The remaining safe duration is computed:
   $$\text{remainingValidSeconds} = \text{maxAllowedExpiresAt} - \text{effectiveNowSeconds}$$
5. If $\text{ttlSeconds} \ge \text{remainingValidSeconds}$, expiration is clamped to $\text{maxAllowedExpiresAt}$.
6. Otherwise, $\text{effectiveExpiresAt} = \text{effectiveNowSeconds} + \text{ttlSeconds}$, which is mathematically guaranteed not to overflow.
7. Strict validation confirms `Number.isSafeInteger(effectiveExpiresAt)` and $\text{effectiveExpiresAt} > \text{effectiveNowSeconds}$.

---

## 10. System Mindmap (Text Form)

```
WEB3USER PERMISSION LAB (Milestone 6.4)
├── 1. PRODUCT VISION & SCOPE
│   ├── Goal: Understandable, testable, auditable off-chain permissions
│   ├── Supported Action: ERC-20 transfer(address,uint256) [selector: 0xa9059cbb]
│   ├── Decisions: ALLOW (permitted), DENY (violated), UNKNOWN (malformed/unsupported)
│   └── Exclusions: Zero token launch, zero custody, zero on-chain deployment
├── 2. CORE EVALUATION ENGINE [BUILT]
│   ├── Language: TypeScript (strict mode, zero runtime dependencies)
│   ├── Calldata Parser: Exact 68-byte validation, ABI padding verification
│   ├── Amount Decoder: uint256 BigInt decoding, lossless limit checks
│   └── Allowlisting: Case-insensitive target token and recipient checks
├── 3. CRYPTOGRAPHIC CAPABILITIES [BUILT]
│   ├── Binding Digest (V1): SHA-256 over length-prefixed canonical encoding
│   ├── Signed Artifacts (V2/V3): Ed25519 digital signatures (node:crypto)
│   ├── Canonical Serialization: name:length:value\n format (injection-proof)
│   └── Cryptographic Boundary: Evaluator signs artifacts; wallet signs EVM transactions
├── 4. PERSISTENT STORAGE & GOVERNANCE [BUILT]
│   ├── Engine: SQLite (node:sqlite, WAL mode, busy_timeout = 5000)
│   ├── Two-Phase State Model: issued -> consumed with version discriminator
│   ├── Key Registry: Active, retired, and revoked lifecycle management
│   ├── Policy Store: Monotonically incremented policy revisions
│   └── Rollback Detection: Transaction-locked persistent monotonic clock high-water
├── 5. CONCURRENCY & RESILIENCE [BUILT]
│   ├── Contention Retries: Bounded budget (5 retries / 250ms), exponential jitter
│   ├── Non-Spinning Sleep: Synchronous Atomics.wait on SharedArrayBuffer
│   ├── Safe TTL Arithmetic: Subtraction-first calculation, zero integer overflow
│   ├── Race Testing: 4-process IPC rendezvous barrier verifying single-use consumption
│   └── Process Crash Recovery: Verified SQLite WAL rollback on child SIGKILL / exit(1)
├── 6. VERIFICATION SUITE [BUILT]
│   ├── Framework: Vitest + TypeScript (npx tsc --noEmit)
│   ├── Test Volume: 238 passing tests across 14 test files
│   ├── Replay Demo: Verified isolated two-step ALLOW -> DENY runner
│   └── Baseline Commit: f1bed7f51e6a3ccb024b17a86993faf07bc48349
└── 7. ROADMAP & DEPLOYMENT
    ├── Completed: M0–M3 (Foundation & Evaluator), M4–M5 (Binding & Persistence),
    │              M6.1–M6.4 (Signatures, Governance, Retries, Crash Recovery)
    ├── Planned: M7 (Budgets), M8 (Adversarial Testing), M9 (Audits & Public Demo)
    └── Hosting: Static preview bundle prepared; custom domain web3user.tech deferred
```

---

## 11. Technology Stack: Tools, Libraries, and Roles

| Tool / Technology | Role in Project | Current Status |
| :--- | :--- | :--- |
| **TypeScript 5.7+** | Core language for policy evaluation, cryptography, and storage logic. | **IN USE** (strict type safety) |
| **Node.js (v26.11+)** | Runtime platform for execution, cryptography (`node:crypto`), and storage. | **IN USE** (runtime engine) |
| **node:sqlite** | Native SQLite binding for WAL persistence and transactional locking. | **IN USE** (embedded storage) |
| **node:crypto** | Ed25519 digital signing, key generation, and SHA-256 hashing. | **IN USE** (cryptographic engine) |
| **Vitest 5.0+** | Automated test runner for unit, integration, concurrency, and crash tests. | **IN USE** (238 passing tests) |
| **tsc (`npx tsc`)** | Static type verification compiler (`--noEmit`). | **IN USE** (zero compiler errors) |
| **npm + lockfile** | Deterministic package management and security vulnerability audits. | **IN USE** (clean audit status) |
| **Git / GitHub** | Local and remote version control (`origin/main`, private repository). | **IN USE** (HEAD: `f1bed7f`) |
| **Static Preview** | Standalone HTML5/CSS landing page bundle (`website-preview/`). | **IN USE** (local development preview) |
| **Custom Domain** | `web3user.tech` planned public identity. | **PLANNED** (DNS unconfigured) |

---

## 12. Static Website Preview and Domain Deployment Strategy

The project includes a self-contained static website bundle (`website-preview/`):
- `website-preview/index.html`: Responsive, dark-themed landing page documenting project status, test metrics, implemented features, and roadmap.
- `website-preview/assets/`: Distribution directory containing downloadable white papers and mind maps.

### Domain Activation Policy
The project adheres to a strict **Zero-Cost and Approval-First** deployment policy:
1. **Local Preview First**: The website preview is reviewed locally without public DNS exposure.
2. **Provider Preview (Optional)**: If approved by the project owner, the static site may be deployed to a free static provider preview URL (e.g., Cloudflare Pages or GitHub Pages).
3. **Custom Domain Deferred**: The custom domain `web3user.tech` remains unconnected until an official public preview milestone is authorized. No DNS records are modified without explicit review and approval.

---

## 13. Development Roadmap (M0–M6.4 Implemented, M7–M9 Planned)

```
[M0-M6.3: Complete]  -->  [M6.4: Locally Validated (Unpublished)]  -->  [M7-M9: Planned Future Work]
  209 Tests Passing                238 Tests Passing (Working Tree)              Planned Future Work
```

### Milestone History & Validation Status
- **M0–M3: Foundation, Evaluator & Baseline Tests (Complete)**: Initial project structure, ERC-20 transfer evaluator, basic unit tests, and repository baseline (34 tests).
- **M4–M5: Exact Transaction Binding & Persistence (Complete)**: Length-prefixed canonical encoding, SHA-256 binding digest, SQLite two-phase store (`issued` → `consumed`).
- **M6.1–M6.2: Asymmetric Signatures & In-Database Governance (Complete)**: Ed25519 V2/V3 signing, in-database key registry (`active`, `retired`, `revoked`), and monotonic policy revisions.
- **M6.3: Concurrency Hardening & Monotonic Clock (Complete)**: Transaction-locked monotonic clock high-water state, non-spinning contention backoff via `Atomics.wait`, and fail-closed legacy controls (209 tests).
- **M6.4: Post-Commit Security & Crash-Recovery Validation (Locally Validated · Unpublished)**: Subtraction-first safe TTL arithmetic, multi-process IPC rendezvous barriers, process-crash recovery verification, and comprehensive test suite expansion (238 tests). Locally validated in working tree on top of commit `f1bed7f51e6a3ccb024b17a86993faf07bc48349`.

### Planned Future Milestones
- **M7: Cumulative Spending Budgets & Time Windows**: Rolling multi-transaction budgets (e.g., maximum \$500 per 24-hour window), concurrency-safe expenditure reservations, and automated budget resets.
- **M8: Adversarial Corpus, Fuzzing & Property Testing**: Property-based fuzzing of ABI decoders, malformed payload corpora, and formal state-machine invariant proofs.
- **M9: Public Demo Readiness & Independent Security Review**: Formal third-party security audits, public demonstration testnet integration, responsible disclosure program, and public repository release.

---

## 14. Governance, Privacy, Secret Hygiene, and Release Policy

1. **No Real-Money Custody**: The prototype must never be deployed with custody of real funds, live mainnet private keys, or unmonitored production transaction pipelines.
2. **Strict Secret Hygiene**: Zero private keys, seed phrases, or sensitive credentials may be committed to source control. Ephemeral test keys are generated dynamically during test runs.
3. **Truth in Advertising**: Passing internal automated tests must never be misrepresented as an independent security audit or formal verification.
4. **Reproducible Releases**: Every white paper and documentation release must cite its exact Git commit hash, test count, and verification commands.
5. **Fail-Closed Default**: In all ambiguous, malformed, or error states, the system must fail closed, returning `DENY` or `UNKNOWN` and preventing unauthorized operations.

---

## 15. Key Technical Risks and Architectural Decisions

1. **Host-Level Storage Durability**: While process-crash recovery is verified via SQLite WAL journaling, physical power loss durability depends on OS-level `fsync` behavior. Production deployments requiring hard guarantees must audit filesystem mount options and disk write-caching policies.
2. **Clock Source Integrity**: The library relies on caller-supplied `trustedNowSeconds`. While backward jumps are rejected by the monotonic clock, forward clock drift can prematurely expire authorizations. Production callers must synchronize clocks via authenticated NTP/chrony daemons.
3. **Adversarial Interception of Bearer Artifacts**: Unconsumed signed authorization artifacts are bearer capabilities. Systems must protect artifacts in transit using authenticated, encrypted transport (e.g., TLS 1.3).
4. **Single-Token Scope**: The evaluator currently inspects only standard ERC-20 `transfer` calls. Fee-on-transfer tokens, rebasing tokens, and non-standard ERC-20 implementations require specialized policy modeling.

---

## 16. Summary & Next Steps

Web3User Permission Lab has advanced from an initial proof-of-concept evaluator into a robust, cryptographically sound authorization lifecycle engine. With Milestone 6.4 locally validated in the working tree, the repository features:
- Complete Ed25519 V3 signed authorization capabilities.
- Persistent two-phase single-use replay protection.
- Transaction-locked monotonic clock rollback protection.
- Bounded contention retry logic with non-spinning backoff.
- Verified process-crash recovery and safe TTL arithmetic.
- 238 passing automated tests and clean TypeScript compilation.

The next engineering phase will focus on Milestone 7: designing cumulative spending budgets across rolling time windows and formalizing wallet integration interfaces.

---

## Appendix A — Reproducibility Commands & Test Harness

To reproduce the verification results reported in this white paper:

```bash
# Navigate to repository root
cd /path/to/Web3User

# Execute full automated test suite (332 tests across 17 test suites)
npm test

# Verify static TypeScript type checking
npx tsc --noEmit

# Execute persistent replay demonstration harness
npm run demo:persistent-replay -- --verify

# Inspect working tree status and baseline commit
git status
git log -1 --oneline
```

---

## Appendix B — Known Repository Snapshot & Invariants

- **Baseline Commit**: `f1bed7f51e6a3ccb024b17a86993faf07bc48349`
- **Tracked Implementation Files**:
  - `src/policy.ts`: Core ERC-20 policy evaluator.
  - `src/authorization-binding.ts`: Canonical length-prefixed encoding and SHA-256 binding digests.
  - `src/authorization-crypto.ts`: Ed25519 key generation, signing, and V2/V3 canonical payloads.
  - `src/authorization-lifecycle.ts`: Issuance, consumption, TTL arithmetic, and lifecycle management.
  - `src/authorization-store.ts`: SQLite two-phase persistent store and transaction management.
  - `src/clock.ts`: Clock interfaces and monotonic time providers.
  - `src/key-registry.ts`: Key governance definitions and interfaces.
  - `src/key-store.ts`: SQLite key registry persistence and validation.
  - `src/policy-store.ts`: Authoritative SQLite policy store and revision tracking.
  - `src/sqlite-transaction.ts`: Transaction-wrapped execution, retry loops, and non-spinning backoff.
  - `src/transaction-envelope.ts`: Request envelope normalization and validation.
- **Test Suite Files (14 files, 238 tests)**:
  - `test/authorization-boundaries.test.ts`
  - `test/authorization-lifecycle.test.ts`
  - `test/calldata-evaluator.test.ts`
  - `test/concurrency-governance.test.ts`
  - `test/crypto-signatures.test.ts`
  - `test/edge-cases.test.ts`
  - `test/fail-closed.test.ts`
  - `test/persistence-recovery.test.ts`
  - `test/policy-evaluator.test.ts`
  - `test/policy-store.test.ts`
  - `test/signed-authorization-v3.test.ts`
  - `test/sqlite-concurrency.test.ts`
  - `test/sqlite-store.test.ts`
  - `test/sqlite-transaction.test.ts`
