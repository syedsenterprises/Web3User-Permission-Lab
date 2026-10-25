# Web3User Permission Lab

Web3User Permission Lab is an early-stage **off-chain transaction authorization and policy-governance SDK** for Node.js (`>=22.13.0`) with zero third-party runtime dependencies.

Designed for transaction relayers, wallet middleware, and dApp backends, Web3User provides pre-execution governance:
1. Evaluates candidate transaction proposals against authoritative in-database governance policies.
2. Generates versioned, tamper-evident authorization artifacts using Ed25519 digital signatures.
3. Enforces persistent, single-use replay prevention backed by SQLite Write-Ahead Logging (WAL) and monotonic timekeeping.

> [!IMPORTANT]
> **Off-Chain Scope & Boundaries:**
> Web3User is an off-chain decision engine, not an on-chain smart contract, blockchain validator, or transaction broadcaster.
> - The SDK validates candidate transaction parameters against declarative rules and records persistent single-use reservations in local SQLite storage.
> - The SDK does **not** sign Ethereum transactions with wallet keys (secp256k1), submit RPC requests to nodes, manage mempool broadcasts, estimate gas, manage nonces, or custody assets.
> - An `ALLOW` decision indicates off-chain policy compliance; it does **not** constitute blockchain execution or funds movement. The integrating relayer or application remains responsible for separate wallet-signing and RPC broadcast.

## Status

Development-stage preview and release candidate (`v0.1.0-rc.1`). This software is a local-first reference implementation intended for evaluation, integration testing, and research. It has not undergone an independent external security audit and makes no claim of formal verification or production readiness.

## Requirements
- Node.js 22.13.0 or later. The persistent SQLite store uses the built-in `node:sqlite` module, which was added in Node.js 22.5.0 and is available without an experimental flag starting in 22.13.0.
- npm

## Run
```bash
npm install
npm test
npx tsx examples/basic-authorization.ts
npm run demo:persistent-replay
```

## Web3User Engine SDK Quickstart

The SDK provides an off-chain authorization and policy governance engine backed by SQLite persistence with WAL journaling, cryptographic key management, and atomic single-use replay prevention.

### Local Installation

Build and package the SDK locally into a `.tgz` tarball without publishing to a remote registry:

```bash
# In the Web3User repository:
npm run build
npm pack

# In your consumer project:
npm install /path/to/web3user-permission-lab-0.1.0-rc.1.tgz
```

### Minimal Example

```typescript
import { Web3UserEngine, type DemoPolicy, type TransactionRequest } from "web3user-permission-lab";

// 1. Open the engine
const engine = Web3UserEngine.open({
  databasePath: "./data/authorization.sqlite",
  durability: {
    synchronous: "FULL",  // Default: fsync commits for OS crash safety
    busyTimeoutMs: 5000,  // Bounded retry under write lock contention
  },
});

// 2. Register an Ed25519 issuer key
const keypair = engine.keys.generate();
engine.keys.register({
  keyId: "issuer-01",
  publicKey: keypair.publicKey,
  status: "active",
});

// 3. Register a policy
const policy: DemoPolicy = {
  version: 1,
  policyId: "transfer-limit-policy",
  allowedTarget: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  allowedRecipient: "0x2222222222222222222222222222222222222222",
  allowedSelector: "0xa9059cbb",
  maxAmount: "1000000000",
  validFrom: 0,
  expiresAt: 2_000_000_000,
  revoked: false,
};
engine.policies.register(policy);

// 4. Issue a V3 signed authorization artifact
const request: TransactionRequest = {
  chainId: "1",
  sender: "0x1111111111111111111111111111111111111111",
  target: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  calldata: "0xa9059cbb" + "22".repeat(20).padStart(64, "0") + (500n).toString(16).padStart(64, "0"),
  value: "0",
};

const issueResult = engine.issue({
  authorizationId: "auth-001",
  policyId: "transfer-limit-policy",
  request,
  signer: { keyId: "issuer-01", privateKey: keypair.privateKey },
  ttlSeconds: 300,
});

if (issueResult.decision === "ALLOW") {
  // 5. Relayer / Consumer consumes the artifact atomically before execution
  const consumeResult = engine.consume({
    artifact: issueResult.artifact,
    request,
  });

  if (consumeResult.decision === "ALLOW") {
    // Note: ALLOW confirms policy compliance and marks the authorization consumed
    // in SQLite. The external caller / relayer remains responsible for signing the
    // EVM transaction with an Ethereum wallet key (secp256k1) and broadcasting to an RPC node.
    console.log("Authorization granted off-chain. Ready for wallet signing and RPC broadcast.");
  }

  // 6. Any duplicate consumption attempt is strictly denied
  const replayResult = engine.consume({
    artifact: issueResult.artifact,
    request,
  });
  console.log(replayResult.decision); // "DENY" (Replay prevented)
}

// 7. Clean teardown
engine.close();
```

### Decision Semantics

The engine strictly returns one of three decisions:
- **`ALLOW`**: The transaction request satisfies authoritative policy rules, signing key validity intervals, and timestamp guardrails. A persistent single-use reservation was recorded atomically in SQLite. This represents an off-chain authorization outcome, not an on-chain execution or transaction broadcast.
- **`DENY`**: The request violates policy bounds (e.g. transfer limit exceeded, disallowed target/selector), references a revoked/retired key or policy, has expired, or has already been consumed (replay attack).
- **`UNKNOWN`**: The candidate calldata or request structure is malformed or cannot be safely parsed into a valid transaction envelope.

### Typed Operational Errors vs. Policy Denials

- **Policy Denials are normal business outcomes**: Returned as structured objects `{ decision: "DENY", reasons: string[] }`. They do not throw exceptions and do not corrupt engine health.
- **Operational Failures throw typed `Web3UserError` subclasses**:
  - `ValidationError`: Invalid parameter types, blank IDs, or strings exceeding maximum length limits (128 chars).
  - `EngineClosedError`: Invoking operations on an engine after `engine.close()` has been called.
  - `ContentionError`: SQLite write lock acquisition failed after exhausting the contention retry budget.
  - `ClockGuardError`: Clock rollback, forward drift exceeding safety bounds, or startup forward gap violation.
  - `StoreTaintedError`: The database connection was quarantined due to an uncertain `COMMIT;` outcome or unrecoverable disk error. **Never automatically retry an operation when a store is tainted.**

### SQLite Durability, Checkpointing & Storage Boundaries

- **Local Storage Requirement**: SQLite WAL mode requires shared memory (`-shm`) and POSIX byte-range file locking. Network filesystems (such as NFS, SMB/CIFS, AWS EFS, or Azure Files) do not reliably implement these primitives and can cause silent corruption, locking deadlocks, or `SQLITE_BUSY` errors. The database must reside on direct, locally attached block storage (e.g. local NVMe/SSD or dedicated cloud block storage like AWS EBS / GCP Persistent Disk mounted locally).
- **WAL & Synchronous FULL**: Every owned connection configures `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = FULL;` by default.
- **Checkpointing & WAL Management**:
  - The SDK exposes `engine.storage.checkpoint(mode?: CheckpointMode): CheckpointResult`.
  - Supported modes: `"PASSIVE"` (default), `"FULL"`, `"RESTART"`, and `"TRUNCATE"`.
  - Return structure: `{ busy: boolean, logFrames: number, checkpointedFrames: number }`.
  - Checkpointing transfers write-ahead log frames back into the main database file.
  - Active or long-running read transactions hold shared locks on earlier WAL frames, preventing them from being checkpointed or truncated, which causes `result.busy` to be `true`.
  - **Operational practice**: Avoid calling `checkpoint("TRUNCATE")` unconditionally on latency-sensitive request paths. Run checkpointing as a periodic background maintenance task or during low-concurrency intervals, and always inspect `result.busy` to verify whether the log was fully truncated.
- **Durability Model & Hardware Recommendations**:
  1. *Process Crash*: Protected by WAL atomic commits and automatic rollback upon database reopen.
  2. *OS Crash / Kernel Panic*: Protected by `synchronous = FULL` issuing OS-level flush requests (`fsync` / `FlushFileBuffers`) on every commit.
  3. *Power Loss Durability*: Disk controllers with volatile write caches may acknowledge writes before data is permanently committed to non-volatile NAND cells. For mission-critical deployments requiring physical power-loss durability, enterprise host storage controllers with hardware Power Loss Protection (PLP) capacitors are recommended.

### Security Boundary & Private Key Hygiene

- **Off-Chain Scope**: Web3User is an off-chain decision engine. It does not sign Ethereum transactions, connect to RPC nodes, or broadcast to mempools.
- **Dual-Key Architecture (Issuer Ed25519 vs. Wallet secp256k1)**:
  - *Issuer Keys (Ed25519)*: Managed within the SDK (`SQLiteKeyStore`) to sign and verify off-chain V3 authorization artifacts.
  - *Wallet Keys (secp256k1)*: Ethereum private keys used on-chain to sign EVM transactions. The Web3User SDK never handles, stores, or accesses wallet private keys.
- **Private Key Safety**: Never hardcode private keys in source code. Load private keys from secure environment variables, KMS, or HSMs. The SDK never logs, serializes, or echoes private key material in error messages.
- **NTP Time Synchronization Target**: To minimize clock-rollback detections across multi-process workers sharing a database, host servers should synchronize via NTP (e.g., `chrony` or `systemd-timesyncd`). Maintaining host clock drift within an operational target of ~100ms is recommended.
- **Privileged Store Access**: `engine.getStore()` is provided strictly for administrative maintenance and diagnostics. Executing raw SQL directly on the underlying connection bypasses engine validations and ClockGuard safeguards.

## Persistent replay demonstration

The demo demonstrates persistent replay protection using bound authorization artifacts and an additive two-phase (`issued` → `consumed`) state model in SQLite. It uses a fixed local policy, transfer request, trusted demonstration time, and authorization ID (`bound-replay-demo-authorization-001`).

- **First run**: Issues the bound authorization artifact (inserting a record in state `issued` with canonical SHA-256 binding digest), then revalidates and atomically consumes the artifact (transitioning state to `consumed`). Prints `Decision: ALLOW`.
- **Subsequent runs**: Reopens the persistent database, reconstructs the bound artifact, and attempts to consume it again. Because the database record is already in state `consumed`, the consumption fails closed and prints `Decision: DENY` with reason `Bound transaction authorization is unknown, consumed, or mismatched.`. A denial is the expected successful replay-protection result.
- **Verification mode**: Run `npm run demo:persistent-replay -- --verify` to run an automated, end-to-end verification against an isolated temporary database, demonstrating both fresh issuance/consumption and replay rejection across database reopen.

The demo database is stored at `.demo-data/bound-authorization-replay.sqlite` in the repository. It is separate from application data and is ignored by Git. The legacy demo database (`.demo-data/authorization-replay.sqlite`) is preserved. The demo never removes or resets databases automatically.

This is a local authorization demonstration only. An `ALLOW` result does not mean a transaction was signed, submitted, or executed. The demo does not connect to a wallet, interact with a blockchain, move funds, or provide a production deployment.

## Scope and Supported Transactions

- **Supported Transaction Format**: Currently restricted to the standard ERC-20 `transfer(address,uint256)` function selector (`0xa9059cbb`) with exactly 68 bytes of calldata (4-byte selector and two 32-byte ABI arguments). Other selectors, arbitrary contract calls, or malformed encodings return `UNKNOWN` or `DENY`.
- **Policy Allowlisting**: Enforces case-insensitive address allowlists for the ERC-20 token contract (`allowedTarget`) and the recipient (`allowedRecipient`).
- **Spending Limits Boundary**: Enforces an inclusive per-action maximum transfer amount (`maxAmount`). It does **not** provide cumulative, aggregate, or rolling time-window spending budgets across multiple transactions.
- **Authority and Invalidation**: V3 authorizations bind the authoritative policy revision and issuer key state in SQLite. Restoring or modifying a policy increments its revision and permanently invalidates prior authorizations.

## Safety and Operational Boundaries

- **Not an On-Chain Enforcer**: Web3User operates strictly off-chain. It does not monitor mempools, intercept RPC traffic, or communicate directly with blockchain consensus. Callers must fail closed on `DENY` or `UNKNOWN` and must verify authorization before requesting user wallet signatures.
- **Durable Local Storage Required**: SQLite WAL mode requires shared memory (`-shm`) and POSIX byte-range file locking. Network filesystems (NFS, SMB/CIFS, AWS EFS) are strictly unsupported and risk database corruption or `SQLITE_BUSY` errors. The database must reside on directly attached local block storage.
- **Pre-Release Audit Notice**: This release candidate is not audited for production deployment. Do not use it as the sole security control for high-value mainnet treasuries or unmonitored autonomous execution.
