# Web3User Permission Lab

Early-stage starter scaffold for the Web3User Protocol MVP.

## Status
Local-first prototype scaffold only. It is not deployed, audited, or an onchain enforcement mechanism.

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
npm install /path/to/web3user-permission-lab-0.1.0.tgz
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
    console.log("Authorization granted. Safe to broadcast transaction.");
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
- **`ALLOW`**: The transaction request satisfies authoritative policy rules, signing key validity intervals, and timestamp guardrails. A persistent single-use reservation was recorded atomically in SQLite.
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

### SQLite Durability, Checkpointing & Hardware Limitations

- **WAL & Synchronous FULL**: Every owned connection configures `PRAGMA journal_mode = WAL;` and `PRAGMA synchronous = FULL;` by default.
- **Checkpointing**: Call `engine.storage.checkpoint("TRUNCATE")` to safely checkpoint and truncate write-ahead log frames when concurrent readers are inactive.
- **Durability Model**:
  1. *Process Crash*: Protected by WAL atomic commits and transaction rollback.
  2. *OS Crash / Kernel Panic*: Protected by `synchronous = FULL` forcing `fsync` on every commit.
  3. *Power Loss Limitation*: Storage controllers with volatile write caches without battery/capacitor Power Loss Protection (PLP) may acknowledge writes before non-volatile NAND persistence. Physical power-loss durability requires enterprise host storage controllers with hardware PLP.

### Security Boundary & Private Key Hygiene

- **Off-Chain Scope**: Web3User is an off-chain decision engine. It does not sign Ethereum transactions, connect to RPC nodes, or broadcast to mempools.
- **Private Key Safety**: Never hardcode private keys in source code. Load private keys from secure environment variables, KMS, or HSMs. The SDK never logs, serializes, or echoes private key material in error messages.
- **Privileged Store Access**: `engine.getStore()` is provided strictly for administrative maintenance and diagnostics. Executing raw SQL directly on the underlying connection bypasses engine validations and ClockGuard safeguards.

## Persistent replay demonstration

The demo demonstrates persistent replay protection using bound authorization artifacts and an additive two-phase (`issued` → `consumed`) state model in SQLite. It uses a fixed local policy, transfer request, trusted demonstration time, and authorization ID (`bound-replay-demo-authorization-001`).

- **First run**: Issues the bound authorization artifact (inserting a record in state `issued` with canonical SHA-256 binding digest), then revalidates and atomically consumes the artifact (transitioning state to `consumed`). Prints `Decision: ALLOW`.
- **Subsequent runs**: Reopens the persistent database, reconstructs the bound artifact, and attempts to consume it again. Because the database record is already in state `consumed`, the consumption fails closed and prints `Decision: DENY` with reason `Bound transaction authorization is unknown, consumed, or mismatched.`. A denial is the expected successful replay-protection result.
- **Verification mode**: Run `npm run demo:persistent-replay -- --verify` to run an automated, end-to-end verification against an isolated temporary database, demonstrating both fresh issuance/consumption and replay rejection across database reopen.

The demo database is stored at `.demo-data/bound-authorization-replay.sqlite` in the repository. It is separate from application data and is ignored by Git. The legacy demo database (`.demo-data/authorization-replay.sqlite`) is preserved. The demo never removes or resets databases automatically.

This is a local authorization demonstration only. An `ALLOW` result does not mean a transaction was signed, submitted, or executed. The demo does not connect to a wallet, interact with a blockchain, move funds, or provide a production deployment.

## Scope
Deterministic demo checks for an allowlisted target and function selector, maximum amount, validity window, revocation, and unknown inputs.

## Safety
This is an off-chain simulator. It does not block or authorize blockchain transactions. Do not connect real funds or use it as a security control.
