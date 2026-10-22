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
npm run demo:persistent-replay
```

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
